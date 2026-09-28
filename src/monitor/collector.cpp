#include "arch/x64/resolver.hpp"
#include "monitor/monitor.hpp"
#include "unreal/origin.hpp"

// Association discovery and position sampling have deliberately different lifetimes.
// A copied Actor list is a bounded candidate queue, never an atomic/current world snapshot.
// No target writes, guessed PawnPrivate offset, cached coordinates, or cached resolver code.
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <set>
#include <sstream>
#include <unordered_set>

namespace monitor {
namespace {
using Index = std::unordered_map<u64, i32>;

void Require(u64 p, const char* stage) {
    if (!p) Fail(Code::NullObject, stage, "Resolved null object (not necessarily a read failure)");
    if (!UserAddress(p)) Fail(Code::InvalidAddress, stage, "Invalid resolved user address", p);
}
void PropagateControl(const Fault& e) {
    if (e.issue().code == Code::Cancelled || e.issue().code == Code::Deadline) throw;
}
bool SessionEqual(const Session& a, const Session& b) {
    // generation is only this monitor's attach counter. Preserve association and
    // validated raw-root state across a soft/full rebind when the actual process
    // identity and memory binding remain unchanged.
    return a.pid && a.pid == b.pid && a.process_sequence == b.process_sequence && a.cr3 == b.cr3
        && a.peb == b.peb && a.base == b.base
        && a.image_size == b.image_size && a.timestamp == b.timestamp;
}
bool InvalidatesCachedRoot(const Issue& issue) {
    // A missing page, timeout, or transient local/roster read is not evidence of a
    // new World. Keep the last validated raw root so the next frame can retry.
    if (issue.code == Code::ReadFailed || issue.code == Code::Deadline || issue.code == Code::Cancelled)
        return false;
    const auto& stage = issue.stage;
    const auto begins = [&](const char* prefix) { return stage.rfind(prefix, 0) == 0; };
    if ((issue.code == Code::NullObject || issue.code == Code::InvalidAddress)
        && (begins("WORLD_RESOLVE") || begins("GAMESTATE_RESOLVE")
            || begins("CURRENT_LEVEL_RESOLVE") || begins("CURRENT_LEVEL_READ/"))) return true;
    // Changed resolver code or metadata is independent evidence that the old raw
    // root can no longer be interpreted under the same context.
    return issue.code == Code::CodeChanged
        || (issue.code == Code::SnapshotChanged && begins("RESOLVER_METADATA_RECHECK"));
}
std::int64_t AgeMs(Clock::time_point now, Clock::time_point when) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(now - when).count();
}
std::pair<u64, Vec3> Position(Reader& m, FrameResolver& r, u64 pawn) {
    u64 root_raw = 0;
    const u64 slot = Add(pawn, Offset::RootComponent, "ROOT_COMPONENT_READ");
    const u64 root = r.Field(pawn, Offset::RootComponent, Cipher::RootComponent, "ROOT_COMPONENT_READ", &root_raw);
    Require(root, "ROOT_COMPONENT");
    const Vec3 p = m.Value<Vec3>(Add(root, Offset::ComponentLocation, "POSITION_READ"), "POSITION_READ");
    if (!ValidPosition(p)) Fail(Code::InvalidLayout, "POSITION_READ", "Nonfinite/out-of-range coordinates", root);
    if (m.Value<u64>(slot, "ROOT_COMPONENT_RECHECK") != root_raw)
        Fail(Code::SnapshotChanged, "ROOT_COMPONENT_RECHECK", "Root changed while sampling this player", slot);
    return {root, p};
}
std::string Name(Reader& m, u64 at) {
    const auto h = m.Value<ArrayHeader>(at, "NAME_HEADER");
    if (h.num == 0) return {};
    if (h.num < 0 || h.num > 128 || h.max < h.num || h.max > 256)
        Fail(Code::InvalidLayout, "NAME_HEADER", "Invalid UTF-16 header", at);
    std::vector<u16> v(static_cast<std::size_t>(h.num));
    m.Bytes(h.data, v.data(), v.size() * sizeof(u16), "NAME_READ");
    if (!(m.Value<ArrayHeader>(at, "NAME_RECHECK") == h))
        Fail(Code::SnapshotChanged, "NAME_RECHECK", "Name header changed while reading", at);
    std::string out;
    for (std::size_t i = 0; i < v.size() && v[i]; ++i) {
        u32 cp = v[i];
        if (cp >= 0xD800 && cp <= 0xDBFF) {
            if (i + 1 >= v.size() || v[i + 1] < 0xDC00 || v[i + 1] > 0xDFFF) return {};
            const u32 hi = cp;
            ++i;
            cp = 0x10000 + ((hi - 0xD800) << 10) + (v[i] - 0xDC00);
        } else if (cp >= 0xDC00 && cp <= 0xDFFF) return {};
        if (cp < 0x80) out.push_back(static_cast<char>(cp));
        else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 63)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 63)));
            out.push_back(static_cast<char>(0x80 | (cp & 63)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 63)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 63)));
            out.push_back(static_cast<char>(0x80 | (cp & 63)));
        }
    }
    return out;
}
void RawStatus(Reader& m, Player& p, const Config& c, bool read_name) {
    p.team = m.Probe<i32>(Add(p.state, Offset::TeamNumber, "TEAM_READ"), "TEAM_READ");
    // The supplied 0x710 has no confirmed PlayerState owner in this dump.
    // A byte read there would present unrelated data as a death state.
    p.status_raw = m.Probe<u8>(Add(p.state, Offset::PlayerStatusType, "STATUS_RAW"), "STATUS_RAW");
    if (p.pawn) p.dbno_raw = m.Probe<u8>(Add(p.pawn, Offset::DBNORaw, "DBNO_RAW"), "DBNO_RAW");
    // Raw flags remain diagnostic values; bit meanings do not decide alive/dead filtering.
    // Names are read fresh, not cached across identities.
    if (c.include_names && read_name) {
        try { p.name = Name(m, Add(p.state, Offset::PlayerName, "NAME_HEADER")); }
        catch (const Fault& e) { PropagateControl(e); }
        if (p.name.empty() && p.pawn) {
            try { p.name = Name(m, Add(p.pawn, Offset::CharacterName, "NAME_HEADER")); }
            catch (const Fault& e) { PropagateControl(e); }
        }
    }
}
u64 StateInRoster(FrameResolver& r, const Index& roster, u64 raw) {
    if (!raw) return 0;
    if (roster.find(raw) != roster.end()) return raw;
    const u64 decoded = r.Object(raw, Cipher::PlayerState);
    return roster.find(decoded) != roster.end() ? decoded : 0;
}
struct LocalAnchor {
    std::vector<std::pair<u64, u64>> slots;
    u64 local_array_at = 0;
    ArrayHeader local_array{};
    void Check(Reader& m) const {
        for (const auto& x : slots)
            if (m.Value<u64>(x.first, "OWN_CHAIN_RECHECK") != x.second)
                Fail(Code::NoReference, "OWN_CHAIN_RECHECK", "Local reference chain changed during capture", x.first);
        if (local_array_at && !(m.Value<ArrayHeader>(local_array_at, "OWN_CHAIN_RECHECK") == local_array))
            Fail(Code::NoReference, "OWN_CHAIN_RECHECK", "LocalPlayers header changed during capture", local_array_at);
    }
};
void AcquireLocal(Reader& m, FrameResolver& r, Snapshot& f, LocalAnchor& anchor) {
    f.game_instance = r.Field(f.world, Offset::GameInstance, Cipher::GameInstance, "GAMEINSTANCE_READ", &f.game_instance_raw);
    Require(f.game_instance, "GAMEINSTANCE_RESOLVE");
    anchor.slots.emplace_back(Add(f.world, Offset::GameInstance, "GAMEINSTANCE_READ"), f.game_instance_raw);
    anchor.local_array_at = Add(f.game_instance, Offset::LocalPlayer, "LOCALPLAYERS");
    const auto lp = ArrayValues(m, anchor.local_array_at, 16, "LOCALPLAYERS", &f.local_players_header);
    anchor.local_array = f.local_players_header;
    if (lp.empty()) Fail(Code::NoReference, "LOCALPLAYERS", "No local-player entry");
    anchor.slots.emplace_back(f.local_players_header.data, lp.front());
    f.local_player = r.Object(lp.front(), Cipher::LocalPlayer); Require(f.local_player, "LOCALPLAYER_RESOLVE");
    u64 controller_raw = 0;
    f.controller = r.Field(f.local_player, Offset::PlayerController, Cipher::ControlPointer, "CONTROLLER_READ", &controller_raw);
    Require(f.controller, "CONTROLLER_RESOLVE");
    anchor.slots.emplace_back(Add(f.local_player, Offset::PlayerController, "CONTROLLER_READ"), controller_raw);
    const u64 own_slot = Add(f.controller, Offset::AcknowledgedPawn, "ACKNOWLEDGED_PAWN_READ");
    const u64 own_raw = m.Value<u64>(own_slot, "ACKNOWLEDGED_PAWN_READ");
    anchor.slots.emplace_back(own_slot, own_raw);
    f.self_pawn = r.Object(own_raw, Cipher::ControlPointer);
    if (!f.self_pawn) Fail(Code::NoReference, "ACKNOWLEDGED_PAWN_NULL",
        "No own Pawn; respawn/spectating/transition is possible, not proven");
}
}

struct Collector::State {
    struct Entry {
        u64 pawn = 0;
        Clock::time_point discovered{};
        std::string source;
    };
    struct Scan {
        std::shared_ptr<const std::vector<u64>> values;
        std::size_t cursor = 0;
        Clock::time_point started{};
        u64 state = 0, header_address = 0;
        ArrayHeader header{};
        std::unordered_map<u64, Entry> found;
        std::unordered_set<u64> ambiguous;
        bool Active() const { return bool(values); }
    } scan;
    Session session;
    // A raw root is eligible only after a complete frame has committed. It is
    // intentionally separate from association and discovery cache lifetimes.
    u64 cached_world_state = 0;
    bool root_cache_valid = false;
    Clock::time_point root_verified_at{};
    Clock::time_point root_attempt_at{};
    u64 world = 0, game_state = 0, level = 0, cycle = 0;
    std::unordered_map<u64, Entry> entries;
    std::unordered_set<u64> roster;
    std::optional<float> last_world_time;
    Clock::time_point next_scan = Clock::time_point::min();
    Clock::time_point next_allowed = Clock::time_point::min();
    Clock::time_point next_words = Clock::time_point::min();
    Clock::time_point last_completed{};
    bool has_completed = false;
    std::string pending_reason = "INITIAL";
    // Kept only for labelled diagnostic history, never for position sampling.
    u64 last_state = 0, last_header_address = 0;
    ArrayHeader last_header{};
    Clock::time_point last_header_at{};
    bool has_header = false;

    void Request(const char* reason) {
        pending_reason = reason;
        next_scan = std::min(next_scan, std::max(Clock::now(), next_allowed));
    }
    void Discovery(Reader& m, FrameResolver& r, Snapshot& f, const Config& c, const Index& ps) {
        const auto now = Clock::now();
        if (scan.Active() && AgeMs(now, scan.started) >= c.discovery_cycle_timeout_ms) {
            f.discovery.issue = Issue{Code::Deadline, "DISCOVERY_CYCLE_EXPIRED",
                "Candidate queue aged out; discard uncommitted discoveries and reschedule"};
            scan = {}; next_scan = now + std::chrono::milliseconds(c.discovery_min_interval_ms);
            pending_reason = "QUEUE_EXPIRED";
        }
        if (!scan.Active() && now >= next_scan && now >= next_allowed) {
            f.discovery.started = true;
            f.discovery.reason = pending_reason;
            ++cycle;
            next_allowed = now + std::chrono::milliseconds(c.discovery_min_interval_ms);
            // A failed copy is retried later, never in a hot loop in the same capture.
            next_scan = next_allowed;
            try {
                const u64 at = Add(f.level, Offset::Actors, "DISCOVERY_STATE_READ");
                const u64 raw = m.Value<u64>(at, "DISCOVERY_STATE_READ");
                const u64 header_at = r.Actors(raw);
                Require(header_at, "DISCOVERY_HEADER_ADDRESS");
                ArrayHeader h;
                auto values = ArrayValues(m, header_at, c.max_actors, "DISCOVERY_ARRAY", &h);
                if (m.Value<u64>(at, "DISCOVERY_STATE_RECHECK") != raw)
                    Fail(Code::SnapshotChanged, "DISCOVERY_STATE_RECHECK", "Actors state changed while copying candidate queue", at);
                scan = {};
                scan.started = Clock::now(); scan.state = raw;
                scan.header_address = header_at; scan.header = h;
                scan.values = std::make_shared<const std::vector<u64>>(std::move(values));
                last_state = raw; last_header_address = header_at; last_header = h;
                last_header_at = scan.started; has_header = true;
                f.actors_header_sampled = true;
            } catch (const Fault& e) {
                PropagateControl(e);
                f.discovery.issue = e.issue();
                pending_reason = "RETRY_DISCOVERY_COPY";
            }
        }
        f.discovery.cycle = cycle;
        if (scan.Active()) {
            // Copying the queue is done once per pass. Each candidate is freshly resolved
            // when visited. The queue may be historical; every committed mapping is again
            // checked against the CURRENT roster and Pawn back-reference before display.
            f.discovery.bootstrap = !has_completed;
            // Cold start should not require four successful update frames before the
            // first useful mapping in a ~1000-Actor scene. Later passes use smaller slices.
            const int slice_ms = has_completed ? c.discovery_slice_ms : c.first_discovery_slice_ms;
            const auto age_ms = std::max<std::int64_t>(0, AgeMs(Clock::now(), scan.started));
            f.discovery.cycle_age_ms = age_ms;
            // Aim to finish in half the hard lifetime, leaving room for slow/failed
            // captures. A fixed quota starves queues larger than 4352 at 300 ms/5 s.
            // The wall-clock slice and capture deadline remain the hard work limits.
            const auto remaining_ms = std::max<std::int64_t>(0, c.discovery_cycle_timeout_ms / 2 - age_ms);
            const auto slices = static_cast<std::size_t>(std::max<std::int64_t>(1,
                remaining_ms / std::max(1, c.interval_ms)));
            const auto remaining = scan.values->size() - scan.cursor;
            const auto adaptive_limit = remaining / slices + (remaining % slices != 0);
            const std::size_t slice_limit = std::max(adaptive_limit,
                has_completed ? c.discovery_actors_per_slice : c.first_discovery_actors_per_slice);
            f.discovery.slice_limit = slice_limit;
            const auto until = Clock::now() + std::chrono::milliseconds(slice_ms);
            while (scan.cursor < scan.values->size()
                && f.discovery.scanned_this_frame < slice_limit
                && Clock::now() < until) {
                m.Check("DISCOVERY_SLICE");
                const u64 raw = (*scan.values)[scan.cursor++];
                ++f.discovery.scanned_this_frame;
                if (!raw) continue;
                try {
                    const u64 actor = r.Object(raw);
                    if (!actor) continue;
                    ++f.actor_objects;
                    const u64 back_raw = m.Value<u64>(Add(actor, Offset::PlayerState, "DISCOVERY_PLAYERSTATE_READ"),
                                                     "DISCOVERY_PLAYERSTATE_READ");
                    const u64 ps_address = StateInRoster(r, ps, back_raw);
                    if (!ps_address) continue;
                    const Entry e{actor, Clock::now(), "ACTOR_DISCOVERY"};
                    const auto found = scan.found.find(ps_address);
                    if (found != scan.found.end()) {
                        ++f.duplicate_matches;
                        if (found->second.pawn != actor) {
                            // A duplicate relationship alone cannot identify the active Pawn.
                            // Own acknowledged Pawn is the only independently established tie-break.
                            if (actor == f.self_pawn) { found->second = e; scan.ambiguous.erase(ps_address); }
                            else if (found->second.pawn != f.self_pawn) scan.ambiguous.insert(ps_address);
                        }
                    } else scan.found.emplace(ps_address, e);
                } catch (const Fault& e) {
                    PropagateControl(e);
                    ++f.actor_failures;
                    if (!f.first_actor_failure) f.first_actor_failure = e.issue();
                }
            }
            f.discovery.cursor = scan.cursor;
            f.discovery.total = scan.values->size();
            f.discovery.candidates_found = scan.found.size();
            f.discovery.ambiguous = scan.ambiguous.size();
            if (scan.cursor == scan.values->size()) {
                // A whole candidate pass completed, but its list is not advertised as a
                // current/atomic roster. Only associations (never coordinates) are merged.
                for (u64 state : scan.ambiguous) entries.erase(state);
                for (const auto& kv : scan.found) {
                    if (ps.find(kv.first) == ps.end() || scan.ambiguous.count(kv.first)) continue;
                    const auto old = entries.find(kv.first);
                    if (old == entries.end() || old->second.pawn != kv.second.pawn) ++f.cache.new_mappings;
                    entries[kv.first] = kv.second;
                }
                scan = {}; has_completed = true; last_completed = Clock::now();
                f.discovery.completed = true;
                next_scan = last_completed + std::chrono::milliseconds(c.discovery_interval_ms);
                pending_reason = "PERIODIC";
            }
        }
        f.discovery.running = scan.Active();
        if (has_completed) f.discovery.last_completed_age_ms = AgeMs(Clock::now(), last_completed);
        if (has_header) {
            f.actors_state = last_state; f.actors_header_address = last_header_address;
            f.actors_header = last_header;
            f.actors_header_age_ms = AgeMs(Clock::now(), last_header_at);
        }
    }
};

Collector::Collector() : state_(std::make_unique<State>()) {}
Collector::~Collector() = default;
void Collector::Reset() noexcept { state_.reset(); }

Snapshot Collector::Capture(IBytes& backend, const Session& session, const Config& c,
                           const std::atomic_bool& stop, u64 seq) {
    Snapshot f; f.session = session; f.sequence = seq; f.started = Clock::now();
    f.world_root_unverified = true;
    Reader m(backend, Budget{&stop, f.started + std::chrono::milliseconds(c.capture_budget_ms)}, c.read_attempts);
    FrameResolver r(m, session.base, &f.trace);
    try {
        if (!state_) state_ = std::make_unique<State>();
        f.cache.before = state_->entries.size();
        const bool binding_changed = !SessionEqual(state_->session, session);
        const bool cached_root_invalidated = c.experimental_world_cache && state_->root_cache_valid
            && binding_changed;
        if (binding_changed) {
            state_ = std::make_unique<State>(); state_->session = session;
            f.cache.reset = true;
            f.cache.reset_reason = "PROCESS_OR_MEMORY_BINDING_CHANGED";
            if (cached_root_invalidated) {
                f.world_cache_invalidated = true;
                f.trace.push_back("WORLD_CACHE_BINDING_CHANGED: cached raw root discarded before acquisition");
                Fail(Code::SessionChanged, "WORLD_CACHE_BINDING_CHANGED",
                    "Cached WorldState belonged to a different process or memory binding; retry with a fresh root");
            }
        } else {
            // Refresh only the bookkeeping generation. World/GameState/Level checks below
            // decide whether the cached association topology still belongs to this match.
            state_->session = session;
        }
        const u64 ws = Add(session.base, Offset::UWorld, "WORLD_STATE_READ");
        f.world_cache_used = c.experimental_world_cache && state_->root_cache_valid;
        Clock::time_point root_attempt_at = state_->root_attempt_at;
        Clock::time_point root_verified_at = state_->root_verified_at;
        bool refresh_first_read_matched = false;
        if (f.world_cache_used) {
            f.world_state = state_->cached_world_state;
            f.world_cache_age_ms = std::max<std::int64_t>(0, AgeMs(f.started, root_verified_at));
            if (AgeMs(f.started, root_attempt_at) >= std::max(1, c.world_refresh_interval_ms)) {
                f.world_refresh_attempted = true;
                root_attempt_at = f.started;
                // This timestamp is scheduling state, not a newly accepted root.
                // Commit it before the read so Deadline or a later failed frame
                // cannot repeatedly spend the next frame on the same absent page.
                state_->root_attempt_at = root_attempt_at;
                try {
                    const u64 observed = m.Value<u64>(ws, "WORLD_CACHE_REFRESH");
                    if (observed != f.world_state) {
                        f.world_refresh_failed = true;
                        f.world_cache_invalidated = true;
                        f.cache.reset = true;
                        f.cache.reset_reason = "WORLD_CACHE_CHANGED";
                        f.trace.push_back("WORLD_CACHE_CHANGED cached=" + Hex(f.world_state)
                            + " observed=" + Hex(observed));
                        Reset();
                        Fail(Code::SnapshotChanged, "WORLD_CACHE_CHANGED",
                            "Raw WorldState changed; discard this frame and acquire a fresh root next frame", ws);
                    }
                    refresh_first_read_matched = true;
                    f.trace.push_back("WORLD_CACHE_REFRESH_FIRST_READ_MATCHED raw=" + Hex(observed));
                } catch (const Fault& e) {
                    PropagateControl(e);
                    if (e.issue().code != Code::ReadFailed) throw;
                    f.world_refresh_failed = true;
                    f.trace.push_back("WORLD_CACHE_REFRESH_UNAVAILABLE " + Describe(e.issue()));
                }
            }
        } else {
            f.world_state = m.Value<u64>(ws, "WORLD_STATE_READ");
            f.world_root_unverified = false;
        }
        f.world = r.World(f.world_state); Require(f.world, "WORLD_RESOLVE");
        (void)m.Value<u64>(f.world, "WORLD_PROBE");
        const u64 gs = Add(f.world, Offset::GameState, "GAMESTATE_STATE_READ");
        f.game_state_raw = m.Value<u64>(gs, "GAMESTATE_STATE_READ");
        f.game_state = r.GameState(f.game_state_raw); Require(f.game_state, "GAMESTATE_RESOLVE");
        (void)m.Value<u64>(f.game_state, "GAMESTATE_PROBE");
        f.level = r.Field(f.world, Offset::CurrentLevel, Cipher::CurrentLevel, "CURRENT_LEVEL_READ", &f.level_raw);
        Require(f.level, "CURRENT_LEVEL_RESOLVE");
        const auto origin_before=unreal::ReadOrigin(m,f.world,f.origin_issue,"PLAYER_ORIGIN_READ");
        f.time_seconds = m.Probe<float>(Add(f.world, Offset::TimeSeconds, "WORLD_TIME"), "WORLD_TIME");
        f.alive_teams_raw = m.Probe<i32>(Add(f.game_state, Offset::NumAliveTeams, "ALIVE_TEAMS_RAW"), "ALIVE_TEAMS_RAW");
        const bool time_restarted = f.time_seconds && state_->last_world_time
            && std::isfinite(*f.time_seconds) && std::isfinite(*state_->last_world_time)
            && *f.time_seconds < *state_->last_world_time - 2.0f;
        if (state_->world != f.world || state_->game_state != f.game_state || state_->level != f.level || time_restarted) {
            if (f.world_cache_used) {
                f.world_cache_invalidated = true;
                f.cache.reset = true;
                f.cache.reset_reason = time_restarted ? "WORLD_TIME_ROLLBACK" : "WORLD_GAMESTATE_LEVEL_CHANGED";
                f.trace.push_back(std::string("WORLD_CACHE_CONTEXT_CHANGED reason=")
                    + (time_restarted ? "WORLD_TIME_ROLLBACK" : "WORLD_GAMESTATE_LEVEL_CHANGED"));
                Reset();
                Fail(Code::SnapshotChanged, "WORLD_CACHE_CONTEXT_CHANGED",
                    "Cached root's World/GameState/Level context changed; retry with a fresh root");
            }
            state_ = std::make_unique<State>(); state_->session = session;
            state_->world = f.world; state_->game_state = f.game_state; state_->level = f.level;
            f.cache.reset = true;
            f.cache.reset_reason += f.cache.reset_reason.empty() ? "" : ";";
            f.cache.reset_reason += time_restarted ? "WORLD_TIME_ROLLBACK" : "WORLD_GAMESTATE_LEVEL_CHANGED";
        }
        // Transactional: positive cache/discovery updates are committed only after the
        // current frame's root, roster and resolver checks. A failure does not publish them.
        State work = *state_; // Candidate vector uses shared ownership, not a megabyte copy per tick.
        const u64 roster_at = Add(f.game_state, Offset::PlayerArray, "PLAYER_ARRAY");
        const auto ps_values = ArrayValues(m, roster_at, c.max_players, "PLAYER_ARRAY", &f.players_header);
        Index ps_index; ps_index.reserve(ps_values.size());
        std::unordered_set<u64> roster;
        bool roster_added = false;
        for (std::size_t i = 0; i < ps_values.size(); ++i) {
            m.Check("PLAYER_ARRAY_ELEMENTS");
            if (!UserAddress(ps_values[i])) { ++f.player_slots_unusable; continue; }
            if (!ps_index.emplace(ps_values[i], static_cast<i32>(i)).second) { ++f.player_slots_unusable; continue; }
            roster.insert(ps_values[i]);
            if (!work.roster.count(ps_values[i])) roster_added = true;
        }
        work.roster = std::move(roster);
        std::unordered_map<u64, std::string> unavailable;
        for (auto it = work.entries.begin(); it != work.entries.end();) {
            if (!ps_index.count(it->first)) { ++f.cache.roster_removed; it = work.entries.erase(it); }
            else if (AgeMs(Clock::now(), it->second.discovered) >= c.association_ttl_ms) {
                unavailable[it->first] = "ASSOCIATION_EXPIRED";
                ++f.cache.expired; it = work.entries.erase(it);
            } else ++it;
        }
        if (roster_added) work.Request("ROSTER_ADDED");
        if (f.cache.expired) work.Request("ASSOCIATION_EXPIRED");

        LocalAnchor local;
        bool local_ready = false;
        try { AcquireLocal(m, r, f, local); local_ready = true; }
        catch (const Fault& e) {
            PropagateControl(e);
            if (f.world_cache_used)
                Fail(e.issue().code, "WORLD_CACHE_LOCAL_CHAIN",
                    "Local chain unavailable while using cached root: " + Describe(e.issue()), e.issue().address);
            f.reference_issue = e.issue();
        }

        work.Discovery(m, r, f, c, ps_index);
        // An independently acquired local Pawn may seed its OWN mapping without
        // enumerating all Actors. It does not stand in for any spectated teammate.
        if (local_ready) {
            try {
                const u64 raw = m.Value<u64>(Add(f.self_pawn, Offset::PlayerState, "SELF_PLAYERSTATE_READ"), "SELF_PLAYERSTATE_READ");
                const u64 ps = StateInRoster(r, ps_index, raw);
                if (ps) work.entries[ps] = State::Entry{f.self_pawn, Clock::now(), "LOCAL_CONTROL"};
            } catch (const Fault& e) { PropagateControl(e); }
            try { f.reference = Position(m, r, f.self_pawn).second; }
            catch (const Fault& e) { PropagateControl(e); f.reference_issue = e.issue(); }
        }
        // Update in stable PlayerArray order. No position/name/status is loaded from cache.
        for (std::size_t i = 0; i < ps_values.size(); ++i) {
            m.Check("CACHED_PLAYER_UPDATE");
            const auto ix = ps_index.find(ps_values[i]);
            if (ix == ps_index.end() || ix->second != static_cast<i32>(i)) continue;
            Player p; p.index = ix->second; p.state = ix->first;
            auto entry = work.entries.find(p.state);
            if (entry == work.entries.end()) {
                const auto why = unavailable.find(p.state);
                p.availability = why == unavailable.end() ? "NO_CONFIRMED_MAPPING" : why->second;
                RawStatus(m, p, c, false);
                f.unmatched.push_back(std::move(p));
                continue;
            }
            const u64 pawn = entry->second.pawn;
            u64 back_before = 0;
            bool valid_link = false;
            try {
                Require(pawn, "CACHED_PAWN");
                const u64 first = m.Value<u64>(pawn, "CACHED_PAWN_PROBE");
                if (!UserAddress(first)) Fail(Code::InvalidAddress, "CACHED_PAWN_PROBE", "Cached address no longer passes object-shape heuristic", pawn);
                const u64 back_at = Add(pawn, Offset::PlayerState, "CACHED_PLAYERSTATE_READ");
                back_before = m.Value<u64>(back_at, "CACHED_PLAYERSTATE_READ");
                if (StateInRoster(r, ps_index, back_before) != p.state)
                    Fail(Code::SnapshotChanged, "CACHED_PLAYERSTATE_READ", "Pawn now refers to a different PlayerState", back_at);
                valid_link = true;
                p.pawn = pawn; p.mapping_source = entry->second.source;
                p.self = local_ready && pawn == f.self_pawn;
                try {
                    const auto pos = Position(m, r, pawn);
                    p.root = pos.first;
                    // SELF is compared to the exact same reference sample, never to a
                    // second sample of itself taken later during the frame.
                    p.position = p.self && f.reference ? *f.reference : pos.second;
                    p.availability = "POSITION_SAMPLED";
                } catch (const Fault& e) {
                    PropagateControl(e); p.acquisition_issue = e.issue(); p.availability = "POSITION_UNAVAILABLE";
                    if (!f.first_actor_failure) f.first_actor_failure = e.issue();
                }
                RawStatus(m, p, c, true);
                if (m.Value<u64>(back_at, "CACHED_PLAYERSTATE_RECHECK") != back_before)
                    Fail(Code::SnapshotChanged, "CACHED_PLAYERSTATE_RECHECK", "Pawn association changed during player sampling", back_at);
                ++f.cache.validated;
                if (f.reference && p.position) {
                    p.distance2d = p.self ? 0.0 : Distance2D(*f.reference, *p.position) * c.units_to_meters;
                    p.distance3d = p.self ? 0.0 : Distance3D(*f.reference, *p.position) * c.units_to_meters;
                }
                f.players.push_back(std::move(p));
            } catch (const Fault& e) {
                PropagateControl(e);
                ++f.cache.invalidated; work.entries.erase(p.state); work.Request("CACHED_MAPPING_INVALIDATED");
                p.pawn = p.root = 0; p.self = false; p.position.reset(); p.distance2d.reset(); p.distance3d.reset();
                p.availability = valid_link ? "ASSOCIATION_CHANGED_DURING_SAMPLE" : "CACHED_MAPPING_UNAVAILABLE";
                p.acquisition_issue = e.issue(); p.name.clear();
                if (!f.first_actor_failure) f.first_actor_failure = e.issue();
                f.unmatched.push_back(std::move(p));
            }
        }
        f.matched = f.players.size();
        for (const auto& p : f.players) if (p.position) ++f.positioned;
        if (local_ready) {
            try { local.Check(m); }
            catch (const Fault& e) {
                PropagateControl(e);
                if (f.world_cache_used)
                    Fail(e.issue().code, "WORLD_CACHE_LOCAL_RECHECK",
                        "Local chain changed while using cached root: " + Describe(e.issue()), e.issue().address);
                f.reference.reset(); f.reference_issue = e.issue();
                for (auto& p : f.players) { p.self = false; p.distance2d.reset(); p.distance3d.reset(); }
            }
        }
        if (Clock::now() >= work.next_words) {
            f.object_words_sampled = true;
            for (std::size_t i = 0; i < 12; ++i) {
                f.world_words[i] = m.Probe<u64>(Add(f.world, i * 8, "WORLD_WORDS"), "WORLD_WORDS");
                f.game_state_words[i] = m.Probe<u64>(Add(f.game_state, i * 8, "GAMESTATE_WORDS"), "GAMESTATE_WORDS");
            }
            work.next_words = Clock::now() + std::chrono::milliseconds(c.object_diagnostics_interval_ms);
        }
        const bool world_changed = !f.world_cache_used
            && m.Value<u64>(ws, "WORLD_RECHECK") != f.world_state;
        const u64 game_state_recheck = m.Value<u64>(gs, "GAMESTATE_RECHECK");
        const u64 level_recheck = m.Value<u64>(Add(f.world, Offset::CurrentLevel, "LEVEL_RECHECK"), "LEVEL_RECHECK");
        if (world_changed || game_state_recheck != f.game_state_raw || level_recheck != f.level_raw) {
            if (f.world_cache_used) {
                f.world_cache_invalidated = true;
                f.cache.reset = true;
                f.cache.reset_reason = "WORLD_CACHE_CONTEXT_RECHECK_CHANGED";
                f.trace.push_back("WORLD_CACHE_CONTEXT_RECHECK_CHANGED gs=" + Hex(game_state_recheck)
                    + " level=" + Hex(level_recheck));
            }
            Reset();
            Fail(Code::SnapshotChanged, "CONTEXT_RECHECK", "World/GameState/level changed; discard frame and all associations");
        }
        // Player roster is small: check both header AND content, including in-place
        // replacements with unchanged Data/Num/Max. A header match alone was insufficient.
        ArrayHeader roster_after;
        const auto values_after = ArrayValues(m, roster_at, c.max_players, "PLAYER_ARRAY_RECHECK", &roster_after);
        if (!(roster_after == f.players_header) || values_after != ps_values)
            Fail(Code::SnapshotChanged, "PLAYER_ARRAY_RECHECK", "Player roster changed during capture; frame not published", roster_at);
        // Do NOT re-require the entire Actor container to be unchanged after a position
        // update. Discovery owns that container; cached-player sampling owns its links.
        f.origin=unreal::CheckOrigin(m,f.world,origin_before,f.origin_issue,"PLAYER_ORIGIN_RECHECK");
        r.Verify();
        if (refresh_first_read_matched) {
            try {
                const u64 observed = m.Value<u64>(ws, "WORLD_CACHE_RECHECK");
                if (observed != f.world_state) {
                    f.world_refresh_failed = true;
                    f.world_cache_invalidated = true;
                    f.cache.reset = true;
                    f.cache.reset_reason = "WORLD_CACHE_RECHECK_CHANGED";
                    f.trace.push_back("WORLD_CACHE_RECHECK_CHANGED cached=" + Hex(f.world_state)
                        + " observed=" + Hex(observed));
                    Reset();
                    Fail(Code::SnapshotChanged, "WORLD_CACHE_RECHECK_CHANGED",
                        "Raw WorldState changed during refresh frame; discard and reacquire next frame", ws);
                }
                f.world_refresh_succeeded = true;
                f.world_root_unverified = false;
                root_verified_at = Clock::now();
                f.world_cache_age_ms = 0;
                f.trace.push_back("WORLD_CACHE_REFRESH_VERIFIED raw=" + Hex(observed));
            } catch (const Fault& e) {
                PropagateControl(e);
                if (e.issue().code != Code::ReadFailed) throw;
                f.world_refresh_failed = true;
                f.trace.push_back("WORLD_CACHE_RECHECK_UNAVAILABLE " + Describe(e.issue()));
            }
        }
        if (f.time_seconds && std::isfinite(*f.time_seconds)) work.last_world_time = *f.time_seconds;
        if (c.experimental_world_cache) {
            work.root_cache_valid = true;
            work.cached_world_state = f.world_state;
            work.root_attempt_at = f.world_cache_used ? root_attempt_at : Clock::now();
            work.root_verified_at = f.world_cache_used ? root_verified_at : work.root_attempt_at;
            if (!f.world_cache_used) f.world_cache_age_ms = 0;
        } else {
            work.root_cache_valid = false;
        }
        f.cache.after = work.entries.size();
        f.trace.push_back(std::string("Collection path=")
            + (f.discovery.started || f.discovery.scanned_this_frame ? "DISCOVERY_SLICE_AND_UPDATE" : "CACHED_UPDATE")
            + " validated=" + std::to_string(f.cache.validated)
            + " cache=" + std::to_string(f.cache.after)
            + " scan=" + std::to_string(f.discovery.cursor) + "/" + std::to_string(f.discovery.total));
        *state_ = std::move(work);
        f.complete = true;
    } catch (const Fault& e) {
        f.fatal = e.issue();
        if (f.world_cache_used && InvalidatesCachedRoot(e.issue())) {
            f.world_cache_invalidated = true;
            f.cache.reset = true;
            f.cache.reset_reason += f.cache.reset_reason.empty() ? "" : ";";
            f.cache.reset_reason += "WORLD_CACHE_ROOT_EVIDENCE_INVALID";
            f.trace.push_back("WORLD_CACHE_INVALIDATED fatal=" + Describe(e.issue()));
            Reset();
        } else if (f.world_cache_used && !f.world_cache_invalidated) {
            f.trace.push_back("WORLD_CACHE_RETAINED_AFTER_FRAME_FAILURE fatal=" + Describe(e.issue()));
        }
    }
    catch (const std::exception& e) { f.fatal = Issue{Code::InternalError, "CAPTURE", e.what()}; }
    f.finished = Clock::now(); f.backend_calls = m.Calls(); f.failed_attempts = m.FailedAttempts();
    f.read_stats = m.Stats();
    return f;
}
Snapshot Capture(IBytes& b, const Session& s, const Config& c, const std::atomic_bool& stop, u64 seq) {
    Collector once;
    // Legacy callers requested a one-shot full enumeration. Do not silently turn
    // that into the first slice of a queue whose owner is immediately destroyed.
    // The worker uses persistent Collector::Capture instead and gets the cache path.
    Config one_shot = c;
    one_shot.discovery_actors_per_slice = static_cast<std::size_t>(std::max(1, c.max_actors));
    one_shot.discovery_slice_ms = std::max(1, c.capture_budget_ms);
    one_shot.first_discovery_slice_ms = one_shot.discovery_slice_ms;
    one_shot.first_discovery_actors_per_slice = one_shot.discovery_actors_per_slice;
    return once.Capture(b, s, one_shot, stop, seq);
}

std::string WorldCacheFrameReport(const Snapshot& f) {
    std::size_t root_attempts = 0, root_failures = 0;
    for (const char* stage : {"WORLD_STATE_READ", "WORLD_RECHECK",
                              "WORLD_CACHE_REFRESH", "WORLD_CACHE_RECHECK"}) {
        const auto found = f.read_stats.find(stage);
        if (found == f.read_stats.end()) continue;
        root_attempts += found->second.attempts;
        root_failures += found->second.failed_attempts;
    }
    std::ostringstream o;
    o << "WORLD_CACHE_FRAME frame=" << f.sequence << " pid=" << f.session.pid
      << " generation=" << f.session.generation << " process_sequence=" << Hex(f.session.process_sequence)
      << " start_tick_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(f.started.time_since_epoch()).count()
      << " capture_ms=" << AgeMs(f.finished, f.started)
      << " complete=" << f.complete << " cached=" << f.world_cache_used
      << " unverified=" << f.world_root_unverified << " root_age_ms=" << f.world_cache_age_ms
      << " root_read_attempts=" << root_attempts << " root_failed_attempts=" << root_failures
      << " refresh_attempted=" << f.world_refresh_attempted
      << " refresh_verified=" << f.world_refresh_succeeded
      << " refresh_failed=" << f.world_refresh_failed << " invalidated=" << f.world_cache_invalidated
      << " used_world_state=" << Hex(f.world_state) << " world=" << Hex(f.world)
      << " game_state=" << Hex(f.game_state) << " level=" << Hex(f.level)
      << " roster=" << f.players_header.num << " matched=" << f.matched
      // A failed frame may contain partial samples; never count those as accepted.
      << " accepted_positions=" << (f.complete ? f.positioned : 0)
      << " discovery_cycle=" << f.discovery.cycle
      << " discovery_running=" << f.discovery.running << " discovery_completed=" << f.discovery.completed
      << " discovery_cursor=" << f.discovery.cursor << " discovery_total=" << f.discovery.total
      << " discovery_quota=" << f.discovery.slice_limit << " discovery_age_ms=" << f.discovery.cycle_age_ms
      << " discovery_last_completed_age_ms=" << f.discovery.last_completed_age_ms
      << " discovery_candidates=" << f.discovery.candidates_found
      << " discovery_issue=" << (f.discovery.issue ? f.discovery.issue.stage : "NONE")
      << " world_time=";
    if (f.time_seconds && std::isfinite(*f.time_seconds)) o << std::setprecision(9) << *f.time_seconds;
    else o << "unavailable";
    o << " self=" << Hex(f.self_pawn) << " reference=";
    if (f.complete && f.reference)
        o << std::setprecision(9) << f.reference->x << ',' << f.reference->y << ',' << f.reference->z;
    else o << "unavailable";
    o << " fatal=" << CodeName(f.fatal.code)
      << " fatal_stage=" << (f.fatal.stage.empty() ? "NONE" : f.fatal.stage);
    return o.str();
}

std::string SnapshotReport(const Snapshot& f) {
    std::ostringstream o;
    o << "\n=== Snapshot #" << f.sequence << " | generation=" << f.session.generation << " ===\n";
    o << "PID=" << f.session.pid << " process_sequence=" << Hex(f.session.process_sequence) << " CR3=" << Hex(f.session.cr3)
      << " PEB=" << Hex(f.session.peb) << " Base=" << Hex(f.session.base) << "\n";
    o << "Result=" << (f.complete ? "CAPTURED" : "FAILED") << " elapsed_ms="
      << AgeMs(f.finished, f.started) << " read_calls=" << f.backend_calls << " failed_attempts=" << f.failed_attempts << "\n";
    o << "World root source=" << (f.world_cache_used ? "CACHE" : "FRESH")
      << " unverified=" << f.world_root_unverified
      << " cache_age_ms=" << f.world_cache_age_ms
      << " refresh_attempted=" << f.world_refresh_attempted
      << " refresh_succeeded=" << f.world_refresh_succeeded
      << " refresh_failed=" << f.world_refresh_failed
      << " cache_invalidated=" << f.world_cache_invalidated << "\n";
    o << "Cache before=" << f.cache.before << " after=" << f.cache.after << " validated_now=" << f.cache.validated
      << " invalidated=" << f.cache.invalidated << " expired=" << f.cache.expired << " roster_removed=" << f.cache.roster_removed
      << " new_mappings=" << f.cache.new_mappings << " reset=" << f.cache.reset << " reason=" << f.cache.reset_reason << "\n";
    o << "Discovery cycle=" << f.discovery.cycle << " started=" << f.discovery.started << " running=" << f.discovery.running
      << " completed_pass=" << f.discovery.completed << " bootstrap=" << f.discovery.bootstrap << " cursor=" << f.discovery.cursor << "/" << f.discovery.total
      << " scanned_this_frame=" << f.discovery.scanned_this_frame << " candidates_found=" << f.discovery.candidates_found
      << " slice_limit=" << f.discovery.slice_limit << " cycle_age_ms=" << f.discovery.cycle_age_ms
      << " ambiguous=" << f.discovery.ambiguous << " last_completed_age_ms=" << f.discovery.last_completed_age_ms
      << " reason=" << f.discovery.reason << "\n";
    if (f.discovery.issue) o << "DISCOVERY_ONLY " << Describe(f.discovery.issue) << "\n";
    o << "Read stages (attempts include retries; not a count of independent failed frames):\n";
    for (const auto& kv : f.read_stats) {
        const auto& x = kv.second;
        o << "  " << kv.first << " attempts=" << x.attempts << " failed=" << x.failed_attempts << " exhausted=" << x.exhausted_requests;
        if (x.failed_attempts) o << " first_failed_address=" << Hex(x.first_failed_address) << " requested_bytes=" << x.first_requested_bytes;
        o << "\n";
    }
    for (const auto& t : f.trace) o << "  " << t << "\n";
    o << "WorldState=" << Hex(f.world_state) << " World=" << Hex(f.world)
      << " GameStateRaw=" << Hex(f.game_state_raw) << " GameState=" << Hex(f.game_state) << "\n";
    o << "LevelRaw=" << Hex(f.level_raw) << " Level=" << Hex(f.level) << "\n";
    o << "Actors candidate header (NOT live roster): sampled_this_frame=" << f.actors_header_sampled
      << " age_ms=" << f.actors_header_age_ms << " State=" << Hex(f.actors_state)
      << " Header=" << Hex(f.actors_header_address) << " " << ArrayHeaderText(f.actors_header) << "\n";
    o << "GameInstanceRaw=" << Hex(f.game_instance_raw) << " GI=" << Hex(f.game_instance)
      << " LocalPlayer=" << Hex(f.local_player) << " Controller=" << Hex(f.controller) << " OwnPawn=" << Hex(f.self_pawn) << "\n";
    o << MapFrameReport(f) << '\n';
    if (!f.complete) o << "Incomplete capture: diagnostic values are not a publishable current sample.\n";
    auto words = [&](const char* label, const std::array<std::optional<u64>,12>& values) {
        o << label << " (QWORD diagnostic):\n";
        if (!f.object_words_sampled) { o << "  NOT_SAMPLED: periodic diagnostics not due, or stage not reached.\n"; return; }
        for (std::size_t i = 0; i < values.size(); ++i)
            o << "  +" << Hex(i * 8) << " " << (values[i] ? Hex(*values[i]) : "UNAVAILABLE") << "\n";
    };
    words("World", f.world_words); words("GameState", f.game_state_words);
    if (f.time_seconds) o << "WorldTime(raw float)=" << *f.time_seconds << "\n";
    if (f.alive_teams_raw) o << "NumAliveTeams(raw/unverified)=" << *f.alive_teams_raw << "\n";
    o << "PlayerArray=" << f.players_header.num << " unusable_or_duplicate_slots=" << f.player_slots_unusable
      << " ActorCandidatesResolvedThisSlice=" << f.actor_objects << " matched=" << f.matched
      << " position_valid=" << f.positioned << " unmatched=" << f.unmatched.size()
      << " skipped_discovery_errors=" << f.actor_failures << " duplicates=" << f.duplicate_matches << "\n";
    if (f.fatal) o << "ERROR " << Describe(f.fatal) << "\n";
    if (f.reference_issue) o << "REFERENCE " << Describe(f.reference_issue) << "\n";
    if (f.first_actor_failure) o << "First candidate/player issue: " << Describe(*f.first_actor_failure) << "\n";
    auto item = [&](const Player& p, bool unmatched) {
        o << (unmatched ? "[UNMATCHED] " : (p.self ? "[SELF] " : "[PLAYER] ")) << "#" << p.index
          << " PS=" << Hex(p.state) << " Pawn=" << Hex(p.pawn) << " Root=" << Hex(p.root)
          << " Availability=" << p.availability << " MappingSource=" << p.mapping_source
          << " Team=" << (p.team ? std::to_string(*p.team) : "UNKNOWN")
          << " KilledRaw=" << (p.killed_raw ? Hex(*p.killed_raw) : "READ_FAILED")
          << " StatusRawByte=" << (p.status_raw ? Hex(*p.status_raw) : "READ_FAILED")
          << " DBNORawByte(owner/unverified)=" << (p.dbno_raw ? Hex(*p.dbno_raw) : "UNAVAILABLE");
        if (!p.name.empty()) o << " Name=" << p.name;
        if (p.position) o << std::fixed << std::setprecision(3) << " XYZ=(" << p.position->x << "," << p.position->y << "," << p.position->z << ")";
        if (p.distance2d && p.distance3d) o << " D2=" << *p.distance2d << "m D3=" << *p.distance3d << "m";
        else o << " Distance=N/A";
        if (p.acquisition_issue) o << " Issue=" << Describe(p.acquisition_issue);
        o << "\n";
    };
    for (const auto& p : f.players) item(p, false);
    for (const auto& p : f.unmatched) item(p, true);
    o << "Note: cache stores associations ONLY. Coordinates/status/names are sampled anew.\n"
         "A completed discovery pass is not proof of all-server-player coverage or object lifetime.\n"
         "Raw state bytes are NOT verified alive/dead facts; client network freshness is unknown.\n";
    return o.str();
}
}
