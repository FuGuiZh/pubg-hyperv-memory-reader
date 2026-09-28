#pragma once
#include "platform/windows/kernel_queries.hpp"
// Shared monitor contracts. Platform-specific memory transport stays in backend.cpp.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#if defined(_WIN32)
#include <winsock2.h>
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#endif
#include <utility>
#include <memory>
#include <mutex>
#include <stdexcept>

// ============================================================================
// CORE declarations
// ============================================================================
#include <atomic>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <map>
#include <vector>

namespace monitor {
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using Clock = std::chrono::steady_clock;

enum class Code {
    None, Cancelled, Deadline, ReadFailed, InvalidAddress, InvalidLayout,
    NullObject, NoProcess, MultipleProcesses, ProcessExited, IdentityUnavailable,
    SessionChanged, ImageMismatch, BackendUnavailable, UnsupportedInstruction,
    UnsupportedPrefix, UnknownRegister, CodeChanged, SnapshotChanged,
    InstructionLimit, NoReference, InternalError
};
const char* CodeName(Code code) noexcept;
struct Issue {
    Code code = Code::None;
    std::string stage;
    std::string detail;
    u64 address = 0;
    std::size_t bytes = 0;
    unsigned attempts = 0;
    std::optional<u32> native_error; // Only when the backend/API actually returns one.
    Issue() = default;
    Issue(Code c, std::string s, std::string d, u64 a=0, std::size_t n=0,
          unsigned tries=0, std::optional<u32> native=std::nullopt)
        : code(c), stage(std::move(s)), detail(std::move(d)), address(a), bytes(n),
          attempts(tries), native_error(native) {}
    explicit operator bool() const noexcept { return code != Code::None; }
};
std::string Describe(const Issue& issue);
std::string Hex(u64 value);
class Fault final : public std::exception {
public:
    explicit Fault(Issue issue) : issue_(std::move(issue)) {}
    const char* what() const noexcept override { return issue_.detail.c_str(); }
    const Issue& issue() const noexcept { return issue_; }
private:
    Issue issue_;
};
[[noreturn]] inline void Fail(Code code, const char* stage, std::string message,
                              u64 address = 0, std::size_t bytes = 0) {
    throw Fault(Issue{code, stage, std::move(message), address, bytes, 0, std::nullopt});
}
inline bool TryAdd(u64 a, u64 b, u64& out) noexcept {
    if (a > (std::numeric_limits<u64>::max)() - b) return false;
    out = a + b;
    return true;
}
inline u64 Add(u64 a, u64 b, const char* stage) {
    u64 out = 0;
    if (!TryAdd(a, b, out)) Fail(Code::InvalidAddress, stage, "Address addition overflow", a);
    return out;
}
inline bool UserAddress(u64 address) noexcept {
    // This project's original 48-bit Windows-user-VA heuristic. Not a mapping test.
    return address >= 0x10000ULL && address < 0x0000800000000000ULL;
}
inline bool UserRange(u64 address, std::size_t bytes) noexcept {
    if (bytes == 0) return true;
    u64 last = 0;
    return UserAddress(address) && TryAdd(address, static_cast<u64>(bytes - 1), last)
        && UserAddress(last);
}
struct Budget {
    const std::atomic_bool* stop = nullptr;
    Clock::time_point deadline = Clock::time_point::max();
    void Check(const char* stage) const {
        if (stop && stop->load(std::memory_order_relaxed))
            Fail(Code::Cancelled, stage, "Stop requested");
        if (Clock::now() >= deadline)
            Fail(Code::Deadline, stage, "Acquisition time budget exceeded");
    }
};
struct Transfer {
    bool ok = false;
    std::size_t bytes = 0;
    std::optional<u32> native_error;
};
class IBytes {
public:
    virtual ~IBytes() = default;
    virtual void ReadContext(const char*, unsigned) {}
    virtual Transfer Read(u64 address, void* output, std::size_t bytes) = 0;
};
// Per-stage counts describe backend attempts, not independent failed frames.
struct ReadStageStats {
    std::size_t attempts=0, failed_attempts=0, exhausted_requests=0;
    u64 first_failed_address=0;
    std::size_t first_requested_bytes=0;
};
class Reader {
public:
    Reader(IBytes& backend, Budget budget, unsigned attempts = 2)
        : backend_(backend), budget_(budget), attempts_(attempts ? attempts : 1) {}
    void Bytes(u64 address, void* output, std::size_t bytes, const char* stage);
    template<class T> T Value(u64 address, const char* stage) {
        static_assert(std::is_trivially_copyable<T>::value, "Raw read requires a POD-like type");
        T value{};
        Bytes(address, &value, sizeof(value), stage);
        return value;
    }
    template<class T> std::optional<T> Probe(u64 address, const char* stage) {
        try { return Value<T>(address, stage); }
        catch (const Fault& e) {
            if (e.issue().code == Code::Cancelled || e.issue().code == Code::Deadline) throw;
            return std::nullopt;
        }
    }
    void Check(const char* stage) const { budget_.Check(stage); }
    std::size_t Calls() const noexcept { return calls_; }
    std::size_t FailedAttempts() const noexcept { return failed_; }
    const std::map<std::string,ReadStageStats>& Stats() const noexcept { return stats_; }
private:
    IBytes& backend_;
    Budget budget_;
    unsigned attempts_;
    std::size_t calls_ = 0, failed_ = 0;
    std::map<std::string,ReadStageStats> stats_;
};

struct ArrayHeader { u64 data = 0; i32 num = 0; i32 max = 0; };
static_assert(sizeof(ArrayHeader) == 16 && offsetof(ArrayHeader, num) == 8
              && offsetof(ArrayHeader, max) == 12, "Unexpected array layout");
inline bool operator==(const ArrayHeader& a, const ArrayHeader& b) noexcept {
    return a.data == b.data && a.num == b.num && a.max == b.max;
}
std::string ArrayHeaderText(const ArrayHeader& header);
void ValidateArray(const ArrayHeader& a, i32 limit, const char* stage);
std::vector<u64> ArrayValues(Reader& memory, u64 header_address, i32 limit,
                            const char* stage, ArrayHeader* observed = nullptr);
struct Vec3 { float x = 0, y = 0, z = 0; };
struct WorldOrigin {
    i32 x=0, y=0, z=0;
    bool operator==(const WorldOrigin&) const = default;
};
static_assert(sizeof(WorldOrigin)==12);
struct ObjectName {
    std::optional<u32> raw_index, raw_number, index, number;
    std::string base, full;
    bool wide=false, verified=false;
};
enum class NameCaptureStatus : unsigned { NotAttempted=1, Succeeded=2, Failed=3 };
static_assert(sizeof(Vec3) == 12, "This observed layout uses three floats");
bool ValidPosition(const Vec3& v) noexcept;
double Distance2D(const Vec3& a, const Vec3& b) noexcept;
double Distance3D(const Vec3& a, const Vec3& b) noexcept;
}

// ============================================================================
// CONFIG declarations
// ============================================================================
namespace monitor {
// TslGame 2609.1.2.5: checked against the local image's accessors/registration code.
namespace Offset {
inline constexpr u64 UWorld = 0x133133E8;
inline constexpr u64 WorldMode = 0x1176E900, WorldSlot = 0x1176E928;
inline constexpr u64 GameStateMode = 0x1176ED00, GameStateSlot = 0x1176ED28;
inline constexpr u64 GameInstanceMode = 0x1176EE00, GameInstanceSlot = 0x1176EE28;
inline constexpr u64 LocalPlayerMode = 0x1176FD00, LocalPlayerSlot = 0x1176FD28;
inline constexpr u64 ActorsMode = 0x1177BF00, ActorsSlot = 0x1177BF28;
inline constexpr u64 GameInstance = 0x2A8, CurrentLevel = 0x110, GameState = 0x940;
inline constexpr u64 TimeSeconds = 0x7D4, PlayerArray = 0x420, NumAliveTeams = 0x4AC;
inline constexpr u64 PlayerState = 0x430, RootComponent = 0x178, ComponentLocation = 0x2A0;
inline constexpr u64 Actors = 0x100;
inline constexpr u64 ComponentToWorld = 0x290, LocalPlayer = 0xE0, PlayerController = 0x38;
inline constexpr u64 AcknowledgedPawn = 0x4B0, TeamNumber = 0xB00;
inline constexpr u64 DBNORaw = 0x8F2, PlayerStatusType = 0x40C;
inline constexpr u64 PlayerName = 0x410, CharacterName = 0x1E10;
// User-supplied 2609.1.2.5 field. Exported as raw bits; no guessed name-index decryption.
inline constexpr u64 ObjectIdRaw = 0x24;
inline constexpr u64 ObjectNumberRaw = 0x28, GNames = 0x135A92A0, WorldOriginLocation = 0x30C;
}
struct Config {
    u32 requested_pid = 0; // Entered interactively at startup. Zero is rejected.
    int interval_ms = 300;
    int capture_budget_ms = 1500;
    unsigned read_attempts = 2;
    // Opt-in experiment: reuse only a fully checked WorldState raw value while the
    // same process/memory binding remains valid. Other game data stays live-read.
    bool experimental_world_cache = false;
    int world_refresh_interval_ms = 5000;
    // Confirmed address-space changes rebind immediately. Otherwise this remains
    // the last-resort threshold for sustained ROOT acquisition read failures.
    int root_failure_rebind_ms = 8000;
    int attach_retry_ms = 1500;
    int heartbeat_ms = 1000;
    int max_actors = 200000, max_players = 2048;
    double units_to_meters = 0.01; // User sample's working assumption; configurable here.
    // Fingerprint of the analyzed 2609.1.2.5 image. Never guess across builds.
    u32 expected_timestamp = 0x6AB10BA3;
    u32 expected_image_size = 0x1AFCC000;
    bool verify_expected_image = true;
    bool include_names = false; // Additional FString reads are optional.
    // Discovery is independent from the 300 ms position refresh.
    int discovery_interval_ms = 1000;
    int discovery_min_interval_ms = 500; // Throttles topology-triggered retries.
    int first_discovery_slice_ms = 300; // Cold start gets a larger bounded slice.
    std::size_t first_discovery_actors_per_slice = 2048;
    int discovery_slice_ms = 60;        // Cooperative slice; a backend call cannot be interrupted.
    std::size_t discovery_actors_per_slice = 256; // Baseline; large queues raise the quota within the time slice.
    int discovery_cycle_timeout_ms = 5000;
    int association_ttl_ms = 8000;      // Only a new discovery/control-chain observation renews this.
    int object_diagnostics_interval_ms = 5000;
    int scene_slice_ms = 60;
    int name_budget_ms = 40; // Optional metadata has an independent cooperative budget.
    std::size_t scene_actors_per_slice = 1024;
};
}

// ============================================================================
// COLLECTOR declarations
// ============================================================================
#include <map>
#include <unordered_map>

namespace monitor {
struct Session {
    u32 pid = 0;
    u64 process_sequence = 0, cr3 = 0, peb = 0, base = 0, generation = 0;
    u32 image_size = 0, timestamp = 0;
};
struct Player {
    i32 index = -1;
    u64 state = 0, pawn = 0, root = 0;
    std::optional<i32> team;
    std::optional<u8> killed_raw, dbno_raw, status_raw;
    std::optional<Vec3> position;
    std::string name;
    bool self = false;
    std::optional<double> distance2d, distance3d;
    std::string availability; // Diagnostic state, NOT an alive/dead classification.
    std::string mapping_source;
    Issue acquisition_issue;
};
struct DiscoveryStats {
    bool started = false, running = false, completed = false, bootstrap = false;
    u64 cycle = 0;
    std::size_t scanned_this_frame = 0, cursor = 0, total = 0;
    std::size_t slice_limit = 0;
    std::int64_t cycle_age_ms = -1;
    std::size_t candidates_found = 0, ambiguous = 0;
    std::int64_t last_completed_age_ms = -1;
    std::string reason;
    Issue issue; // A discovery-only failure does not invalidate independently revalidated positions.
};
struct CacheStats {
    bool reset = false;
    std::string reset_reason;
    std::size_t before = 0, after = 0, validated = 0;
    std::size_t invalidated = 0, expired = 0, roster_removed = 0, new_mappings = 0;
};
struct SceneActor {
    u64 actor=0, raw=0, root_raw=0, root=0;
    i32 index=-1;
    std::optional<u32> object_id_raw;
    std::optional<Vec3> position;
    std::optional<WorldOrigin> origin; // Bound to this observation, including cached observations.
    Clock::time_point observed{};
    std::string availability="NOT_SAMPLED";
};
struct Snapshot {
    Session session;
    Clock::time_point started = Clock::now(), finished = Clock::now();
    u64 sequence = 0;
    bool complete = false;
    Issue fatal, reference_issue;
    u64 world_state = 0, world = 0, game_state_raw = 0, game_state = 0;
    bool world_cache_used = false, world_root_unverified = false;
    bool world_refresh_attempted = false, world_refresh_succeeded = false, world_refresh_failed = false;
    bool world_cache_invalidated = false;
    std::int64_t world_cache_age_ms = -1; // Since the last successful raw-root read.
    u64 game_instance_raw = 0, game_instance = 0, level_raw = 0, level = 0;
    u64 local_player = 0, controller = 0, self_pawn = 0;
    u64 actors_state = 0, actors_header_address = 0;
    std::optional<Vec3> reference;
    std::optional<WorldOrigin> origin; // Brackets player/reference sampling, not later scene samples.
    Issue origin_issue, scene_origin_issue, world_name_issue;
    ObjectName world_name;
    NameCaptureStatus world_name_status=NameCaptureStatus::NotAttempted;
    u64 name_world=0; // Independent metadata identity; may differ from a rejected core capture.
    bool name_root_unverified=true;
    Clock::time_point world_name_observed{};
    ArrayHeader players_header{}, actors_header{}, local_players_header{};
    std::optional<float> time_seconds;
    std::optional<i32> alive_teams_raw;
    std::array<std::optional<u64>,12> world_words{}, game_state_words{};
    std::vector<Player> players, unmatched;
    std::size_t actor_objects = 0, matched = 0, positioned = 0, actor_failures = 0;
    std::size_t duplicate_matches = 0, backend_calls = 0, failed_attempts = 0;
    std::optional<Issue> first_actor_failure;
    std::vector<std::string> trace;
    std::map<std::string,ReadStageStats> read_stats;
    DiscoveryStats discovery;
    CacheStats cache;
    bool object_words_sampled = false;
    bool actors_header_sampled = false; // Header describes a discovery candidate copy, not a live roster.
    std::int64_t actors_header_age_ms = -1;
    std::size_t player_slots_unusable = 0;
    // Full copied Actor candidate list, including unreadable/unclassified entries.
    // Observation times belong to individual entries, not to the sending frame.
    std::vector<SceneActor> scene_actors;
    bool scene_list_valid=false;
    std::size_t scene_updated=0,scene_cursor=0;
    Issue scene_issue;
};
// One Collector per acquisition worker. It never caches positions or decrypted state.
// An optional experiment caches only a previously validated raw WorldState value.
class Collector {
public:
    Collector();
    ~Collector();
    Collector(const Collector&) = delete;
    Collector& operator=(const Collector&) = delete;
    void Reset() noexcept;
    Snapshot Capture(IBytes& backend,const Session& session,const Config& config,
                     const std::atomic_bool& stop,u64 sequence);
private:
    struct State;
    std::unique_ptr<State> state_;
};
// Compatibility full-pass one-shot API: no cross-call cache. Worker uses Collector::Capture.
Snapshot Capture(IBytes& backend,const Session& session,const Config& config,
                 const std::atomic_bool& stop,u64 sequence);
std::string SnapshotReport(const Snapshot& snapshot);
std::string WorldCacheFrameReport(const Snapshot& snapshot);
std::string MapFrameReport(const Snapshot& snapshot);
}

// ============================================================================
// BACKEND declarations
// ============================================================================
#include <memory>
namespace monitor {
class IBackend : public IBytes {
public:
    virtual void BeginDiagnostics(u64) {}
    virtual std::string DrainDiagnostics() { return {}; }
    virtual bool ExtendedDiagnostics() const noexcept { return false; }
    virtual unsigned DiagnosticsVersion() const noexcept { return ExtendedDiagnostics() ? 1 : 0; }
    virtual u64 DiagnosticBuildStamp() const noexcept { return 0; }
    virtual Session Attach(const Config& config, const std::atomic_bool& stop) = 0;
    virtual bool Alive() = 0;
    // Read-only binding probe. No binding mutation; nullopt means unavailable.
    virtual std::optional<u64> QueryAddressSpace(const Budget&) { return std::nullopt; }
    virtual void Detach() noexcept = 0;
};
std::unique_ptr<IBackend> MakeGuestBackend();
}

// ============================================================================
// VIEW declarations
// ============================================================================
#include <mutex>
namespace monitor {
struct ViewState {
    int target_interval_ms = 300;
    std::optional<Snapshot> latest;
    std::optional<Snapshot> last_good;
    Issue connection_issue;
    Session session;
    bool acquiring = false;
    Clock::time_point acquisition_started{};
    unsigned consecutive_failures = 0;
    // A complete old sample can be shown briefly, explicitly frozen, after
    // container-only races. The timestamp is never refreshed on a failure.
    int retained_display_ms = 3000;
    u64 observed_frames=0, accepted_frames=0, array_changed_frames=0, other_failed_frames=0;
    u64 discovery_slice_frames=0, cache_update_frames=0, discovery_warning_frames=0;
};
// Same underlying target/binding. generation is intentionally ignored: generation is
// this monitor's attach counter, not a game-process identity field.
bool SameSession(const Session& a,const Session& b) noexcept;
// Permission to keep a prior complete sample briefly and explicitly as STALE/FROZEN.
bool CanRetainAfterArrayChange(const Snapshot& previous,const Snapshot& current) noexcept;
// Caller owns SharedState::mutex. Also usable by offline replay tests.
void PublishSnapshot(ViewState& view,const Snapshot& frame,unsigned consecutive_failures);
struct SharedState { std::mutex mutex; ViewState view; };
std::vector<std::string> BuildScreen(const ViewState& view,int width,int height,
                                    unsigned requested_page,Clock::time_point now);
}

#if defined(_WIN32)

// ============================================================================
// Windows handle and symbol helpers
// ============================================================================
namespace monitor {
class UniqueHandle {
public:
    explicit UniqueHandle(HANDLE h=nullptr) noexcept : h_(h) {}
    ~UniqueHandle() { Reset(); }
    UniqueHandle(const UniqueHandle&)=delete;
    UniqueHandle& operator=(const UniqueHandle&)=delete;
    UniqueHandle(UniqueHandle&& o) noexcept : h_(o.h_) { o.h_=nullptr; }
    UniqueHandle& operator=(UniqueHandle&& o) noexcept { if(this!=&o){ Reset(); h_=o.h_; o.h_=nullptr; } return *this; }
    HANDLE Get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ && h_!=INVALID_HANDLE_VALUE; }
    void Reset(HANDLE h=nullptr) noexcept { if(*this) CloseHandle(h_); h_=h; }
private: HANDLE h_;
};
}

// ============================================================================
// Console and cooperative stop
// ============================================================================
namespace monitor {
class StopControl {
public:
    StopControl();
    ~StopControl();
    void Stop() noexcept;
    void Wait(int milliseconds) const noexcept;
    std::atomic_bool flag{false};
private:
    static BOOL WINAPI Handler(DWORD event);
    static std::atomic<StopControl*> active_;
    static std::atomic_uint handlers_;
    UniqueHandle event_;
    bool registered_=false;
};
class Console {
public:
    Console();
    ~Console();
    void Clear();
    void Text(const std::string& utf8);
    void Draw(const ViewState& view,unsigned page);
    int Key(); // '\r', 'n', 'p', 'd', or 0. No blocking call.
private:
    UniqueHandle out_;
    HANDLE in_=INVALID_HANDLE_VALUE;
    DWORD old_input_=0;
    bool input_changed_=false,cursor_saved_=false;
    CONSOLE_CURSOR_INFO old_cursor_{};
};
}

#endif // _WIN32
