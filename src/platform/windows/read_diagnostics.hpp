#pragma once
#include "monitor/monitor.hpp"
#include "platform/windows/guest_memory.hpp"
#include <sstream>

namespace monitor {
// One worker owns the journal. Disk IO stays outside capture; v3 World reads
// explicitly request a post-copy traversal whose evidence is kept separately.
class ReadDiagnostics {
public:
    struct SampleTime {
        Clock::time_point tick = Clock::now();
        u64 epoch_ms = static_cast<u64>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    };
    void Begin(u64 frame) { frame_ = frame; records_.clear(); counts_.clear(); dropped_ = ordinary_ = critical_ = baselines_ = dropped_baselines_ = 0; checked_pairs_ = mapping_changes_ = entry_changes_ = chain_unavailable_ = 0; }
    void ResetHistory() noexcept { watches_ = {}; }
    void Context(const char* stage, unsigned attempt) { stage_ = stage ? stage : "UNSPECIFIED"; attempt_ = attempt; }
    bool WantsChain() const { return stage_ == "WORLD_STATE_READ" || stage_ == "WORLD_RECHECK"
        || stage_ == "WORLD_CACHE_REFRESH" || stage_ == "WORLD_CACHE_RECHECK" || stage_.starts_with("MODULE_"); }
    void ObserveConsistency(const GuestReadFailure& evidence, const char* path, u64 address, std::size_t bytes) {
        if (!evidence.translation.chain_requested) return;
        const bool unavailable = evidence.consistency == GuestReadFailure::Consistency::Unavailable || !evidence.translation.chain_valid
            || (evidence.post_translation.invoked && !evidence.post_translation.chain_valid);
        if (evidence.post_translation.invoked) ++checked_pairs_;
        if (evidence.consistency == GuestReadFailure::Consistency::EntryBitsChanged) ++entry_changes_;
        const bool changed = evidence.consistency == GuestReadFailure::Consistency::MappingChanged;
        if (changed) ++mapping_changes_;
        if (unavailable) ++chain_unavailable_;
        if (changed || unavailable) {
            const SampleTime time;
            AddBaseline({stage_, attempt_, path, address, bytes, evidence, "CHECK", frame_, time.epoch_ms},
                changed ? "MAPPING_CHANGE" : "CHAIN_UNAVAILABLE");
        }
    }
    void Record(const GuestReadFailure& failure, const char* path, u64 address, std::size_t bytes, std::optional<SampleTime> sample_time = std::nullopt) {
        if (auto* watch = WatchFor(address, bytes, failure.target_cr3)) {
            if (!watch->failing && watch->last) AddBaseline(*watch->last, "PRE_FAILURE");
            watch->failing = true;
        }
        const bool critical = stage_.starts_with("WORLD_") || stage_.starts_with("GAMESTATE_") || stage_.starts_with("LEVEL_");
        auto& count = counts_[stage_];
        ++count;
        if (count > 16 || (critical ? critical_ >= 64 : ordinary_ >= 256)) { ++dropped_; return; }
        const auto time = sample_time ? *sample_time : SampleTime{};
        records_.push_back({stage_, attempt_, path, address, bytes, failure, "FAILURE", frame_, time.epoch_ms});
        critical ? ++critical_ : ++ordinary_;
    }
    // Called only after the entire logical read succeeds, including all byte fallbacks.
    void ObserveSuccess(const GuestReadFailure& evidence, const char* path, u64 address, std::size_t bytes, std::optional<SampleTime> sample_time = std::nullopt) {
        if (evidence.reason != GuestReadFailure::Reason::None || !evidence.copy.invoked) return;
        auto* watch = WatchFor(address, bytes, evidence.target_cr3);
        if (!watch) return;
        const auto time = sample_time ? *sample_time : SampleTime{};
        RecordValue sample{stage_, attempt_, path, address, bytes, evidence, "PERIODIC", frame_, time.epoch_ms};
        const bool periodic = !watch->last_periodic || time.tick - *watch->last_periodic >= std::chrono::seconds(5);
        if (watch->failing || periodic) {
            if (AddBaseline(sample, watch->failing ? "RECOVERY" : "PERIODIC")) watch->last_periodic = time.tick;
        }
        watch->last = std::move(sample);
        watch->failing = false;
    }
    std::string Drain() {
        if (records_.empty() && !dropped_ && !dropped_baselines_ && !checked_pairs_ && !chain_unavailable_) return {};
        std::ostringstream out;
        out << "TRANSPORT_FRAME frame=" << frame_ << " records=" << records_.size() << " omitted=" << dropped_
            << " failure_records=" << ordinary_ + critical_ << " baseline_records=" << baselines_
            << " baselines_omitted=" << dropped_baselines_ << " cpu_scope=windows_before_after;hv_apic_when_marked"
            << " checked_pairs=" << checked_pairs_ << " mapping_changes=" << mapping_changes_
            << " entry_bit_changes=" << entry_changes_ << " chain_unavailable=" << chain_unavailable_ << '\n';
        for (const auto& record : records_) {
            const auto& e = record.failure;
            out << "  stage=" << record.stage << " retry=" << record.attempt << " path=" << record.path
                << " request_va=" << Hex(record.address) << " request_bytes=" << record.bytes
                << " sub_va=" << Hex(e.va) << " sub_bytes=" << e.requested << " target_cr3=" << Hex(e.target_cr3)
                << " destination_va=" << Hex(e.destination_va) << " reason=" << Reason(e.reason)
                << " sample_kind=" << record.kind << " sample_frame=" << record.frame << " sample_epoch_ms=" << record.epoch_ms;
            Call(out, "translate", e.translation);
            Walk(out, e.translation);
            Call(out, "copy", e.copy);
            Call(out, "post_translate", e.post_translation);
            out << " consistency=" << Consistency(e.consistency)
                << " entry_change_mask=" << Hex(e.entry_change_mask) << " mapping_change_mask=" << Hex(e.mapping_change_mask)
                << " before_chain_requested=" << e.translation.chain_requested << " before_chain_valid=" << e.translation.chain_valid
                << " before_chain_bytes=" << e.translation.chain_bytes << " after_chain_requested=" << e.post_translation.chain_requested
                << " after_chain_valid=" << e.post_translation.chain_valid << " after_chain_bytes=" << e.post_translation.chain_bytes;
            out << '\n';
            Chain(out, "before", e.translation);
            Chain(out, "after", e.post_translation);
        }
        for (const auto& [stage, count] : counts_) out << "  stage_failures=" << stage << " count=" << count << '\n';
        const auto result = out.str();
        Begin(frame_);
        return result;
    }
private:
    static const char* Consistency(GuestReadFailure::Consistency value) {
        switch (value) {
        case GuestReadFailure::Consistency::SameObserved: return "SAME_OBSERVED";
        case GuestReadFailure::Consistency::EntryBitsChanged: return "ENTRY_BITS_CHANGED";
        case GuestReadFailure::Consistency::MappingChanged: return "MAPPING_CHANGED";
        case GuestReadFailure::Consistency::Unavailable: return "UNAVAILABLE";
        default: return "NOT_CHECKED";
        }
    }
    static void Chain(std::ostringstream& out, const char* phase, const GuestCallEvidence& call) {
        if (!call.chain_valid) return;
        for (unsigned i = 0; i < call.chain.count; ++i) {
            auto entry = call;
            entry.result.walk = call.chain.entries[i];
            out << "    chain_phase=" << phase << " index=" << i << " count=" << call.chain.count;
            Walk(out, entry);
            out << '\n';
        }
    }
    struct RecordValue {
        std::string stage;
        unsigned attempt;
        const char* path;
        u64 address;
        std::size_t bytes;
        GuestReadFailure failure;
        const char* kind;
        u64 frame, epoch_ms;
    };
    struct Watch {
        u64 address = 0, cr3 = 0;
        std::size_t bytes = 0;
        bool failing = false;
        std::optional<RecordValue> last;
        std::optional<Clock::time_point> last_periodic;
    };
    Watch* WatchFor(u64 address, std::size_t bytes, u64 cr3) {
        const int index = stage_ == "WORLD_STATE_READ" ? 0
            : stage_ == "WORLD_RECHECK" ? 1 : stage_ == "WORLD_CACHE_REFRESH" ? 2
            : stage_ == "WORLD_CACHE_RECHECK" ? 3 : -1;
        if (index < 0) return nullptr;
        auto& watch = watches_[index];
        if (watch.address != address || watch.bytes != bytes || watch.cr3 != cr3) {
            watch = {}; watch.address = address; watch.bytes = bytes; watch.cr3 = cr3;
        }
        return &watch;
    }
    bool AddBaseline(RecordValue sample, const char* kind) {
        if (baselines_ >= 8) { ++dropped_baselines_; return false; }
        sample.kind = kind; records_.push_back(std::move(sample)); ++baselines_; return true;
    }
    static void Walk(std::ostringstream& out, const GuestCallEvidence& e) {
        const auto& walk = e.result.walk;
        const bool available = e.invoked && e.result.marker == hypercall::diagnostic_marker && hypercall_walk::Valid(walk.status);
        out << " walk=" << (available ? "available" : "unavailable");
        if (!available) return;
        const auto outcome = static_cast<hypercall_walk::Outcome>(walk.status & 0xff);
        const auto level = static_cast<unsigned>((walk.status >> 8) & 0xff);
        constexpr const char* levels[] = {"UNKNOWN", "PT", "PD", "PDPT", "PML4"};
        out << " walk_status=" << Hex(walk.status) << " walk_outcome="
            << (outcome == hypercall_walk::Outcome::Success ? "SUCCESS" : outcome == hypercall_walk::Outcome::NotPresent ? "NOT_PRESENT" : "TABLE_MAPPING_FAILED")
            << " walk_level=" << levels[level] << " entry_valid=" << (outcome != hypercall_walk::Outcome::TableMappingFailed)
            << " entry_raw=" << Hex(walk.entry) << " entry_gpa=" << Hex(walk.entry_gpa)
            << " entry_hpa=" << Hex(walk.entry_hpa) << " page_shift=" << ((walk.status >> 16) & 0xff);
    }
    static const char* Reason(GuestReadFailure::Reason reason) {
        switch (reason) {
        case GuestReadFailure::Reason::TranslationZero: return "TRANSLATION_ZERO";
        case GuestReadFailure::Reason::CopyShort: return "COPY_SHORT";
        case GuestReadFailure::Reason::CopyOversized: return "COPY_OVERSIZED";
        case GuestReadFailure::Reason::InvalidArguments: return "INVALID_ARGUMENTS";
        case GuestReadFailure::Reason::MappingChanged: return "MAPPING_CHANGED";
        case GuestReadFailure::Reason::ChainUnavailable: return "CHAIN_UNAVAILABLE";
        default: return "NONE";
        }
    }
    static void Call(std::ostringstream& out, const char* name, const GuestCallEvidence& e) {
        out << ' ' << name << "_invoked=" << e.invoked;
        if (!e.invoked) return;
        out << ' ' << name << "_return=" << Hex(e.result.value)
            << ' ' << name << "_cpu_before=" << e.before.Group << ':' << unsigned(e.before.Number)
            << ' ' << name << "_cpu_after=" << e.after.Group << ':' << unsigned(e.after.Number);
        const bool hv = e.result.marker == hypercall::diagnostic_marker;
        out << ' ' << name << "_hv_context=" << (hv ? "available" : "unavailable");
        if (hv) out << ' ' << name << "_guest_cr3=" << Hex(e.result.guest_cr3)
            << ' ' << name << "_saved_slat=" << Hex(e.result.saved_slat)
            << ' ' << name << "_active_slat=" << Hex(e.result.active_slat)
            << ' ' << name << "_apic_kind=" << (e.result.cpu >> 32)
            << ' ' << name << "_apic_id=" << static_cast<u32>(e.result.cpu);
    }
    u64 frame_ = 0;
    std::string stage_ = "UNSPECIFIED";
    unsigned attempt_ = 0;
    std::size_t dropped_ = 0, ordinary_ = 0, critical_ = 0, baselines_ = 0, dropped_baselines_ = 0;
    std::size_t checked_pairs_ = 0, mapping_changes_ = 0, entry_changes_ = 0, chain_unavailable_ = 0;
    std::array<Watch, 4> watches_{};
    std::vector<RecordValue> records_;
    std::map<std::string, std::size_t> counts_;
};

inline Transfer ReadGuestBytes(GuestMemory& memory, ReadDiagnostics& diagnostics, u64 address, void* output, std::size_t bytes) {
    auto* dst = static_cast<u8*>(output);
    std::size_t off = 0;
    GuestReadFailure last_success;
    const char* last_path = "byte";
    GuestReadFailure failure;
    const auto read = [&](u64 at, auto& value, const char* path) {
        bool ok = memory.ReadValue(at, value, &failure, diagnostics.WantsChain());
        diagnostics.ObserveConsistency(failure, path, address, bytes);
        if (ok) return true;
        diagnostics.Record(failure, path, address, bytes);
        return ok;
    };
    while (off < bytes) {
        const auto at = address + off;
        if (bytes - off >= 8 && (at & 0xFFFULL) <= 0xFF8ULL) {
            u64 value = 0;
            const bool ok = read(at, value, "qword");
            if (ok) {
                last_success = failure; last_path = "qword";
                std::memcpy(dst + off, &value, 8); off += 8; continue;
            }
            // Smaller reads cannot repair a missing/unverified mapping. Retry
            // the whole logical request through Reader's existing bounded loop.
            if (failure.reason != GuestReadFailure::Reason::CopyShort
                || failure.consistency == GuestReadFailure::Consistency::MappingChanged
                || failure.consistency == GuestReadFailure::Consistency::Unavailable) return {false, off, std::nullopt};
        }
        u8 value = 0;
        const bool ok = read(at, value, "byte");
        if (!ok) {
            return {false, off, std::nullopt};
        }
        dst[off++] = value;
        last_success = failure; last_path = "byte";
    }
    if (bytes) diagnostics.ObserveSuccess(last_success, last_path, address, bytes);
    return {true, off, std::nullopt};
}
}
