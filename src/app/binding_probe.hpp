#pragma once
#include "monitor/monitor.hpp"

namespace monitor {
inline bool RootTransportFailure(const Snapshot& frame) noexcept {
    // A final consistency check has already reached a valid root chain.
    return !frame.complete && frame.fatal.code == Code::ReadFailed
        && (!frame.world || !frame.game_state || !frame.level);
}

struct BindingProbeResult {
    bool attempted = false, changed = false;
    std::optional<u64> observed_cr3;
};

// A failed page is not evidence of a changed address space. Ask the backend for
// the current process binding, rate limited, without switching the active CR3.
class BindingProbe {
public:
    static constexpr int interval_ms = 1000;
    static constexpr int budget_ms = 100;
    void Reset() noexcept { next_ = Clock::time_point::min(); }
    BindingProbeResult Check(IBackend& backend, const Snapshot& frame,
                             const std::atomic_bool& stop, Clock::time_point now) {
        if (!RootTransportFailure(frame) || now < next_) return {};
        next_ = now + std::chrono::milliseconds(interval_ms);
        BindingProbeResult result;
        result.attempted = true;
        try {
            const Budget budget{&stop, now + std::chrono::milliseconds(budget_ms)};
            budget.Check("ADDRESS_SPACE_PROBE");
            result.observed_cr3 = backend.QueryAddressSpace(budget);
            budget.Check("ADDRESS_SPACE_PROBE");
        } catch (const Fault& error) {
            if (error.issue().code != Code::Deadline && error.issue().code != Code::ReadFailed) throw;
            result.observed_cr3.reset();
        }
        constexpr u64 root_mask = 0x000FFFFFFFFFF000ULL;
        if (result.observed_cr3 && !(*result.observed_cr3 & root_mask)) result.observed_cr3.reset();
        result.changed = result.observed_cr3 && (frame.session.cr3 & root_mask)
            && ((*result.observed_cr3 & root_mask) != (frame.session.cr3 & root_mask));
        return result;
    }
private:
    Clock::time_point next_ = Clock::time_point::min();
};
}
