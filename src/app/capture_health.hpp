#pragma once
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>

namespace monitor {
// Counts complete capture outcomes, independently of transport retries/subrequests.
// Recovery is immediate; sustained success is a separate, timed observation.
class CaptureHealth {
public:
    using ClockType = std::chrono::steady_clock;
    enum class Failure { Root, Recheck, Other };
    std::string Observe(std::uint64_t frame, bool complete, Failure kind, ClockType::time_point now) {
        ++observed_;
        std::ostringstream out;
        if (!complete) {
            ++failed_; ++streak_;
            if (kind == Failure::Root) ++root_;
            else if (kind == Failure::Recheck) ++recheck_;
            else ++other_;
            success_streak_ = 0; stable_reported_ = false;
            if (streak_ == 1) {
                ++episodes_; failed_since_ = now;
                out << "CAPTURE_HEALTH state=FAILING frame=" << frame << " episode=" << episodes_;
            }
            if (streak_ > longest_) longest_ = streak_;
        } else {
            ++accepted_; ++success_streak_;
            if (success_streak_ == 1) success_since_ = now;
            if (streak_) {
                out << "CAPTURE_HEALTH state=RECOVERED frame=" << frame << " episode=" << episodes_
                    << " failed_frames=" << streak_ << " outage_ms=" << Milliseconds(now - failed_since_)
                    << " sustained_success=0";
                ++recoveries_; streak_ = 0;
            } else if (!stable_reported_ && Milliseconds(now - success_since_) >= 5000) {
                out << "CAPTURE_HEALTH state=STABLE frame=" << frame << " consecutive_successes=" << success_streak_
                    << " success_span_ms=" << Milliseconds(now - success_since_);
                stable_reported_ = true;
            }
        }
        return out.str();
    }
    std::string BreakContinuity(const char* reason) {
        if (!streak_ && !success_streak_) return {};
        std::ostringstream out;
        out << "CAPTURE_HEALTH state=INTERRUPTED reason=" << reason << " failed_frames=" << streak_;
        if (streak_) ++interrupted_;
        streak_ = success_streak_ = 0;
        stable_reported_ = false;
        return out.str();
    }
    std::string Counters() const {
        std::ostringstream out;
        out << " health_observed=" << observed_ << " health_accepted=" << accepted_ << " health_failed=" << failed_
            << " root_read_failed=" << root_ << " recheck_failed=" << recheck_ << " other_capture_failed=" << other_
            << " failure_episodes=" << episodes_ << " recovery_episodes=" << recoveries_
            << " current_failed_streak=" << streak_ << " longest_failed_streak=" << longest_
            << " consecutive_successes=" << success_streak_ << " interrupted_failure_episodes=" << interrupted_;
        return out.str();
    }
private:
    static long long Milliseconds(ClockType::duration duration) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    }
    std::uint64_t observed_ = 0, accepted_ = 0, failed_ = 0, root_ = 0, recheck_ = 0, other_ = 0;
    std::uint64_t episodes_ = 0, recoveries_ = 0, streak_ = 0, longest_ = 0, success_streak_ = 0, interrupted_ = 0;
    ClockType::time_point failed_since_{}, success_since_{};
    bool stable_reported_ = false;
};
}
