#pragma once
#include "monitor/monitor.hpp"

namespace monitor {
// General scene telemetry, independent from player association/discovery rules.
// Each call copies the candidate list and samples a bounded rotating slice.
class SceneCollector {
public:
    void Capture(IBytes& backend,Snapshot& frame,const Config& config,const std::atomic_bool& stop);
private:
    Session session_{};
    u64 world_=0,level_=0,game_state_=0;
    std::size_t cursor_=0;
    std::unordered_map<u64,SceneActor> observations_;
};
}
