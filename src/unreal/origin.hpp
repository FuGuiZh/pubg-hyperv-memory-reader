#pragma once
#include "monitor/monitor.hpp"

namespace monitor::unreal {
inline std::optional<WorldOrigin> ReadOrigin(Reader& memory,u64 world,Issue& issue,const char* stage) {
    try {return memory.Value<WorldOrigin>(Add(world,Offset::WorldOriginLocation,stage),stage);}
    catch(const Fault& e) {
        if(e.issue().code==Code::Cancelled || e.issue().code==Code::Deadline)throw;
        issue=e.issue();return std::nullopt;
    }
}
inline std::optional<WorldOrigin> CheckOrigin(Reader& memory,u64 world,
    const std::optional<WorldOrigin>& before,Issue& issue,const char* stage) {
    if(!before)return std::nullopt;
    const auto after=ReadOrigin(memory,world,issue,stage);
    if(!after)return std::nullopt;
    if(*after!=*before) {
        issue=Issue{Code::SnapshotChanged,stage,"World origin changed during position sampling"};
        return std::nullopt;
    }
    return before;
}
}
