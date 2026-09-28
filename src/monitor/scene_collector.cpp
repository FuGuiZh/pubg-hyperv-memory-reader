#include "monitor/scene_collector.hpp"
#include "arch/x64/resolver.hpp"
#include "unreal/origin.hpp"
#include <algorithm>
#include <unordered_set>

namespace monitor {
void SceneCollector::Capture(IBytes& backend,Snapshot& f,const Config& c,const std::atomic_bool& stop) {
    f.scene_actors.clear();f.scene_list_valid=false;f.scene_updated=0;f.scene_cursor=0;f.scene_issue={};f.scene_origin_issue={};
    if(!f.complete)return;
    if(!SameSession(session_,f.session) || world_!=f.world || level_!=f.level || game_state_!=f.game_state) {
        observations_.clear();cursor_=0;
        session_=f.session;world_=f.world;level_=f.level;game_state_=f.game_state;
    }
    const auto deadline=Clock::now()+std::chrono::milliseconds(c.scene_slice_ms);
    Reader m(backend,Budget{&stop,deadline},c.read_attempts);
    FrameResolver resolver(m,f.session.base,nullptr);
    try {
        const auto origin_before=unreal::ReadOrigin(m,f.world,f.scene_origin_issue,"SCENE_ORIGIN_READ");
        const u64 slot=Add(f.level,Offset::Actors,"SCENE_ARRAY_ADDRESS");
        const auto raw=m.Value<u64>(slot,"SCENE_ARRAY_STATE");
        const auto header_address=resolver.Actors(raw);
        ArrayHeader header;
        const auto values=ArrayValues(m,header_address,c.max_actors,"SCENE_ARRAY",&header);
        std::vector<SceneActor> updated;
        if(!values.empty()) cursor_%=values.size(); else cursor_=0;
        auto next=cursor_;
        // Reserve time for context/code rechecks. A backend call is cooperative
        // and can overrun; that causes this scene sample to be rejected explicitly.
        const auto sample_until=deadline-std::chrono::milliseconds(std::min(10,std::max(1,c.scene_slice_ms/4)));
        for(std::size_t count=0;count<std::min(c.scene_actors_per_slice,values.size()) && Clock::now()<sample_until;++count) {
            m.Check("SCENE_SAMPLE");
            SceneActor a;a.raw=values[next];a.index=static_cast<i32>(next);a.observed=Clock::now();
            next=(next+1)%values.size();
            if(!UserAddress(a.raw)) {a.availability="INVALID_ACTOR_ADDRESS";updated.push_back(std::move(a));continue;}
            a.actor=a.raw; // Actor-array entries use the same plain-pointer path as existing discovery.
            try {
                a.object_id_raw=m.Probe<u32>(Add(a.actor,Offset::ObjectIdRaw,"SCENE_OBJECT_ID"),"SCENE_OBJECT_ID");
                a.root=resolver.Field(a.actor,Offset::RootComponent,Cipher::RootComponent,"SCENE_ROOT_READ",&a.root_raw);
                if(!a.root) Fail(Code::NoReference,"SCENE_ROOT_NULL","Actor has no readable root component");
                a.position=m.Value<Vec3>(Add(a.root,Offset::ComponentLocation,"SCENE_POSITION"),"SCENE_POSITION");
                if(m.Value<u64>(Add(a.actor,Offset::RootComponent,"SCENE_ROOT_RECHECK"),"SCENE_ROOT_RECHECK")!=a.root_raw) {
                    a.position.reset();Fail(Code::SnapshotChanged,"SCENE_ROOT_RECHECK","Root association changed during sample");
                }
                // Raw floats are retained, even NaN/out-of-range: radar owns display filtering.
                a.availability="RAW_POSITION_READ";
            } catch(const Fault& e) {
                if(e.issue().code==Code::Cancelled || e.issue().code==Code::Deadline)throw;
                a.position.reset();a.availability=e.issue().stage+":"+CodeName(e.issue().code);
            }
            updated.push_back(std::move(a));
        }
        if(m.Value<u64>(slot,"SCENE_ARRAY_STATE_RECHECK")!=raw
            || !(m.Value<ArrayHeader>(header_address,"SCENE_ARRAY_HEADER_RECHECK")==header)
            || m.Value<u64>(Add(f.world,Offset::GameState,"SCENE_CONTEXT"),"SCENE_GAMESTATE_RECHECK")!=f.game_state_raw
            || m.Value<u64>(Add(f.world,Offset::CurrentLevel,"SCENE_CONTEXT"),"SCENE_LEVEL_RECHECK")!=f.level_raw)
            Fail(Code::SnapshotChanged,"SCENE_CONTEXT_RECHECK","Scene list header or World context changed");
        resolver.Verify();
        const auto origin=unreal::CheckOrigin(m,f.world,origin_before,f.scene_origin_issue,"SCENE_ORIGIN_RECHECK");
        for(auto& a:updated)if(a.position)a.origin=origin;
        // Commit only after the shared scene context/code passed its checks.
        for(auto& a:updated) {const auto key=a.raw;observations_[key]=std::move(a);}
        f.scene_updated=updated.size();cursor_=next;f.scene_cursor=cursor_;
        std::unordered_set<u64> current(values.begin(),values.end());
        for(auto it=observations_.begin();it!=observations_.end();) {
            if(!current.count(it->first))it=observations_.erase(it);else ++it;
        }
        f.scene_actors.reserve(values.size());
        for(std::size_t i=0;i<values.size();++i) {
            const auto found=observations_.find(values[i]);
            SceneActor a;
            if(found!=observations_.end())a=found->second;
            a.raw=values[i];a.actor=UserAddress(a.raw)?a.raw:0;a.index=static_cast<i32>(i);
            f.scene_actors.push_back(std::move(a));
        }
        f.scene_list_valid=true;
    } catch(const Fault& e) { f.scene_issue=e.issue(); }
    for(const auto& [stage,stat]:m.Stats()) {
        auto& target=f.read_stats[stage];target.attempts+=stat.attempts;target.failed_attempts+=stat.failed_attempts;
        target.exhausted_requests+=stat.exhausted_requests;
        if(!target.first_failed_address){target.first_failed_address=stat.first_failed_address;target.first_requested_bytes=stat.first_requested_bytes;}
    }
    f.backend_calls+=m.Calls();f.failed_attempts+=m.FailedAttempts();f.finished=Clock::now();
}
}
