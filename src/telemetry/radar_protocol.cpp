#include "telemetry/radar_protocol.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <stdexcept>

namespace monitor::radar {
namespace {
// A small encoder for the fixed schema. Compatibility is checked using code
// generated from radar.proto and the official protobuf parser in tests.
struct Wire {
    std::string bytes;
    void Varint(u64 n) { while(n>=128) { bytes.push_back(static_cast<char>((n&127)|128)); n>>=7; } bytes.push_back(static_cast<char>(n)); }
    void Tag(unsigned field,unsigned wire) { Varint((u64(field)<<3)|wire); }
    void UInt(unsigned field,u64 n) { Tag(field,0); Varint(n); }
    void Signed(unsigned field,std::int64_t n) { UInt(field,(static_cast<u64>(n)<<1)^static_cast<u64>(-(n<0))); }
    void Fixed(unsigned field,u64 bits,unsigned count) { Tag(field,count==4?5:1); for(unsigned i=0;i<count;++i) bytes.push_back(static_cast<char>((bits>>(i*8))&255)); }
    void Float(unsigned field,float n) { Fixed(field,std::bit_cast<u32>(n),4); }
    void Double(unsigned field,double n) { Fixed(field,std::bit_cast<u64>(n),8); }
    void Data(unsigned field,const std::string& value) { Tag(field,2); Varint(value.size()); bytes+=value; }
};
u64 Tick(Clock::time_point t) {
    return static_cast<u64>(std::max<std::int64_t>(0,std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count()));
}
std::string Position(const Vec3& p) { Wire w; w.Float(1,p.x);w.Float(2,p.y);w.Float(3,p.z);return w.bytes; }
std::string Origin(const WorldOrigin& p) {Wire w;w.Signed(1,p.x);w.Signed(2,p.y);w.Signed(3,p.z);return w.bytes;}
std::string Map(const Snapshot& f,bool accepted) {
    Wire map,n;
    const auto& name=f.world_name;
    const bool verified=name.verified && f.world_name_status==NameCaptureStatus::Succeeded;
    if(name.raw_index)n.UInt(1,*name.raw_index);
    if(name.raw_number)n.UInt(2,*name.raw_number);
    if(name.index)n.UInt(3,*name.index);
    if(name.number)n.UInt(4,*name.number);
    if(verified){n.Data(5,name.base);n.Data(6,name.full);}
    n.UInt(7,name.wide);n.UInt(8,verified);
    map.Data(1,n.bytes);
    if(accepted && f.origin)map.Data(2,Origin(*f.origin));
    map.UInt(3,Tick(f.world_name_observed));
    map.UInt(4,f.name_world);map.UInt(5,f.name_root_unverified);
    map.UInt(6,static_cast<unsigned>(f.world_name_status));
    u64 attempts=0,failed=0;
    for(const char* stage:{"NAME_WORLD_STATE_READ","NAME_WORLD_RECHECK"}) {
        const auto it=f.read_stats.find(stage);
        if(it!=f.read_stats.end()){attempts+=it->second.attempts;failed+=it->second.failed_attempts;}
    }
    map.UInt(7,attempts);map.UInt(8,failed);
    return map.bytes;
}
std::string Entity(const Actor& a) {
    Wire w;
    w.UInt(1,a.actor_id);w.UInt(2,a.player_state_id);
    if(a.roster_index) w.Signed(3,*a.roster_index);
    if(a.position) w.Data(4,Position(*a.position));
    if(a.team_id) w.Signed(5,*a.team_id);
    w.Data(7,a.name);w.Data(8,a.type_name);
    if(a.status_raw) w.UInt(10,*a.status_raw);
    if(a.dbno_raw) w.UInt(11,*a.dbno_raw);
    if(a.killed_raw) w.UInt(12,*a.killed_raw);
    w.Data(13,a.availability);w.Data(14,a.source);w.UInt(15,a.observed_at_monotonic_ms);
    w.UInt(16,a.raw_actor_value);w.UInt(17,a.class_id);
    if(a.name_id) w.UInt(18,*a.name_id);
    if(a.item_id) w.UInt(19,*a.item_id);
    if(a.item_count) w.Signed(20,*a.item_count);
    w.Data(21,a.vehicle_type);w.Data(22,a.item_name);w.UInt(23,a.root_component_id);
    if(a.object_id_raw)w.UInt(24,*a.object_id_raw);
    w.UInt(25,a.root_component_raw);
    if(a.actor_array_index)w.Signed(26,*a.actor_array_index);
    if(a.position && a.origin)w.Data(27,Origin(*a.origin));
    return w.bytes;
}
std::string Diagnostics(const Snapshot& f) {
    Wire w;
    w.UInt(1,f.world_cache_used);w.UInt(2,f.world_root_unverified);w.UInt(3,f.world_cache_invalidated);
    w.UInt(4,f.world_refresh_attempted);w.UInt(5,f.world_refresh_succeeded);
    u64 attempts=0,failed=0;
    for(const char* stage:{"WORLD_STATE_READ","WORLD_RECHECK","WORLD_CACHE_REFRESH","WORLD_CACHE_RECHECK"}) {
        const auto it=f.read_stats.find(stage);
        if(it!=f.read_stats.end()) {attempts+=it->second.attempts;failed+=it->second.failed_attempts;}
    }
    w.UInt(6,attempts);w.UInt(7,failed);w.Data(8,CodeName(f.fatal.code));w.Data(9,f.fatal.stage);
    w.UInt(10,std::max(0,f.players_header.num));w.UInt(11,f.matched);w.UInt(12,f.positioned);w.UInt(13,f.unmatched.size());
    w.UInt(14,f.discovery.cycle);w.UInt(15,f.discovery.cursor);w.UInt(16,f.discovery.total);
    w.UInt(17,f.discovery.running);w.UInt(18,f.discovery.completed);w.Signed(19,f.discovery.last_completed_age_ms);
    w.Data(20,f.discovery.issue.stage);w.UInt(21,f.player_slots_unusable);
    w.UInt(22,f.scene_list_valid);w.UInt(23,f.scene_actors.size());w.UInt(24,f.scene_updated);w.UInt(25,f.scene_cursor);
    w.Data(26,CodeName(f.scene_issue.code));w.Data(27,f.scene_issue.stage);
    w.Data(28,CodeName(f.world_name_issue.code));w.Data(29,f.world_name_issue.stage);
    w.Data(30,CodeName(f.origin_issue.code));w.Data(31,f.origin_issue.stage);
    w.Data(32,CodeName(f.scene_origin_issue.code));w.Data(33,f.scene_origin_issue.stage);
    return w.bytes;
}
}

std::vector<Actor> PlayerActors(const Snapshot& f) {
    std::vector<Actor> out;
    out.reserve(f.players.size()+f.unmatched.size());
    auto append=[&](const Player& p) {
        Actor a;
        a.actor_id=p.pawn;a.player_state_id=p.state;a.root_component_id=p.root;a.roster_index=p.index;
        a.position=p.position;a.team_id=p.team;a.name=p.name;
        if(p.position)a.origin=f.origin;
        a.source="PLAYER_ROSTER";a.availability=p.availability;
        a.observed_at_monotonic_ms=Tick(f.started);
        a.status_raw=p.status_raw;a.dbno_raw=p.dbno_raw;a.killed_raw=p.killed_raw;
        out.push_back(std::move(a));
    };
    for(const auto& p:f.players) append(p);
    for(const auto& p:f.unmatched) append(p);
    std::stable_sort(out.begin(),out.end(),[](const Actor& a,const Actor& b){return a.roster_index<b.roster_index;});
    return out;
}

std::vector<Actor> AllActors(const Snapshot& f) {
    auto out=PlayerActors(f);out.reserve(out.size()+f.scene_actors.size());
    for(const auto& p:f.scene_actors) {
        Actor a;a.actor_id=p.actor;a.raw_actor_value=p.raw;a.root_component_id=p.root;a.root_component_raw=p.root_raw;
        a.actor_array_index=p.index;a.object_id_raw=p.object_id_raw;a.position=p.position;
        a.origin=p.origin;
        a.observed_at_monotonic_ms=Tick(p.observed);a.availability=p.availability;a.source="SCENE_ARRAY";
        out.push_back(std::move(a));
    }
    return out;
}

std::vector<std::string> Encode(const Snapshot& f,const Metadata& m,const std::vector<Actor>& actors,
    FrameStatus status,std::size_t limit) {
    if(limit>kMaxDatagramBytes || limit<512) throw std::invalid_argument("Invalid radar datagram bound");
    const bool accepted=status==FrameStatus::Accepted && f.complete;
    if(status==FrameStatus::Accepted && !f.complete) status=FrameStatus::Rejected;
    Wire header;
    header.UInt(1,kSchemaVersion);header.Data(2,m.stream_id);header.UInt(3,m.sequence);header.UInt(4,m.sent_at_unix_ms);
    header.UInt(5,Tick(f.started));header.UInt(6,Tick(f.finished)>=Tick(f.started)?Tick(f.finished)-Tick(f.started):0);
    header.UInt(7,static_cast<unsigned>(status));header.UInt(8,f.session.pid);header.UInt(9,f.session.process_sequence);
    header.UInt(10,f.session.generation);header.UInt(11,f.world);header.UInt(12,f.game_state);header.UInt(13,f.level);
    if(f.time_seconds && std::isfinite(*f.time_seconds)) header.Float(14,*f.time_seconds);
    header.Double(15,m.meters_per_unit);
    if(accepted && (f.self_pawn || f.reference)) {
        Wire self;self.UInt(1,f.self_pawn);if(f.reference)self.Data(2,Position(*f.reference));
        if(f.reference && f.origin)self.Data(3,Origin(*f.origin));
        header.Data(16,self.bytes);
    }
    header.UInt(20,accepted?actors.size():0);header.Data(21,Diagnostics(f));header.UInt(22,f.sequence);
    header.UInt(23,m.interval_ms);header.Data(24,m.build_sha256);
    // Metadata has its own checked identity. Rejected player frames still contain
    // zero actors/local positions, even when an independent name read succeeds.
    if(status==FrameStatus::Accepted || status==FrameStatus::Rejected)header.Data(25,Map(f,accepted));
    // Two uint32 part fields need at most 14 bytes, including two-byte tags.
    constexpr std::size_t part_budget=14;
    if(header.bytes.size()+part_budget>limit) throw std::length_error("Radar metadata exceeds datagram bound");
    std::vector<std::string> parts(1,header.bytes);
    if(accepted) for(const auto& a:actors) {
        Wire encoded;encoded.Data(17,Entity(a));
        if(header.bytes.size()+encoded.bytes.size()+part_budget>limit)
            throw std::length_error("One radar actor exceeds datagram bound");
        if(parts.back().size()+encoded.bytes.size()+part_budget>limit) parts.push_back(header.bytes);
        parts.back()+=encoded.bytes;
    }
    for(std::size_t i=0;i<parts.size();++i) {
        Wire tags;tags.UInt(18,i);tags.UInt(19,parts.size());parts[i]+=tags.bytes;
    }
    return parts;
}
}
