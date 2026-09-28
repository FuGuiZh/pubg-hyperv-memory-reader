#include "unreal/names.hpp"
#include <bit>
#include <iomanip>
#include <sstream>

namespace monitor::unreal {
u32 DecodeNameIndex(u32 raw) noexcept {
    const u32 t=raw^0x65630A2CU;
    return std::rotr(t,20)^(((t>>4)&0x0FFF0000U)|(t<<28))^0xC19C5851U;
}
u32 DecodeNameNumber(u32 raw) noexcept {
    const u32 n=raw^0x3F1D4464U;
    return std::rotr(n,16)^(n&0xFFFF0000U)^0x2FFA9EFCU;
}
namespace {
void Utf8(std::string& out,u32 cp) {
    if(cp<0x80)out.push_back(char(cp));
    else if(cp<0x800){out.push_back(char(0xc0|(cp>>6)));out.push_back(char(0x80|(cp&63)));}
    else if(cp<0x10000){out.push_back(char(0xe0|(cp>>12)));out.push_back(char(0x80|((cp>>6)&63)));out.push_back(char(0x80|(cp&63)));}
    else {out.push_back(char(0xf0|(cp>>18)));out.push_back(char(0x80|((cp>>12)&63)));out.push_back(char(0x80|((cp>>6)&63)));out.push_back(char(0x80|(cp&63)));}
}
void Pointer(u64 value,const char* stage) {
    if(!UserAddress(value))Fail(Code::InvalidAddress,stage,"Invalid name-chain pointer",value);
}
}
void NameResolver::ReadObject(u64 object,ObjectName& out,std::size_t max_units) {
    out={};
    if(max_units==0 || max_units>1024)Fail(Code::InvalidLayout,"NAME_LENGTH_LIMIT","Invalid name scan bound");
    Pointer(object,"NAME_OBJECT");
    std::vector<std::pair<u64,u64>> links;
    auto link=[&](u64 at,const char* stage) {
        const u64 raw=memory_.Value<u64>(at,stage);links.emplace_back(at,raw);
        if(trace_)trace_->push_back(std::string(stage)+" address="+Hex(at)+" raw="+Hex(raw));
        return raw;
    };
    const u64 object_at=Add(object,Offset::ObjectIdRaw,"NAME_OBJECT");
    const u64 identity=link(object_at,"NAME_OBJECT_IDENTITY");
    out.raw_index=u32(identity);out.raw_number=u32(identity>>32);
    out.index=DecodeNameIndex(*out.raw_index);out.number=DecodeNameNumber(*out.raw_number);
    if(*out.index>0x7fffffffU)Fail(Code::InvalidLayout,"NAME_INDEX","Negative decoded name index",object_at);
    auto decode=[&](u64 raw,Cipher kind,const char* stage) {
        const u64 p=cipher_.Resolve(raw,kind);Pointer(p,stage);return p;
    };
    const u64 g10=decode(link(Add(base_,Offset::GNames+0x20,"NAMES_GLOBAL"),"NAMES_GLOBAL20_READ"),Cipher::NamesGlobal20,"NAMES_GLOBAL10_POINTER");
    const u64 g0=decode(link(g10,"NAMES_GLOBAL10_READ"),Cipher::NamesGlobal10,"NAMES_GLOBAL0_POINTER");
    const u64 container=decode(link(g0,"NAMES_GLOBAL0_READ"),Cipher::NamesContainer,"NAMES_CONTAINER_POINTER");
    // Preserve the original call boundary pairs, including when mode == 0.
    const u64 encoded_container=cipher_.Resolve(container,Cipher::NamesContainerEncode);
    const u64 decoded_container=decode(encoded_container,Cipher::NamesContainerDecode,"NAMES_CONTAINER_DECODE_POINTER");
    if(decoded_container!=container)Fail(Code::InvalidLayout,"NAMES_CONTAINER_ROUNDTRIP","Container encode/decode disagree");
    const u64 blocks=decode(link(decoded_container,"NAMES_ARRAY_READ"),Cipher::NamesBlocks,"NAMES_BLOCKS_POINTER");
    const u64 chunk=link(Add(blocks,8ULL*(*out.index/0x3FB8),"NAME_CHUNK_ADDRESS"),"NAME_CHUNK_READ");
    Pointer(chunk,"NAME_CHUNK_POINTER");
    const u64 entry=link(Add(chunk,8ULL*(*out.index%0x3FB8),"NAME_ENTRY_ADDRESS"),"NAME_ENTRY_READ");
    Pointer(entry,"NAME_ENTRY_POINTER");
    const u64 encoded_entry=cipher_.Resolve(entry,Cipher::NamesEntryEncode);
    const u64 decoded_entry=decode(encoded_entry,Cipher::NamesEntryDecode,"NAME_ENTRY_DECODE_POINTER");
    if(decoded_entry!=entry)Fail(Code::InvalidLayout,"NAME_ENTRY_ROUNDTRIP","Entry encode/decode disagree");
    const u64 header=cipher_.Resolve(link(decoded_entry,"NAME_HEADER_READ"),Cipher::NamesHeader);
    out.wide=(header&1)!=0;
    const u64 text_at=Add(decoded_entry,0x10,"NAME_TEXT_ADDRESS");
    std::vector<u16> units;std::vector<u8> bytes;
    bool terminated=false;
    // Read only through the terminator, avoiding speculative cross-page reads.
    for(std::size_t i=0;i<max_units;++i) {
        const u64 at=Add(text_at,i*(out.wide?2ULL:1ULL),"NAME_TEXT_ADDRESS");
        const u16 unit=out.wide?memory_.Value<u16>(at,"NAME_TEXT_READ"):memory_.Value<u8>(at,"NAME_TEXT_READ");
        units.push_back(unit);bytes.push_back(u8(unit));if(out.wide)bytes.push_back(u8(unit>>8));
        if(!unit){terminated=true;break;}
    }
    if(!terminated)Fail(Code::InvalidLayout,"NAME_TEXT_LIMIT","Name has no terminator within bounded scan",text_at);
    std::string text;
    for(std::size_t i=0;i+1<units.size();++i) {
        u32 cp=units[i];
        if(!out.wide) {text.push_back(cp<128?char(cp):'?');continue;}
        if(cp>=0xd800 && cp<=0xdbff) {
            if(i+2>=units.size() || units[i+1]<0xdc00 || units[i+1]>0xdfff)
                Fail(Code::InvalidLayout,"NAME_UTF16","Unpaired high surrogate",text_at);
            cp=0x10000+((cp-0xd800)<<10)+(units[++i]-0xdc00);
        } else if(cp>=0xdc00 && cp<=0xdfff)Fail(Code::InvalidLayout,"NAME_UTF16","Unpaired low surrogate",text_at);
        Utf8(text,cp);
    }
    for(const auto& [at,raw]:links)
        if(memory_.Value<u64>(at,"NAME_LINK_RECHECK")!=raw)
            Fail(Code::SnapshotChanged,"NAME_LINK_RECHECK","Name identity or container changed",at);
    std::vector<u8> text_after(bytes.size());
    memory_.Bytes(text_at,text_after.data(),text_after.size(),"NAME_TEXT_RECHECK");
    if(bytes!=text_after)Fail(Code::SnapshotChanged,"NAME_TEXT_RECHECK","Name text changed",text_at);
    cipher_.Verify();
    out.base=std::move(text);out.full=out.base;
    if(*out.number)out.full+="_"+std::to_string(*out.number-1);
    out.verified=true;
}
void CaptureWorldName(IBytes& backend,Snapshot& f,const Config& c,const std::atomic_bool& stop) {
    f.world_name={};f.world_name_issue={};f.world_name_observed={};
    f.world_name_status=NameCaptureStatus::NotAttempted;f.name_world=0;f.name_root_unverified=true;
    if(stop.load() || f.fatal.code==Code::Cancelled) {
        f.world_name_issue={Code::Cancelled,"NAME_NOT_ATTEMPTED","Capture cancelled"};return;
    }
    if(!f.session.pid || !UserAddress(f.session.base) || f.fatal.code==Code::SessionChanged
        || f.fatal.code==Code::ProcessExited || f.fatal.code==Code::ImageMismatch) {
        f.world_name_issue={Code::SessionChanged,"NAME_NOT_ATTEMPTED","No eligible bound image/session"};return;
    }
    Reader m(backend,Budget{&stop,Clock::now()+std::chrono::milliseconds(c.name_budget_ms)},c.read_attempts);
    FrameResolver cipher(m,f.session.base,&f.trace);
    NameResolver names(m,cipher,f.session.base,&f.trace);
    try {
        f.world_name_status=NameCaptureStatus::Failed; // Remains failed until every check passes.
        f.world_name_observed=Clock::now();
        const u64 root_slot=Add(f.session.base,Offset::UWorld,"NAME_WORLD_ADDRESS");
        u64 root_raw=0,game_state_raw=0,level_raw=0;
        if(f.complete) {
            // Preserve the accepted core's root-cache contract; no extra global root read.
            f.name_world=f.world;f.name_root_unverified=f.world_root_unverified;
            game_state_raw=f.game_state_raw;level_raw=f.level_raw;
        } else {
            // A failed player capture is not evidence that its cached World is current.
            // Acquire independently; never fall back to the rejected frame's old World.
            root_raw=m.Value<u64>(root_slot,"NAME_WORLD_STATE_READ");
            f.name_world=cipher.World(root_raw);Pointer(f.name_world,"NAME_WORLD_POINTER");
            game_state_raw=m.Value<u64>(Add(f.name_world,Offset::GameState,"NAME_CONTEXT"),"NAME_GAMESTATE_READ");
            level_raw=m.Value<u64>(Add(f.name_world,Offset::CurrentLevel,"NAME_CONTEXT"),"NAME_LEVEL_READ");
        }
        names.ReadObject(f.name_world,f.world_name);
        if(m.Value<u64>(Add(f.name_world,Offset::GameState,"NAME_CONTEXT"),"NAME_GAMESTATE_RECHECK")!=game_state_raw
            || m.Value<u64>(Add(f.name_world,Offset::CurrentLevel,"NAME_CONTEXT"),"NAME_LEVEL_RECHECK")!=level_raw)
            Fail(Code::SnapshotChanged,"NAME_CONTEXT_RECHECK","World context changed during metadata capture");
        if(!f.complete && m.Value<u64>(root_slot,"NAME_WORLD_RECHECK")!=root_raw)
            Fail(Code::SnapshotChanged,"NAME_WORLD_RECHECK","Independent World root changed during metadata capture");
        cipher.Verify();
        if(!f.complete)f.name_root_unverified=false;
        f.world_name_status=NameCaptureStatus::Succeeded;
    } catch(const Fault& e) {
        f.world_name.verified=false;f.world_name.base.clear();f.world_name.full.clear();f.world_name_issue=e.issue();
    }
    for(const auto& [stage,stat]:m.Stats()) {
        auto& target=f.read_stats[stage];target.attempts+=stat.attempts;target.failed_attempts+=stat.failed_attempts;
        target.exhausted_requests+=stat.exhausted_requests;
        if(!target.first_failed_address){target.first_failed_address=stat.first_failed_address;target.first_requested_bytes=stat.first_requested_bytes;}
    }
    f.backend_calls+=m.Calls();f.failed_attempts+=m.FailedAttempts();f.finished=Clock::now();
}
}

namespace monitor {
std::string MapFrameReport(const Snapshot& f) {
    std::ostringstream o;
    o<<"frame="<<f.sequence<<" complete="<<f.complete<<" world="<<Hex(f.world)
     <<" root_unverified="<<f.world_root_unverified<<" name_world="<<Hex(f.name_world)
     <<" name_root_unverified="<<f.name_root_unverified<<" name_status="
     <<(f.world_name_status==NameCaptureStatus::NotAttempted?"NOT_ATTEMPTED":
        f.world_name_status==NameCaptureStatus::Succeeded?"SUCCEEDED":"FAILED")
     <<" name_verified="<<f.world_name.verified
     <<" name="<<std::quoted(f.world_name.full)<<" index=";
    if(f.world_name.index)o<<*f.world_name.index;else o<<"unknown";
    o<<" name_issue="<<std::quoted(Describe(f.world_name_issue))<<" origin=";
    if(f.origin)o<<f.origin->x<<','<<f.origin->y<<','<<f.origin->z;else o<<"unknown";
    o<<" origin_issue="<<std::quoted(Describe(f.origin_issue))
     <<" scene_origin_issue="<<std::quoted(Describe(f.scene_origin_issue));
    std::size_t attempts=0,failed=0;
    for(const char* stage:{"NAME_WORLD_STATE_READ","NAME_WORLD_RECHECK"}) {
        const auto it=f.read_stats.find(stage);
        if(it!=f.read_stats.end()){attempts+=it->second.attempts;failed+=it->second.failed_attempts;}
    }
    o<<" name_root_read_attempts="<<attempts<<" name_root_failed_attempts="<<failed;
    return o.str();
}
}
