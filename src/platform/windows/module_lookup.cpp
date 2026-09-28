#include "platform/windows/module_lookup.hpp"
#include <unordered_set>

namespace monitor {
namespace {
void Pointer(u64 value,const char* stage) {
    if(!UserAddress(value) || (value&7))Fail(Code::InvalidAddress,stage,"Invalid loader pointer",value);
}
unsigned Lower(unsigned c){return c>='A' && c<='Z'?c+('a'-'A'):c;}
bool SameNameHeader(const UNICODE_STRING_RAW& a,const UNICODE_STRING_RAW& b) {
    return a.Length==b.Length && a.MaximumLength==b.MaximumLength && a.Buffer==b.Buffer;
}
void VerifyLinks(Reader& memory,const ModuleReference& module) {
    if(memory.Value<u64>(Add(module.peb,Offsets::Ldr,"MODULE_PEB_LDR_RECHECK"),"MODULE_PEB_LDR_RECHECK")!=module.ldr)
        Fail(Code::SnapshotChanged,"MODULE_PEB_LDR_RECHECK","PEB loader pointer changed",module.peb+Offsets::Ldr);
    for(const auto& [at,value]:module.links)
        if(memory.Value<u64>(at,"MODULE_LINK_RECHECK")!=value)
            Fail(Code::SnapshotChanged,"MODULE_LINK_RECHECK","Traversed loader link changed",at);
}
}
void ModuleReference::Verify(Reader& memory) const {
    VerifyLinks(memory,*this);
    const auto after=memory.Value<UNICODE_STRING_RAW>(Add(entry,Offsets::BaseDllName,"MODULE_NAME_HEADER_RECHECK"),"MODULE_NAME_HEADER_RECHECK");
    if(!SameNameHeader(after,descriptor))
        Fail(Code::SnapshotChanged,"MODULE_NAME_HEADER_RECHECK","Module name descriptor changed",entry+Offsets::BaseDllName);
    std::vector<u16> text(name.size());
    memory.Bytes(descriptor.Buffer,text.data(),descriptor.Length,"MODULE_NAME_TEXT_RECHECK");
    if(text!=name)Fail(Code::SnapshotChanged,"MODULE_NAME_TEXT_RECHECK","Module name text changed",descriptor.Buffer);
    if(memory.Value<u64>(Add(entry,Offsets::DllBase,"MODULE_BASE_RECHECK"),"MODULE_BASE_RECHECK")!=base)
        Fail(Code::SnapshotChanged,"MODULE_BASE_RECHECK","Module base changed",entry+Offsets::DllBase);
}
ModuleReference FindModuleChecked(Reader& memory,u64 peb,std::string_view wanted) {
    memory.Check("MODULE_LOOKUP");Pointer(peb,"MODULE_PEB_ADDRESS");
    if(wanted.empty() || wanted.size()>128)
        Fail(Code::InvalidLayout,"MODULE_WANTED_NAME","Invalid requested module name");
    for(unsigned char c:wanted)if(!c || c>127)
        Fail(Code::InvalidLayout,"MODULE_WANTED_NAME","Requested module name must be complete ASCII");
    ModuleReference result;result.peb=peb;
    result.ldr=memory.Value<u64>(Add(peb,Offsets::Ldr,"MODULE_PEB_LDR_READ"),"MODULE_PEB_LDR_READ");
    if(!result.ldr)Fail(Code::NullObject,"MODULE_PEB_LDR_NULL","PEB loader pointer is null",peb+Offsets::Ldr);
    Pointer(result.ldr,"MODULE_LDR_ADDRESS");
    const u64 head=Add(result.ldr,Offsets::InLoadOrderLinks,"MODULE_LIST_ADDRESS");
    u64 link=head;
    std::unordered_set<u64> visited;
    for(unsigned count=0;count<=200;++count) {
        memory.Check("MODULE_LOOKUP");
        const u64 next=memory.Value<u64>(link,link==head?"MODULE_LIST_HEAD_READ":"MODULE_NEXT_READ");
        result.links.emplace_back(link,next);
        if(next==head) {
            VerifyLinks(memory,result);
            Fail(Code::NoReference,count?"MODULE_NOT_FOUND":"MODULE_LIST_EMPTY",
                "Loader traversal did not contain "+std::string(wanted)+"; visited="+std::to_string(count),head);
        }
        Pointer(next,"MODULE_ENTRY_ADDRESS");
        if(!visited.insert(next).second)
            Fail(Code::InvalidLayout,"MODULE_LIST_CYCLE","Loader list contains a non-head cycle",next);
        if(count==200)Fail(Code::InvalidLayout,"MODULE_LIST_LIMIT","Loader traversal exceeded 200 entries",next);
        const u64 header_at=Add(next,Offsets::BaseDllName,"MODULE_NAME_HEADER_READ");
        const auto header=memory.Value<UNICODE_STRING_RAW>(header_at,"MODULE_NAME_HEADER_READ");
        if((header.Length&1) || header.Length>header.MaximumLength)
            Fail(Code::InvalidLayout,"MODULE_NAME_HEADER_VALIDATE","Invalid UTF-16 length/capacity",header_at);
        // Nonmatching lengths cannot be the target. No need to touch unrelated string pages.
        if(header.Length==wanted.size()*sizeof(u16)) {
            if(!UserRange(header.Buffer,header.Length) || (header.Buffer&1))
                Fail(Code::InvalidAddress,"MODULE_NAME_BUFFER_VALIDATE","Invalid module name buffer",header.Buffer,header.Length);
            std::vector<u16> name(header.Length/sizeof(u16));
            memory.Bytes(header.Buffer,name.data(),header.Length,"MODULE_NAME_TEXT_READ");
            bool match=true;
            for(std::size_t i=0;i<name.size();++i)
                if(name[i]>127 || Lower(name[i])!=Lower(static_cast<unsigned char>(wanted[i]))) {match=false;break;}
            if(match) {
                result.entry=next;result.descriptor=header;result.name=std::move(name);
                const u64 at=Add(next,Offsets::DllBase,"MODULE_BASE_READ");
                result.base=memory.Value<u64>(at,"MODULE_BASE_READ");
                if(!UserAddress(result.base) || (result.base&0xfff))
                    Fail(Code::InvalidAddress,"MODULE_BASE_VALIDATE","Invalid or unaligned image base",at,sizeof(u64));
                result.Verify(memory);
                return result;
            }
        }
        link=next;
    }
    Fail(Code::InternalError,"MODULE_LOOKUP","Unreachable traversal state");
}
}
