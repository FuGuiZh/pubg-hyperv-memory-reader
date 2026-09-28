#include "arch/x64/interpreter.hpp"
#include "monitor/monitor.hpp"
#include <iomanip>
#include <sstream>

// ============================================================================
// INTERPRETER implementation
// ============================================================================
#include <limits>

namespace monitor {
namespace {
constexpr int AX=0, CX=1, DX=2;
u64 SX32(u32 x) { return (x & 0x80000000U) ? (0xFFFFFFFF00000000ULL | x) : x; }
u64 SX8(u8 x) { return (x & 0x80U) ? (0xFFFFFFFFFFFFFF00ULL | x) : x; }
u64 Mask(u64 x, bool wide) { return wide ? x : u64(u32(x)); }
u64 Rotate(u64 x, unsigned n, bool wide, bool right) {
    const unsigned bits = wide ? 64U : 32U;
    n &= bits - 1;
    x = Mask(x, wide);
    if (!n) return x;
    return Mask(right ? ((x >> n) | (x << (bits-n))) : ((x << n) | (x >> (bits-n))), wide);
}
u64 Shift(u64 x, unsigned n, bool wide, int operation) {
    const unsigned bits = wide ? 64U : 32U;
    n &= bits - 1;
    x = Mask(x, wide);
    if (!n) return x;
    if (operation == 4) return Mask(x << n, wide);
    u64 v = x >> n;
    if (operation == 7 && ((x >> (bits-1)) & 1))
        v |= ((std::numeric_limits<u64>::max)() << (bits-n));
    return Mask(v, wide);
}
// Byte Group-2 operations: destination width stays 8 even with REX.W.
// Carry-dependent operations (/2, /3) and the undocumented /6 alias are rejected.
u8 ByteRotateOrShift(u8 input, unsigned count, int operation) {
    count &= 31U;
    if (operation == 0 || operation == 1) {
        count %= 8U;
        if (!count) return input;
        const unsigned v = input;
        return static_cast<u8>(operation == 0
            ? ((v << count) | (v >> (8U - count)))
            : ((v >> count) | (v << (8U - count))));
    }
    if (!count) return input;
    if (count >= 8U) return (operation == 7 && (input & 0x80U)) ? u8(0xFF) : u8(0);
    if (operation == 4) return static_cast<u8>(unsigned(input) << count);
    unsigned result = unsigned(input) >> count;
    if (operation == 7 && (input & 0x80U)) result |= 0xFFU << (8U - count);
    return static_cast<u8>(result);
}
struct CPU {
    std::array<u64,16> r{};
    std::array<bool,16> valid{};
    u64 entry = 0, pc = 0;
    u64 Get(int i, bool wide=true) const {
        if (!valid[static_cast<std::size_t>(i)])
            Fail(Code::UnknownRegister,"RUNTIME_INPUT",
                "Stub reads an unprovided register R"+std::to_string(i)
                +" from entry="+Hex(entry), pc);
        return Mask(r[static_cast<std::size_t>(i)],wide);
    }
    void Set(int i,u64 v,bool wide=true) {
        r[static_cast<std::size_t>(i)] = Mask(v,wide);
        valid[static_cast<std::size_t>(i)] = true;
    }
};
struct Operand {
    bool reg = false, rip = false;
    int id = 0, regfield = 0, group = 0;
    int base = -1, index = -1;
    unsigned scale = 1;
    u64 displacement = 0;
    u64 Address(const CPU& cpu,u64 next) const {
        u64 v = displacement;
        if (rip) v += next;
        if (base >= 0) v += cpu.Get(base);
        if (index >= 0) v += cpu.Get(index) * scale;
        return v;
    }
};
}
u8 Interpreter::Byte(u64 address) {
    memory_.Check("RUNTIME_CODE");
    const auto it=code_.find(address);
    if (it!=code_.end()) return it->second;
    if (code_.size()>=8192) Fail(Code::InstructionLimit,"RUNTIME_CODE","Capture code budget exceeded",address);
    const u8 b=memory_.Value<u8>(address,"RUNTIME_CODE_READ");
    code_.emplace(address,b);
    return b;
}
void Interpreter::VerifyCode() {
    for (const auto& p:code_) {
        if (memory_.Value<u8>(p.first,"RUNTIME_CODE_RECHECK")!=p.second)
            Fail(Code::CodeChanged,"RUNTIME_CODE_RECHECK","Code bytes changed during acquisition",p.first,1);
    }
}
u64 Interpreter::Execute(u64 entry,u32 selector,u64 state) {
    if (!UserAddress(entry)) Fail(Code::InvalidAddress,"RUNTIME_ENTRY","Invalid entry",entry);
    CPU cpu;
    cpu.entry = entry;
    cpu.Set(AX,entry); // Observed call rax sites leave entry in RAX at function entry.
    cpu.Set(CX,selector);
    cpu.Set(DX,state);
    u64 pc=entry;
    for (std::size_t step=0;step<256;++step) {
        cpu.pc = pc;
        memory_.Check("RUNTIME_EXECUTE");
        if (!UserAddress(pc) || (pc>entry ? pc-entry : entry-pc)>65536)
            Fail(Code::InvalidAddress,"RUNTIME_PC","Stub escaped the bounded code window",pc);
        std::size_t length=0;
        auto take=[&]() -> u8 {
            if (length>=15) Fail(Code::InvalidLayout,"RUNTIME_DECODE","Instruction exceeds 15 bytes",pc);
            return Byte(Add(pc,static_cast<u64>(length++),"RUNTIME_PC"));
        };
        auto imm32=[&]() -> u32 { u32 x=0; for (unsigned i=0;i<4;++i) x|=u32(take())<<(8*i); return x; };
        u8 op=take(), rex=0;
        // Only the exact known CET entry marker is accepted among REP prefixes.
        if (op==0xF3) {
            if (take()==0x0F && take()==0x1E && take()==0xFA) { pc=Add(pc,length,"RUNTIME_PC"); continue; }
            Fail(Code::UnsupportedPrefix,"RUNTIME_PREFIX","Unsupported F3-prefixed instruction",pc);
        }
        if (op==0x66 || op==0x67 || op==0xF2 || op==0xF0 || op==0x64 || op==0x65
            || op==0x2E || op==0x36 || op==0x3E || op==0x26)
            Fail(Code::UnsupportedPrefix,"RUNTIME_PREFIX","Prefix changes semantics; not ignored",pc);
        if (op>=0x40 && op<=0x4F) { rex=op; op=take(); }
        const bool wide=(rex&8)!=0;
        auto next=[&]() { return Add(pc,length,"RUNTIME_PC"); };
        auto decode=[&]() -> Operand {
            Operand a;
            const u8 b=take();
            const int mod=b>>6, reg=(b>>3)&7, rm=b&7;
            a.group=reg; a.regfield=reg+((rex&4)?8:0);
            if (mod==3) { a.reg=true; a.id=rm+((rex&1)?8:0); return a; }
            if (mod==0 && rm==5) { a.rip=true; a.displacement=SX32(imm32()); return a; }
            if (rm==4) {
                const u8 s=take();
                const int ix=(s>>3)&7, base=s&7;
                a.scale=1U<<(s>>6);
                if (ix!=4 || (rex&2)) a.index=ix+((rex&2)?8:0);
                if (mod==0 && base==5) a.displacement=SX32(imm32());
                else a.base=base+((rex&1)?8:0);
            } else a.base=rm+((rex&1)?8:0);
            if (mod==1) a.displacement+=SX8(take());
            else if (mod==2) a.displacement+=SX32(imm32());
            return a;
        };
        auto get=[&](const Operand& a,bool w) -> u64 {
            if (a.reg) return cpu.Get(a.id,w);
            const auto address=a.Address(cpu,next());
            return w ? memory_.Value<u64>(address,"RUNTIME_DATA_READ")
                     : u64(memory_.Value<u32>(address,"RUNTIME_DATA_READ"));
        };
        auto requireRegisterDestination=[&](const Operand& a) {
            if (!a.reg) Fail(Code::UnsupportedInstruction,"RUNTIME_WRITE","Target-memory writes are not supported",pc);
        };
        auto put=[&](const Operand& a,u64 v,bool w) {
            requireRegisterDestination(a);
            cpu.Set(a.id,v,w);
        };
        auto unsupported=[&](const char* reason="Unsupported opcode/form") {
            std::ostringstream message;
            message << reason << " opcode=" << Hex(op) << " entry=" << Hex(entry)
                    << " pc=" << Hex(pc) << " step=" << (step+1);
            // Preserve the bytes actually consumed from this entry. No invented zero-fill.
            message << " cached_entry_prefix=";
            for (u64 i=0; i<96; ++i) {
                const auto it=code_.find(Add(entry,i,"RUNTIME_DIAGNOSTIC"));
                if (it==code_.end()) break;
                message << std::hex << std::uppercase << std::setw(2)
                        << std::setfill('0') << unsigned(it->second) << ' ';
            }
            // Best effort only: unavailable lookahead must not replace the original error.
            // The cached prefix and lookahead are explicitly not an atomic code snapshot.
            message << " fault_window=";
            for (u64 i=0; i<15; ++i) {
                u64 at=0;
                if (!TryAdd(pc,i,at) || !UserAddress(at)) { message << "<range-end>"; break; }
                try {
                    const auto found=code_.find(at);
                    const u8 b=found!=code_.end() ? found->second
                        : memory_.Value<u8>(at,"RUNTIME_DIAGNOSTIC_READ");
                    message << std::hex << std::uppercase << std::setw(2)
                            << std::setfill('0') << unsigned(b) << ' ';
                } catch (const Fault&) { message << "<unavailable>"; break; }
            }
            Fail(Code::UnsupportedInstruction,"RUNTIME_DECODE",message.str(),pc);
        };
        if (op==0xC3) { steps_=step+1; return cpu.Get(AX); }
        if (op==0xC2) { take(); take(); steps_=step+1; return cpu.Get(AX); }
        if (op==0x90) { if (rex) unsupported(); pc=next(); continue; }
        if (op>=0xB8 && op<=0xBF) {
            const int reg=(op-0xB8)+((rex&1)?8:0);
            u64 x=imm32(); if (wide) x|=u64(imm32())<<32;
            cpu.Set(reg,x,wide); pc=next(); continue;
        }
        if (op==0x8D || op==0x8B || op==0x89 || op==0xC7) {
            const auto a=decode();
            if (op==0x89) requireRegisterDestination(a);
            if (op==0xC7) {
                if (a.group!=0) unsupported();
                requireRegisterDestination(a);
            }
            if (op==0x8D) {
                if (a.reg) unsupported();
                cpu.Set(a.regfield,a.Address(cpu,next()),wide);
            } else if (op==0x8B) cpu.Set(a.regfield,get(a,wide),wide);
            else if (op==0x89) put(a,cpu.Get(a.regfield,wide),wide);
            else { const u32 v=imm32(); put(a,wide?SX32(v):u64(v),wide); }
            pc=next(); continue;
        }
        if (op==0x01 || op==0x03 || op==0x29 || op==0x2B || op==0x31 || op==0x33) {
            const auto a=decode();
            const bool to_reg=(op==0x03 || op==0x2B || op==0x33);
            if (!to_reg) requireRegisterDestination(a);
            // XOR same register zeroes it without depending on the old value.
            if ((op==0x31 || op==0x33) && a.reg && a.id==a.regfield) {
                cpu.Set(a.id,0,wide); pc=next(); continue;
            }
            const u64 left=to_reg?cpu.Get(a.regfield,wide):get(a,wide);
            const u64 right=to_reg?get(a,wide):cpu.Get(a.regfield,wide);
            const u64 result=(op==1 || op==3)?left+right:
                ((op==0x29 || op==0x2B)?left-right:left^right);
            if(to_reg) cpu.Set(a.regfield,result,wide); else put(a,result,wide);
            pc=next(); continue;
        }
        if (op==0x81 || op==0x83) {
            const auto a=decode();
            if(a.group!=0 && a.group!=5 && a.group!=6) unsupported();
            requireRegisterDestination(a);
            const u64 v=(op==0x81)?SX32(imm32()):SX8(take());
            const u64 left=get(a,wide);
            put(a,a.group==0?left+v:(a.group==5?left-v:left^v),wide);
            pc=next(); continue;
        }
        if (op==0x05 || op==0x2D || op==0x35) {
            const u64 v=SX32(imm32()), left=cpu.Get(AX,wide);
            cpu.Set(AX,op==5?left+v:(op==0x2D?left-v:left^v),wide); pc=next(); continue;
        }
        // C0/D0/D2: byte rotate/shift. Unlike a 32-bit write, byte writes preserve
        // all other bits. Without ANY REX prefix, register codes 4..7 mean AH..BH;
        // with REX they mean SPL/BPL/SIL/DIL (or R8B..R15B via REX.B).
        if (op==0xC0 || op==0xD0 || op==0xD2) {
            const auto a=decode();
            if (a.group!=0 && a.group!=1 && a.group!=4 && a.group!=5 && a.group!=7)
                unsupported("Byte group requires unmodelled carry or unsupported suboperation");
            requireRegisterDestination(a);
            const unsigned count=op==0xC0 ? unsigned(take())
                : (op==0xD0 ? 1U : unsigned(cpu.Get(CX)&255U));
            int reg=a.id;
            unsigned shift=0;
            if (!rex && reg>=4 && reg<=7) { reg-=4; shift=8; }
            // Conservatively require the full source register to be known; never invent
            // the untouched upper bits of a register that has not been supplied.
            const u64 original=cpu.Get(reg);
            const u8 value=static_cast<u8>(original >> shift);
            const u64 changed=ByteRotateOrShift(value,count,a.group);
            const u64 mask=u64(0xFF) << shift;
            cpu.Set(reg,(original & ~mask) | (changed << shift));
            pc=next(); continue;
        }
        if (op==0xC1 || op==0xD1 || op==0xD3) {
            const auto a=decode();
            if(a.group!=0 && a.group!=1 && a.group!=4 && a.group!=5 && a.group!=7) unsupported();
            requireRegisterDestination(a);
            const unsigned count=op==0xC1?unsigned(take()):(op==0xD1?1U:unsigned(cpu.Get(CX)&255));
            const u64 v=get(a,wide);
            put(a,a.group<=1?Rotate(v,count,wide,a.group==1):Shift(v,count,wide,a.group),wide);
            pc=next(); continue;
        }
        if (op==0x69 || op==0x6B) {
            const auto a=decode();
            const u64 v=op==0x69?SX32(imm32()):SX8(take());
            // RIP address uses end of the ENTIRE instruction, including its immediate.
            cpu.Set(a.regfield,get(a,wide)*v,wide); pc=next(); continue;
        }
        if (op==0xF7) {
            const auto a=decode(); if (a.group!=2 && a.group!=3) unsupported();
            requireRegisterDestination(a);
            const u64 v=get(a,wide); put(a,a.group==2?~v:u64(0)-v,wide); pc=next(); continue;
        }
        if (op==0x0F) {
            const u8 second=take();
            if(second==0xAF) {
                const auto a=decode(); cpu.Set(a.regfield,cpu.Get(a.regfield,wide)*get(a,wide),wide);
            } else if(second>=0xC8 && second<=0xCF) {
                const int r=second-0xC8+((rex&1)?8:0);
                u64 v=cpu.Get(r,wide),out=0;
                for(unsigned i=0;i<(wide?8U:4U);++i) { out=(out<<8)|(v&255); v>>=8; }
                cpu.Set(r,out,wide);
            } else if(second==0x1F) { const auto a=decode(); if(a.group!=0) unsupported(); }
            else unsupported();
            pc=next(); continue;
        }
        if(op==0xE9 || op==0xEB) {
            const u64 d=op==0xE9?SX32(imm32()):SX8(take()); pc=next()+d; continue;
        }
        if(op==0xFF) {
            const auto a=decode(); if(a.group!=4) unsupported(); pc=get(a,true); continue;
        }
        unsupported();
    }
    Fail(Code::InstructionLimit,"RUNTIME_EXECUTE","No RET within 256 instructions",entry);
}
}
