#include "arch/x64/resolver.hpp"
#include "monitor/monitor.hpp"

namespace monitor {
namespace {
constexpr u32 Ror(u32 v, unsigned n) noexcept { return (v >> n) | (v << (32 - n)); }
constexpr u32 Swap16(u32 v) noexcept { return ((v & 0xffU) << 8) | ((v >> 8) & 0xffU); }
constexpr u32 Mix16(u32 v) noexcept {
    const u32 hi = v >> 16;
    return (hi << 16) | ((v ^ hi) & 0xffffU);
}
constexpr u64 Join(u32 lo, u32 hi) noexcept { return u64(lo) | (u64(hi) << 32); }
constexpr u32 Cross(u32 v) noexcept { return (Swap16(v >> 16) << 16) | Swap16(v ^ (v >> 16)); }
struct Profile { u64 mode, slot; u32 selector; const char* label; };
Profile Spec(Cipher cipher) {
    switch (cipher) {
    case Cipher::World: return {Offset::WorldMode, Offset::WorldSlot, 0x483ECC8F, "WORLD_RESOLVE"};
    case Cipher::GameState: return {Offset::GameStateMode, Offset::GameStateSlot, 0x483ECF3D, "GAMESTATE_RESOLVE"};
    case Cipher::GameInstance: return {Offset::GameInstanceMode, Offset::GameInstanceSlot, 0x483ECF0A, "GAMEINSTANCE_RESOLVE"};
    case Cipher::CurrentLevel: return {Offset::GameInstanceMode, Offset::GameInstanceSlot, 0x483ECCA7, "CURRENT_LEVEL_RESOLVE"};
    case Cipher::RootComponent: return {Offset::GameStateMode, Offset::GameStateSlot, 0x483ECC8C, "ROOT_COMPONENT_RESOLVE"};
    case Cipher::PlayerState: return {Offset::WorldMode, Offset::WorldSlot, 0x483ECCE8, "PLAYERSTATE_RESOLVE"};
    case Cipher::LocalPlayer: return {Offset::LocalPlayerMode, Offset::LocalPlayerSlot, 0x483ECC84, "LOCALPLAYER_RESOLVE"};
    case Cipher::ControlPointer: return {Offset::GameInstanceMode, Offset::GameInstanceSlot, 0x483ECCA0, "CONTROL_POINTER_RESOLVE"};
    case Cipher::Actors: return {Offset::ActorsMode, Offset::ActorsSlot, 0x483ECC62, "ACTORS_RESOLVE"};
    case Cipher::NamesGlobal20: return {0x1177A300,0x1177A328,0x483ECC41,"NAMES_GLOBAL20"};
    case Cipher::NamesGlobal10: return {0x1177A300,0x1177A328,0x483ECC98,"NAMES_GLOBAL10"};
    case Cipher::NamesContainer: return {0x1177A300,0x1177A328,0x483ECCB3,"NAMES_CONTAINER"};
    case Cipher::NamesContainerEncode: return {0x1177A300,0x1177A320,0x483ECCDC,"NAMES_CONTAINER_ENCODE"};
    case Cipher::NamesContainerDecode: return {0x1176EE00,0x1176EE28,0x483ECCDC,"NAMES_CONTAINER_DECODE"};
    case Cipher::NamesBlocks: return {0x1176EE00,0x1176EE28,0x483ECCF8,"NAMES_BLOCKS"};
    case Cipher::NamesEntryEncode: return {0x1176EE00,0x1176EE20,0x483ECC47,"NAMES_ENTRY_ENCODE"};
    case Cipher::NamesEntryDecode: return {0x1176EE00,0x1176EE28,0x483ECC47,"NAMES_ENTRY_DECODE"};
    case Cipher::NamesHeader: return {0x1176F200,0x1176F228,0x483ECCCB,"NAMES_HEADER"};
    case Cipher::Plain: break;
    }
    Fail(Code::InvalidLayout, "RESOLVER_PROFILE", "Plain pointer has no cipher profile");
}
}

// Each nonzero-mode branch is transcribed from the corresponding field accessor.
// Arithmetic wraps independently in each 32-bit half.
u64 StaticResolve(Cipher cipher, u64 state) noexcept {
    const u32 lo = u32(state), hi = u32(state >> 32);
    switch (cipher) {
    case Cipher::World:
        return Join((lo + 0x7F5585EEU) ^ 0x303070D0U,
                    (hi + 0x6236DAC0U) ^ 0xD030D030U);
    case Cipher::GameState:
        return Join(((lo ^ 0xA7D073EBU) + 0x0ACAA2D6U) ^ 0x501AD13DU,
                    ((hi ^ 0xF44FA658U) + 0x09150996U) ^ 0x51A55032U);
    case Cipher::GameInstance:
        return Join(Ror(Ror(lo + 0x0ED003BDU, 16) + 0x1319A904U, 16) ^ 0x6949A547U,
                    Ror(Ror(hi + 0x73FFC6E8U, 8) - 0x08195071U, 8) ^ 0x17191759U);
    case Cipher::CurrentLevel: {
        const u32 a = Mix16(((lo >> 16) << 16 | ((lo ^ (lo >> 16)) & 0xffffU))
            - 0x47472738U) ^ 0xB8B8D8C8U;
        const u32 b = (Swap16(hi >> 16) << 16) | Swap16((hi & 0xffffU) ^ (hi >> 16));
        const u32 c = b + 0xB7C7B7C8U;
        const u32 d = ((Swap16(c >> 16) << 16) | Swap16((c ^ (c >> 16)) & 0xffffU)) ^ 0x48384838U;
        return Join(a, d);
    }
    case Cipher::RootComponent:
        return Join(Ror(Ror(lo + 0x33128A8FU, 24) + 0x61D1CDC0U, 16) ^ 0x9FBF4331U,
                    Ror(Ror(hi - 0x5B4C2A88U, 16) + 0x5243F449U, 8) ^ 0xE16FE12FU);
    case Cipher::PlayerState: {
        const u32 a = (Swap16(lo >> 16) << 16) | ((lo ^ (lo >> 16)) & 0xffffU);
        const u32 b = (hi & 0xffff0000U) | Swap16((hi & 0xffffU) ^ (hi >> 16));
        const u32 c = b + 0xD21CD25DU;
        const u32 d = ((Swap16(c >> 16) << 16) | Swap16((c ^ (c >> 16)) & 0xffffU)) ^ 0x2DE32DA3U;
        return Join(Mix16(a + 0x53F3A73DU) ^ 0x53F3A73DU, d);
    }
    case Cipher::LocalPlayer:
        return Join(Ror(Ror(lo, 8) + 0xC7E7CB89U, 8) ^ 0xC7E7CB89U,
                    (hi + 0x46E84629U) ^ 0xB917B9D7U);
    case Cipher::ControlPointer:
        return Join((lo - 0x44A490ABU) ^ 0xBB5B6F55U,
                    (hi + 0x3A343A75U) ^ 0xC5CBC58BU);
    case Cipher::Actors:
        return Join((lo + 0x4E6E3281U) ^ 0xB191CD7FU,
                    Ror(~Ror(hi, 24) + 0x301E30DFU, 24) ^ 0x301E30DEU);
    case Cipher::NamesGlobal20:
        return Join((lo+0x76B6DEAAU)^0x76B6DEAAU,(hi+0x756975EAU)^0x8A968A16U);
    case Cipher::NamesGlobal10: {
        const u32 a=(Swap16(lo>>16)<<16)|((lo^(lo>>16))&0xffffU);
        const u32 b=(hi&0xffff0000U)|Swap16(hi^(hi>>16));
        return Join(Mix16(a+0xE383F7ADU)^0xE383F7ADU,Cross(b+0x628C62CDU)^0x9D739D33U);
    }
    case Cipher::NamesContainer:
        return Join(Ror(Ror(lo,16)-0x038373BCU,16)^0xFC7C8C44U,
                    Ror(Ror(hi,8)-0x043C043CU,8)^0x043C043CU);
    case Cipher::NamesContainerEncode:
        return Join(Ror(Ror(lo^0x0F2FF3C1U,16)+0x7EBD81B0U,8)+0x1CED7571U,
                    Ror(Ror(hi^0x71DF719FU,24)-0x71D463D9U,16)-0x54B3D578U);
    case Cipher::NamesContainerDecode:
        return Join(Ror(Ror(lo-0x1CED7571U,24)-0x7EBD81B0U,16)^0x0F2FF3C1U,
                    Ror(Ror(hi+0x54B3D578U,16)+0x71D463D9U,8)^0x71DF719FU);
    case Cipher::NamesBlocks: {
        const u32 a=(Swap16(lo>>16)<<16)|((lo^(lo>>16))&0xffffU);
        const u32 b=(hi&0xffff0000U)|Swap16(hi^(hi>>16));
        return Join(Mix16(a+0x03A3978DU)^0x03A3978DU,Cross(b-0x7D937D53U)^0x7D937D53U);
    }
    case Cipher::NamesEntryEncode:
        return Join(Mix16(Mix16(lo^0x989838E8U)+0x6767C718U),Cross(Cross(hi^0x68186818U)-0x97E797E8U));
    case Cipher::NamesEntryDecode:
        return Join(Mix16(Mix16(lo)-0x6767C718U)^0x989838E8U,Cross(Cross(hi)+0x97E797E8U)^0x68186818U);
    case Cipher::NamesHeader:
        return Join(((lo^0xE95D03BDU)-0x7BFB0BC4U)^0x0059F781U,
                    Ror(Ror(hi^0x4E8CC6E8U,24)-0x7C447C44U^0xE98CC6E8U,24)^0x7C447C44U);
    case Cipher::Plain: return state;
    }
    return 0;
}

FrameResolver::Mode FrameResolver::Metadata(u64 mr, u64 sr) {
    const u64 at = Add(base_, mr, "RESOLVER_MODE_ADDRESS");
    const auto key = std::make_pair(at, Add(base_, sr, "RESOLVER_SLOT_ADDRESS"));
    const auto found = modes_.find(key);
    if (found != modes_.end()) return found->second;
    Mode m;
    m.value = memory_.Value<u64>(at, "RESOLVER_MODE_READ");
    m.slot = key.second;
    if (m.value == 0) {
        m.target = memory_.Value<u64>(m.slot, "RESOLVER_SLOT_READ");
        if (!UserAddress(m.target))
            Fail(Code::InvalidAddress, "RESOLVER_SLOT_READ", "Invalid dynamic target", m.target);
    }
    // A mode can own both +20 encode and +28 decode entry points.
    modes_.emplace(key, m);
    if (trace_) trace_->push_back("Resolver mode@" + Hex(at) + "=" + Hex(m.value) + " target=" + Hex(m.target));
    return m;
}
u64 FrameResolver::Transform(u64 raw, Cipher cipher) {
    const auto p = Spec(cipher);
    try {
        const auto m = Metadata(p.mode, p.slot);
        const u64 result = m.value ? StaticResolve(cipher, raw)
            : interpreter_.Execute(m.target, p.selector, raw);
        if (trace_) trace_->push_back(std::string(p.label) + " selector=" + Hex(p.selector)
            + " result=" + Hex(result));
        return result;
    } catch (const Fault& e) {
        Issue i = e.issue(); i.stage = std::string(p.label) + "/" + i.stage; throw Fault(std::move(i));
    }
}
u64 FrameResolver::World(u64 raw) { return Transform(raw, Cipher::World); }
u64 FrameResolver::GameState(u64 raw) { return Transform(raw, Cipher::GameState); }
u64 FrameResolver::Actors(u64 raw) { return Transform(raw, Cipher::Actors); }
bool FrameResolver::ObjectShape(u64 p, Issue* read_issue) {
    if (!UserAddress(p)) return false;
    try {
        const auto first = memory_.Value<u64>(p, "OBJECT_SHAPE_READ");
        return UserAddress(first); // Heuristic only; not RTTI/class confirmation.
    } catch (const Fault& e) {
        if (e.issue().code == Code::Cancelled || e.issue().code == Code::Deadline) throw;
        if (read_issue) *read_issue = e.issue();
        return false;
    }
}
u64 FrameResolver::Object(u64 raw, Cipher cipher) {
    if (cipher == Cipher::Plain && raw == 0) return 0;
    Issue issue;
    const u64 decoded = cipher == Cipher::Plain ? raw : Transform(raw, cipher);
    if (decoded == 0) return 0;
    if (!ObjectShape(decoded, &issue)) {
        std::string detail = cipher == Cipher::Plain
            ? "Plain pointer failed object heuristic" : "Resolved pointer failed object heuristic";
        if (issue) detail += "; candidate read=" + Describe(issue);
        Fail(Code::InvalidAddress, "OBJECT_SHAPE", std::move(detail), decoded);
    }
    return decoded;
}
u64 FrameResolver::Field(u64 object, u64 offset, Cipher cipher, const char* stage, u64* raw_out) {
    const u64 raw = memory_.Value<u64>(Add(object, offset, stage), stage);
    if (raw_out) *raw_out = raw;
    try { return Object(raw, cipher); }
    catch (const Fault& e) { auto i = e.issue(); i.stage = std::string(stage) + "/" + i.stage; throw Fault(std::move(i)); }
}
void FrameResolver::Verify() {
    for (const auto& p : modes_) {
        if (memory_.Value<u64>(p.first.first, "RESOLVER_METADATA_RECHECK") != p.second.value)
            Fail(Code::SnapshotChanged, "RESOLVER_METADATA_RECHECK", "Resolver mode changed", p.first.first);
        if (p.second.value == 0 && memory_.Value<u64>(p.second.slot, "RESOLVER_METADATA_RECHECK") != p.second.target)
            Fail(Code::SnapshotChanged, "RESOLVER_METADATA_RECHECK", "Resolver target changed", p.second.slot);
    }
    interpreter_.VerifyCode();
}
}
