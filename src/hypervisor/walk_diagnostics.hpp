#pragma once
#include <cstdint>

namespace hypercall_walk {
// The supported walker uses four paging levels and 48-bit canonical VAs.
constexpr bool IsCanonical48(std::uint64_t address) {
    return address <= 0x00007fffffffffffull || address >= 0xffff800000000000ull;
}
constexpr bool IsCanonicalRange48(std::uint64_t address, std::uint64_t bytes) {
    if (bytes == 0 || !IsCanonical48(address) || bytes - 1 > UINT64_MAX - address) return false;
    const auto last = address + bytes - 1;
    return IsCanonical48(last) && ((address ^ last) & (1ull << 47)) == 0;
}
inline constexpr std::uint64_t capability = 0x48565257414C4B02ull;
inline constexpr std::uint64_t request_flag = 4;
inline constexpr std::uint64_t chain_capability = 0x48565257414C4B03ull;
inline constexpr std::uint64_t chain_request_flag = 8;
enum class Outcome : std::uint64_t { Success = 1, NotPresent = 2, TableMappingFailed = 3 };
enum class Level : std::uint64_t { PT = 1, PD = 2, PDPT = 3, PML4 = 4 };
struct Evidence {
    std::uint64_t status = 0, entry = 0, entry_gpa = 0, entry_hpa = 0;
};
constexpr std::uint64_t Status(Outcome outcome, Level level, unsigned page_shift = 0) {
    return (2ull << 24) | (std::uint64_t(page_shift) << 16)
        | (static_cast<std::uint64_t>(level) << 8) | static_cast<std::uint64_t>(outcome);
}
constexpr bool Valid(std::uint64_t status) {
    const auto outcome = status & 0xff;
    const auto level = (status >> 8) & 0xff;
    return (status >> 24) == 2 && outcome >= 1 && outcome <= 3 && level >= 1 && level <= 4;
}
static_assert(sizeof(Evidence) == 32);

// Fixed-size v3 output. Entries are ordered PML4 -> terminal; an unmapped
// table has an explicit TableMappingFailed record, not an invented zero entry.
struct Chain {
    std::uint64_t marker = 0, va = 0, cr3 = 0, physical = 0, remaining = 0, count = 0;
    Evidence entries[4]{};
};
static_assert(sizeof(Chain) == 176);
// Validate the recorded traversal's structure, not an atomic memory snapshot.
constexpr bool ValidChain(const Chain& chain) {
    if (chain.marker != chain_capability || chain.count < 1 || chain.count > 4 || !IsCanonical48(chain.va)) return false;
    constexpr std::uint64_t frame_mask = 0x0000fffffffff000ull;
    auto table_gpa = chain.cr3 & frame_mask;
    for (unsigned i = 0; i < chain.count; ++i) {
        const auto& e = chain.entries[i];
        if (!Valid(e.status) || ((e.status >> 8) & 0xff) != 4 - i) return false;
        const auto index = (chain.va >> (12 + (3 - i) * 9)) & 0x1ff;
        if (e.entry_gpa != table_gpa + index * sizeof(std::uint64_t)) return false;
        // SLAT may change the physical frame, but preserves the 4K page offset.
        // An unmapped table has no HPA and is validated as a failure below.
        if ((e.status & 0xff) != static_cast<std::uint64_t>(Outcome::TableMappingFailed)
            && (e.entry_gpa & 0xfff) != (e.entry_hpa & 0xfff)) return false;
        if (i + 1 < chain.count && ((e.status & 0xff) != 1 || (e.entry & 1) == 0 || ((e.status >> 16) & 0xff) != 0)) return false;
        table_gpa = e.entry & frame_mask;
    }
    const auto& terminal = chain.entries[chain.count - 1];
    const auto outcome = terminal.status & 0xff;
    const auto shift = (terminal.status >> 16) & 0xff;
    if (outcome == 1) {
        const auto level = (terminal.status >> 8) & 0xff;
        if (level > 3 || shift != 12 + (level - 1) * 9 || !(terminal.entry & 1)
            || (level > 1 && !(terminal.entry & 0x80))) return false;
        const auto offset_mask = (1ull << shift) - 1;
        return chain.remaining == (1ull << shift) - (chain.va & offset_mask)
            && chain.physical == (terminal.entry & 0x0000fffffffff000ull & ~offset_mask) + (chain.va & offset_mask);
    }
    if (shift != 0 || chain.physical != 0 || chain.remaining != 0) return false;
    return outcome == 2 ? !(terminal.entry & 1) : terminal.entry == 0 && terminal.entry_hpa == 0;
}

struct Difference { std::uint64_t raw_mask = 0, mapping_mask = 0; };
// Diagnostic comparison only. Matching observations cannot exclude ABA changes
// between them and do not make a target-process read atomic.
constexpr Difference Compare(const Chain& before, const Chain& after) {
    Difference result{};
    for (unsigned i = 0; i < 4; ++i) {
        const auto bit = 1ull << (3 - i); // PML4=8, PDPT=4, PD=2, PT=1
        if (i >= before.count && i >= after.count) continue;
        if (i >= before.count || i >= after.count) { result.mapping_mask |= bit; continue; }
        const auto& a = before.entries[i]; const auto& b = after.entries[i];
        if (a.entry != b.entry) result.raw_mask |= bit;
        const auto shift = (a.status >> 16) & 0xff;
        const auto offset_mask = (shift == 12 || shift == 21 || shift == 30) ? (1ull << shift) - 1 : 0xfffull;
        // PAT is bit 7 at PT and bit 12 at large leaves; neither changes the PFN.
        const auto mapping_bits = (0x0000fffffffff000ull & ~offset_mask) | 1ull | ((i == 1 || i == 2) ? 0x80ull : 0ull);
        if (a.status != b.status || a.entry_gpa != b.entry_gpa || a.entry_hpa != b.entry_hpa
            || ((a.entry ^ b.entry) & mapping_bits)) result.mapping_mask |= bit;
    }
    return result;
}
}
