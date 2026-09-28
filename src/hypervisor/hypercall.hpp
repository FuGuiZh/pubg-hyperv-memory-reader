#pragma once
#include <cstdint>
#include <cstddef>
#include "hypervisor/walk_diagnostics.hpp"

// Only the transport operations used by this reader are exposed.
namespace hypercall {
// Optional register-only telemetry. The first field always keeps the original return value.
struct Result {
    std::uint64_t value = 0, guest_cr3 = 0, saved_slat = 0, active_slat = 0, cpu = 0, marker = 0;
    hypercall_walk::Evidence walk{};
};
static_assert(sizeof(Result) == 80 && offsetof(Result, walk) == 48, "Diagnostic assembly register layout changed");
inline constexpr std::uint64_t diagnostic_marker = 0x4856524449414701ull;
struct Capabilities { unsigned version = 0; std::uint64_t build_stamp = 0; };
Capabilities diagnostic_capabilities();
bool diagnostics_supported();
Result translate_diagnostic(std::uint64_t address, std::uint64_t cr3, bool walk = false);
struct ChainResult {
    Result result{};
    hypercall_walk::Chain chain{};
    std::uint64_t bytes_written = 0;
    bool valid = false;
};
ChainResult translate_chain(std::uint64_t address, std::uint64_t cr3);
Result read_physical_diagnostic(void* output, std::uint64_t address, std::uint64_t size);
std::uint64_t read_guest_physical_memory(void* output, std::uint64_t address, std::uint64_t size);
std::uint64_t read_guest_virtual_memory(void* output, std::uint64_t address, std::uint64_t cr3, std::uint64_t size);
std::uint64_t translate_guest_virtual_address(std::uint64_t address, std::uint64_t cr3);
std::uint64_t read_guest_cr3();
}
