#pragma once
#include <cstdint>
#include <atomic>
#include <chrono>
#include <string>

struct UNICODE_STRING_RAW {
	unsigned short Length;
	unsigned short MaximumLength;
	uint64_t Buffer;
};

namespace Offsets {

	constexpr uint64_t UniqueProcessId = 0x1d0;
	constexpr uint64_t ActiveProcessLinks = 0x1d8;
	constexpr uint64_t DirectoryTableBase = 0x028;
	constexpr uint64_t Peb = 0x2e0;
	constexpr uint64_t OwnerProcessId = 0x2d8;

	constexpr uint64_t Ldr = 0x018;
	constexpr uint64_t InLoadOrderLinks = 0x010;
	constexpr uint64_t DllBase = 0x030; // _LDR_DATA_TABLE_ENTRY.DllBase
	constexpr uint64_t BaseDllName = 0x058; // _LDR_DATA_TABLE_ENTRY.BaseDllName


}


struct Cr3LookupDiagnostics {
    const char* stage = "CR3_NOT_STARTED";
    uint64_t target_pid = 0, caller_cr3 = 0, head = 0;
    uint64_t address = 0, requested = 0, received = 0;
    uint64_t current_entry = 0, next_entry = 0, eprocess = 0, observed_pid = 0, target_cr3 = 0;
    unsigned reads = 0, nodes = 0;
};
// caller_cr3 is the CR3 at the hypercall, not a discovered System-process CR3.
// On failure, partial fields are never accepted; diagnostics describe the last read.
uint64_t GetProcessCr3(uint64_t target_pid, uint64_t ps_active_process_head_addr,
    Cr3LookupDiagnostics* diagnostics = nullptr);
std::string DescribeCr3Lookup(const Cr3LookupDiagnostics& diagnostics);
// Quiet, bounded probe via the existing hypervisor transport. Zero means that
// complete, stable PID/DirectoryTableBase fields could not be obtained.
uint64_t ProbeProcessCr3(uint64_t target_pid, uint64_t ps_active_process_head_addr,
    const std::atomic_bool* stop, std::chrono::steady_clock::time_point deadline);

uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const char* wanted_name);
uint64_t GetModuleBase_Raw(uint64_t target_cr3, uint64_t peb_address, const wchar_t* wanted_name);
uint64_t FindPebByCr3_Raw(uint64_t target_cr3, uint64_t ps_active_process_head_addr);
