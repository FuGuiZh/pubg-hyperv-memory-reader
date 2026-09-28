#pragma once
#include "pe_dump.hpp"
#include "../../src/platform/windows/kernel_queries.hpp"
#include <stdexcept>

namespace dumper {
struct IncompleteKernelMetadataError : std::runtime_error {
    IncompleteKernelMetadataError()
        : std::runtime_error("Incomplete kernel process/image metadata read.") {}
};
struct ProcessImage {
    std::uint64_t process = 0, pid = 0, cr3 = 0, base = 0;
    bool operator==(const ProcessImage&) const = default;
};
// Reads kernel metadata only. The callback supplies cancellation/deadline checks.
ProcessImage FindProcessImage(const ReadMemory& kernel, std::uint64_t head,
    std::uint32_t pid, const monitor::ProcessImageLayout& layout);
void VerifyProcessImage(const ReadMemory& kernel, const ProcessImage& expected,
    const monitor::ProcessImageLayout& layout);
void VerifyKernelImage(const ReadMemory& kernel, std::uint64_t base,
    const monitor::ProcessImageLayout& layout);
}
