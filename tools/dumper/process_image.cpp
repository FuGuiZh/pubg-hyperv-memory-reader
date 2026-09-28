#include "process_image.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <stdexcept>
#include <unordered_set>
#include <limits>

namespace dumper {
namespace {
bool KernelPointer(std::uint64_t p) { return p >= 0xFFFF800000000000ULL && !(p & 7); }
std::uint64_t Add(std::uint64_t base, std::uint64_t offset) {
    if (offset > UINT64_MAX - base) throw std::runtime_error("Kernel metadata address overflow.");
    return base + offset;
}
template<class T> T Read(const ReadMemory& memory, std::uint64_t address) {
    T value{};
    if (!memory(address, &value, sizeof(value)))
        throw IncompleteKernelMetadataError{};
    return value;
}
ProcessImage ReadImage(const ReadMemory& kernel, std::uint64_t process,
    const monitor::ProcessImageLayout& layout) {
    return {process, Read<std::uint64_t>(kernel, Add(process, layout.pid)),
        Read<std::uint64_t>(kernel, Add(process, layout.cr3)),
        Read<std::uint64_t>(kernel, Add(process, layout.image_base))};
}
}
void VerifyProcessImage(const ReadMemory& kernel, const ProcessImage& expected,
    const monitor::ProcessImageLayout& layout) {
    if (ReadImage(kernel, expected.process, layout) != expected)
        throw std::runtime_error("Target PID, address space or main image changed during dump.");
}
static ProcessImage FindProcessImageOnce(const ReadMemory& kernel, std::uint64_t head,
    std::uint32_t pid, const monitor::ProcessImageLayout& layout) {
    if (!pid || !KernelPointer(head)) throw std::runtime_error("Invalid process list/PID.");
    std::unordered_set<std::uint64_t> seen;
    auto node = Read<std::uint64_t>(kernel, head);
    for (unsigned count = 0; node != head && count < 50000; ++count) {
        if (!KernelPointer(node) || node < layout.links || !seen.insert(node).second)
            throw std::runtime_error("Invalid or cyclic kernel process list.");
        const auto process = node - layout.links;
        std::uint64_t observed_pid = 0;
        std::uint64_t next = 0;
        bool combined = false;
        if (layout.links == static_cast<std::uint64_t>(layout.pid) + sizeof(std::uint64_t)) {
            std::uint64_t fields[2]{};
            combined = static_cast<bool>(kernel(Add(process, layout.pid), fields, sizeof(fields)));
            if (combined) {
                observed_pid = fields[0];
                next = fields[1];
            }
        }
        if (!combined) observed_pid = Read<std::uint64_t>(kernel, Add(process, layout.pid));
        if (observed_pid == pid) {
            const auto image = ReadImage(kernel, process, layout);
            if (image.pid != pid || !(image.cr3 & 0x000FFFFFFFFFF000ULL)
                || image.base < 0x10000 || image.base >= 0x0000800000000000ULL || (image.base & 0xFFF))
                throw std::runtime_error("Target main image/address space unavailable or not initialized.");
            VerifyProcessImage(kernel, image, layout);
            return image;
        }
        node = combined ? next : Read<std::uint64_t>(kernel, node);
    }
    throw std::runtime_error("Target PID not found in bounded kernel process traversal.");
}
ProcessImage FindProcessImage(const ReadMemory& kernel, std::uint64_t head,
    std::uint32_t pid, const monitor::ProcessImageLayout& layout) {
    for (unsigned attempt = 0; attempt < 5; ++attempt) {
        try { return FindProcessImageOnce(kernel, head, pid, layout); }
        catch (const IncompleteKernelMetadataError&) {
            if (attempt == 4) throw;
            Sleep(2); // Retry a fresh list traversal after a transient metadata read.
        }
    }
    throw IncompleteKernelMetadataError{};
}
void VerifyKernelImage(const ReadMemory& kernel, std::uint64_t base,
    const monitor::ProcessImageLayout& layout) {
    if (!KernelPointer(base)) throw std::runtime_error("Invalid kernel image address.");
    const auto dos = Read<IMAGE_DOS_HEADER>(kernel, base);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000)
        throw std::runtime_error("Invalid live kernel DOS header.");
    const auto nt = Read<IMAGE_NT_HEADERS64>(kernel, Add(base, dos.e_lfanew));
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
        || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
        || nt.FileHeader.TimeDateStamp != layout.kernel_timestamp
        || nt.OptionalHeader.SizeOfImage != layout.kernel_image_size)
        throw std::runtime_error("Running kernel differs from symbol image; refusing process offsets.");
}
}
