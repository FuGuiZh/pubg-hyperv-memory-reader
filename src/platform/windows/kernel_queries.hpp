#pragma once
#include <cstdint>

namespace monitor {
// System module information and kernel symbols; no target process handle.
// DbgHelp is process-global: call these from a single thread per executable.
std::uint64_t QueryKernelBase();
std::uint64_t QueryProcessHeadOffset();
// Resolved from the matching ntoskrnl PDB; never guessed from a Windows version.
struct ProcessImageLayout {
    std::uint64_t head_rva = 0;
    std::uint32_t pid = 0, links = 0, cr3 = 0, image_base = 0;
    std::uint32_t kernel_timestamp = 0, kernel_image_size = 0;
};
ProcessImageLayout QueryProcessImageLayout();
}
