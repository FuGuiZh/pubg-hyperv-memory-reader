// Migrated from the user's Hyper_rw/dump.cpp. See docs/dumper.md for provenance.
#include "pe_dump.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <new>
#include <vector>
namespace dumper {
static std::string PathText(const std::filesystem::path& path) {
    const auto text = path.u8string();
    return std::string(text.begin(), text.end());
}
static bool CheckedAddU64(uint64_t a, uint64_t b, uint64_t &result) {
    if (a > std::numeric_limits<uint64_t>::max() - b) {
        return false;
    }
    result = a + b;
    return true;
}
static bool AlignUpU64(uint64_t value, uint64_t alignment, uint64_t &result) {
    if (alignment == 0) {
        return false;
    }
    // alignment 必须是 2 的幂
    if ((alignment & (alignment - 1)) != 0) {
        return false;
    }
    const uint64_t mask = alignment - 1;
    if (value > std::numeric_limits<uint64_t>::max() - mask) {
        return false;
    }
    result = (value + mask) & ~mask;
    return true;
}
// -----------------------------------------------------------------------------
// 内存读取统计
// -----------------------------------------------------------------------------
constexpr size_t MAX_FAILURE_SAMPLES = 3;
struct MemoryReadStats {
    uint64_t requested = 0;
    uint64_t copied = 0;
    uint64_t failed = 0;
    bool target_exited = false;
    std::array<FailureSample, MAX_FAILURE_SAMPLES> failure_samples{};
    size_t failure_sample_count = 0;
};
static const char* FailureKindName(ReadFailureKind kind) {
    switch (kind) {
    case ReadFailureKind::InvalidRange: return "InvalidRange";
    case ReadFailureKind::TranslationZero: return "TranslationZero";
    case ReadFailureKind::CopyShort: return "CopyShort";
    case ReadFailureKind::CopyOversized: return "CopyOversized";
    case ReadFailureKind::MappingChanged: return "MappingChanged";
    case ReadFailureKind::ChainUnavailable: return "ChainUnavailable";
    case ReadFailureKind::None: return "None";
    default: return "Unknown";
    }
}
static void RecordFailure(MemoryReadStats& stats, uint64_t address, ReadFailureKind kind) {
    const auto page = address & ~0xFFFULL;
    for (size_t i = 0; i < stats.failure_sample_count; ++i)
        if ((stats.failure_samples[i].address & ~0xFFFULL) == page) return;
    if (stats.failure_sample_count < stats.failure_samples.size())
        stats.failure_samples[stats.failure_sample_count++] = {address, kind};
}
// -----------------------------------------------------------------------------
// 单值读取
// -----------------------------------------------------------------------------
template <typename T>
static ReadResult TryReadScalar(const ReadMemory &memory, uint64_t address, uint8_t *destination) {
    T value{};
    const auto result = memory(address, &value, sizeof(value));
    if (result) memcpy(destination, &value, sizeof(T));
    return result;
}
// -----------------------------------------------------------------------------
// 大块内存读取
//
// 特点：
// 1. 先按页面内的大块读取，避免每 8 字节调用一次 hypervisor
// 2. 大块失败才降级为 uint64 / uint32 / uint16 / uint8，以保留局部可读字节
// 3. strict=true 时遇到任何读取失败直接返回 false
// 4. strict=false 时无法读取的数据补 0，并统计失败字节
// -----------------------------------------------------------------------------
static bool ReadMemoryBlock(const ReadMemory &memory, uint64_t address, void *buffer, size_t size,
                            bool strict, MemoryReadStats *stats = nullptr) {
    if (size == 0) {
        if (stats) {
            *stats = {};
        }
        return true;
    }
    if (buffer == nullptr) {
        return false;
    }
    // address + size 溢出检查
    if (static_cast<uint64_t>(size - 1) > std::numeric_limits<uint64_t>::max() - address) {
        return false;
    }
    MemoryReadStats localStats{};
    localStats.requested = static_cast<uint64_t>(size);
    auto *destination = static_cast<uint8_t *>(buffer);
    size_t offset = 0;
    while (offset < size) {
        const uint64_t currentAddress = address + static_cast<uint64_t>(offset);
        const size_t pageRemaining = static_cast<size_t>(0x1000ULL - (currentAddress & 0xFFFULL));
        const size_t totalRemaining = size - offset;
        // The backend copies across destination pages itself. Splitting here
        // makes an unaligned output buffer trigger two hypercalls per source page.
        const size_t available = (std::min)(pageRemaining, totalRemaining);
        if (available > sizeof(uint64_t)) {
            const auto result = memory(currentAddress, destination + offset, available);
            if (result) {
                localStats.copied += static_cast<uint64_t>(available);
                offset += available;
                continue;
            }
            if (result.state == ReadState::TargetExited) {
                localStats.target_exited = true;
                if (strict) {
                    if (stats) *stats = localStats;
                    return false;
                }
                std::memset(destination + offset, 0, size - offset);
                localStats.failed += static_cast<uint64_t>(size - offset);
                break;
            }
            if (result.state == ReadState::PageUnavailable) {
                if (strict) {
                    if (stats) *stats = localStats;
                    return false;
                }
                std::memset(destination + offset, 0, available);
                RecordFailure(localStats, currentAddress, result.failure);
                localStats.failed += static_cast<uint64_t>(available);
                offset += available;
                continue;
            }
        }
        size_t consumed = 0;
        ReadResult scalar{};
        // ---------------------------------------------------------
        // 8 bytes
        // ---------------------------------------------------------
        if (available >= sizeof(uint64_t)) {
            scalar = TryReadScalar<uint64_t>(memory, currentAddress, destination + offset);
            if (scalar) consumed = sizeof(uint64_t);
        }
        // ---------------------------------------------------------
        // 4 bytes
        // ---------------------------------------------------------
        if (consumed == 0 && scalar.state == ReadState::Incomplete && available >= sizeof(uint32_t)) {
            scalar = TryReadScalar<uint32_t>(memory, currentAddress, destination + offset);
            if (scalar) consumed = sizeof(uint32_t);
        }
        // ---------------------------------------------------------
        // 2 bytes
        // ---------------------------------------------------------
        if (consumed == 0 && scalar.state == ReadState::Incomplete && available >= sizeof(uint16_t)) {
            scalar = TryReadScalar<uint16_t>(memory, currentAddress, destination + offset);
            if (scalar) consumed = sizeof(uint16_t);
        }
        // ---------------------------------------------------------
        // 1 byte
        // ---------------------------------------------------------
        if (consumed == 0 && scalar.state == ReadState::Incomplete) {
            scalar = TryReadScalar<uint8_t>(memory, currentAddress, destination + offset);
            if (scalar) consumed = sizeof(uint8_t);
        }
        // ---------------------------------------------------------
        // 成功
        // ---------------------------------------------------------
        if (consumed != 0) {
            localStats.copied += static_cast<uint64_t>(consumed);
            offset += consumed;
            continue;
        }
        if (scalar.state == ReadState::TargetExited) {
            localStats.target_exited = true;
            if (strict) {
                if (stats) *stats = localStats;
                return false;
            }
            std::memset(destination + offset, 0, size - offset);
            localStats.failed += static_cast<uint64_t>(size - offset);
            break;
        }
        if (scalar.state == ReadState::PageUnavailable) {
            if (strict) {
                if (stats) *stats = localStats;
                return false;
            }
            std::memset(destination + offset, 0, available);
            RecordFailure(localStats, currentAddress, scalar.failure);
            localStats.failed += static_cast<uint64_t>(available);
            offset += available;
            continue;
        }
        // ---------------------------------------------------------
        // 读取失败
        // ---------------------------------------------------------
        destination[offset] = 0;
        RecordFailure(localStats, currentAddress, scalar.failure);
        ++localStats.failed;
        ++offset;
        if (strict) {
            if (stats) {
                *stats = localStats;
            }
            return false;
        }
    }
    if (stats) {
        *stats = localStats;
    }
    return localStats.failed == 0;
}
// -----------------------------------------------------------------------------
// Runtime PE Dump
//
// 这个函数不是简单把内存数据覆盖到旧 RawOffset。
// 它会重新构建 section Raw layout，使 VirtualSize 中的运行时数据
// 能够保存进输出文件。
// -----------------------------------------------------------------------------
template<class NtHeaders>
static bool DumpImage(const ReadMemory &memory, uint64_t base_address,
                       const std::filesystem::path &output_filename, DumpSummary *summary) {
    if (summary)
        *summary = {};
    constexpr uint64_t MAX_PE_SIZE = 1024ULL * 1024ULL * 1024ULL;
    // 1 GiB
    constexpr uint32_t MAX_SECTIONS = 128;
    constexpr uint32_t MAX_HEADER_SIZE = 16 * 1024 * 1024;
    printf("\n"
           "============================================================\n"
           "[*] Starting Runtime PE Dump\n"
           "============================================================\n"
           "    Runtime Base : 0x%llX\n",
           static_cast<unsigned long long>(base_address));
    // =========================================================================
    // 1. DOS Header
    // =========================================================================
    IMAGE_DOS_HEADER dos{};
    MemoryReadStats dosStats{};
    if (!ReadMemoryBlock(memory, base_address, &dos, sizeof(dos), true, &dosStats)) {
        printf("[-] Failed to read complete DOS header.\n");
        return false;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature: "
               "0x%04X\n",
               dos.e_magic);
        return false;
    }
    if (dos.e_lfanew <= 0 || static_cast<uint64_t>(dos.e_lfanew) > 0x100000ULL) {
        printf("[-] Abnormal e_lfanew: "
               "0x%X\n",
               dos.e_lfanew);
        return false;
    }
    // =========================================================================
    // 2. NT Header
    // =========================================================================
    uint64_t ntAddress = 0;
    if (!CheckedAddU64(base_address, static_cast<uint64_t>(dos.e_lfanew), ntAddress)) {
        printf("[-] NT header address overflow.\n");
        return false;
    }
    using OptionalHeader = decltype(NtHeaders{}.OptionalHeader);
    constexpr bool is32 = sizeof(OptionalHeader) == sizeof(IMAGE_OPTIONAL_HEADER32);
    constexpr size_t prefixSize = sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    constexpr size_t fixedOptionalSize = offsetof(OptionalHeader, DataDirectory);
    NtHeaders nt{};
    if (!ReadMemoryBlock(memory, ntAddress, &nt, prefixSize, true)
        || nt.Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid or unreadable NT header prefix.\n");
        return false;
    }
    const auto optionalSize = nt.FileHeader.SizeOfOptionalHeader;
    if (optionalSize < fixedOptionalSize) {
        printf("[-] Optional header is too small.\n");
        return false;
    }
    const auto readOptionalSize = (std::min)(size_t(optionalSize), sizeof(OptionalHeader));
    uint64_t optionalAddress{};
    if (!CheckedAddU64(ntAddress, prefixSize, optionalAddress)
        || !ReadMemoryBlock(memory, optionalAddress, &nt.OptionalHeader, readOptionalSize, true)) {
        printf("[-] Failed to read optional header.\n");
        return false;
    }
    if (nt.OptionalHeader.Magic != (is32 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC : IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        || nt.FileHeader.Machine != (is32 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64)) {
        printf("[-] Unsupported or inconsistent PE machine/magic.\n");
        return false;
    }
    if (nt.OptionalHeader.NumberOfRvaAndSizes > (optionalSize - fixedOptionalSize) / sizeof(IMAGE_DATA_DIRECTORY)) {
        printf("[-] Data directories exceed the declared optional header.\n");
        return false;
    }
    const size_t ntBytes = prefixSize + readOptionalSize;
    uint64_t imageEnd{};
    if (!CheckedAddU64(base_address, nt.OptionalHeader.SizeOfImage, imageEnd)
        || (is32 && (base_address > UINT32_MAX || imageEnd > 0x100000000ULL))) {
        printf("[-] Runtime image exceeds its address space.\n");
        return false;
    }
    const uint32_t numSections = nt.FileHeader.NumberOfSections;
    if (numSections == 0 || numSections > MAX_SECTIONS) {
        printf("[-] Abnormal section count: "
               "%u\n",
               numSections);
        return false;
    }
    if (nt.OptionalHeader.SizeOfHeaders == 0 || nt.OptionalHeader.SizeOfHeaders > MAX_HEADER_SIZE) {
        printf("[-] Invalid SizeOfHeaders: "
               "0x%X\n",
               nt.OptionalHeader.SizeOfHeaders);
        return false;
    }
    if (nt.OptionalHeader.SizeOfImage == 0 || nt.OptionalHeader.SizeOfImage > MAX_PE_SIZE) {
        printf("[-] Invalid SizeOfImage: "
               "0x%X\n",
               nt.OptionalHeader.SizeOfImage);
        return false;
    }
    if (nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage) {
        printf("[-] SizeOfHeaders > SizeOfImage.\n");
        return false;
    }
    const uint32_t fileAlignment = nt.OptionalHeader.FileAlignment;
    if (fileAlignment == 0 || (fileAlignment & (fileAlignment - 1)) != 0 || fileAlignment > 0x10000) {
        printf("[-] Invalid FileAlignment: "
               "0x%X\n",
               fileAlignment);
        return false;
    }
    printf("[+] Valid %s image found.\n"
           "    Sections       : %u\n"
           "    SizeOfImage    : 0x%X\n"
           "    SizeOfHeaders  : 0x%X\n"
           "    FileAlignment  : 0x%X\n"
           "    Preferred Base : 0x%llX\n"
           "    Runtime Base   : 0x%llX\n"
           "    Timestamp      : 0x%08X\n",
           is32 ? "PE32 x86" : "PE32+ x64", numSections, nt.OptionalHeader.SizeOfImage, nt.OptionalHeader.SizeOfHeaders, fileAlignment,
           static_cast<unsigned long long>(nt.OptionalHeader.ImageBase),
           static_cast<unsigned long long>(base_address), nt.FileHeader.TimeDateStamp);
    // =========================================================================
    // 3. Section Table
    // =========================================================================
    uint64_t sectionTableOffset = static_cast<uint64_t>(dos.e_lfanew) + sizeof(DWORD) +
                                  sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    uint64_t sectionTableSize = static_cast<uint64_t>(numSections) * sizeof(IMAGE_SECTION_HEADER);
    uint64_t sectionTableEnd = 0;
    if (!CheckedAddU64(sectionTableOffset, sectionTableSize, sectionTableEnd)) {
        printf("[-] Section table range overflow.\n");
        return false;
    }
    if (sectionTableEnd > nt.OptionalHeader.SizeOfHeaders) {
        printf("[-] Section table is outside SizeOfHeaders.\n"
               "    Table end     : 0x%llX\n"
               "    SizeOfHeaders : 0x%X\n",
               static_cast<unsigned long long>(sectionTableEnd), nt.OptionalHeader.SizeOfHeaders);
        return false;
    }
    uint64_t sectionTableAddress = 0;
    if (!CheckedAddU64(base_address, sectionTableOffset, sectionTableAddress)) {
        printf("[-] Section table address overflow.\n");
        return false;
    }
    std::vector<IMAGE_SECTION_HEADER> sections(numSections);
    if (!ReadMemoryBlock(memory, sectionTableAddress, sections.data(),
                         sections.size() * sizeof(IMAGE_SECTION_HEADER), true)) {
        printf("[-] Failed to read section table.\n");
        return false;
    }
    // =========================================================================
    // 4. 计算各 section 实际运行时大小
    // =========================================================================
    std::vector<uint64_t> runtimeCopySizes(numSections, 0);
    for (uint32_t i = 0; i < numSections; ++i) {
        const auto &sec = sections[i];
        char name[9]{};
        memcpy(name, sec.Name, 8);
        if (sec.VirtualAddress == 0) {
            runtimeCopySizes[i] = 0;
            continue;
        }
        if (sec.VirtualAddress >= nt.OptionalHeader.SizeOfImage) {
            printf("[-] Section [%s] starts outside image.\n"
                   "    RVA         : 0x%X\n"
                   "    SizeOfImage : 0x%X\n",
                   name, sec.VirtualAddress, nt.OptionalHeader.SizeOfImage);
            return false;
        }
        uint64_t virtualSize = sec.Misc.VirtualSize;
        if (virtualSize == 0) {
            virtualSize = sec.SizeOfRawData;
        }
        if (virtualSize == 0) {
            runtimeCopySizes[i] = 0;
            continue;
        }
        const uint64_t maximumSize =
            static_cast<uint64_t>(nt.OptionalHeader.SizeOfImage) - sec.VirtualAddress;
        if (virtualSize > maximumSize) {
            printf("[!] Section [%s] VirtualSize exceeds image boundary.\n"
                   "    Requested : 0x%llX\n"
                   "    Maximum   : 0x%llX\n"
                   "    Clamping to image boundary.\n",
                   name, static_cast<unsigned long long>(virtualSize),
                   static_cast<unsigned long long>(maximumSize));
            virtualSize = maximumSize;
        }
        runtimeCopySizes[i] = virtualSize;
    }
    // =========================================================================
    // 5. 重建 Raw layout
    // =========================================================================
    uint64_t rebuiltHeadersSize = 0;
    const uint64_t minimumHeaders =
        (std::max)(static_cast<uint64_t>(nt.OptionalHeader.SizeOfHeaders), sectionTableEnd);
    if (!AlignUpU64(minimumHeaders, fileAlignment, rebuiltHeadersSize)) {
        printf("[-] Failed to align PE headers.\n");
        return false;
    }
    if (rebuiltHeadersSize > std::numeric_limits<DWORD>::max()) {
        printf("[-] Rebuilt headers exceed DWORD range.\n");
        return false;
    }
    uint64_t currentRawOffset = rebuiltHeadersSize;
    std::vector<IMAGE_SECTION_HEADER> rebuiltSections = sections;
    for (uint32_t i = 0; i < numSections; ++i) {
        auto &rebuilt = rebuiltSections[i];
        const uint64_t copySize = runtimeCopySizes[i];
        if (copySize == 0) {
            rebuilt.PointerToRawData = 0;
            rebuilt.SizeOfRawData = 0;
            continue;
        }
        uint64_t rebuiltRawSize = 0;
        if (!AlignUpU64(copySize, fileAlignment, rebuiltRawSize)) {
            printf("[-] Section %u alignment overflow.\n", i);
            return false;
        }
        if (currentRawOffset > std::numeric_limits<DWORD>::max() ||
            rebuiltRawSize > std::numeric_limits<DWORD>::max()) {
            printf("[-] PE raw section exceeds DWORD range.\n");
            return false;
        }
        rebuilt.PointerToRawData = static_cast<DWORD>(currentRawOffset);
        rebuilt.SizeOfRawData = static_cast<DWORD>(rebuiltRawSize);
        uint64_t nextOffset = 0;
        if (!CheckedAddU64(currentRawOffset, rebuiltRawSize, nextOffset)) {
            printf("[-] Final file size overflow.\n");
            return false;
        }
        if (nextOffset > MAX_PE_SIZE) {
            printf("[-] Rebuilt PE exceeds safety limit "
                   "(1 GiB).\n");
            return false;
        }
        currentRawOffset = nextOffset;
    }
    const uint64_t finalFileSize = currentRawOffset;
    if (finalFileSize == 0 || finalFileSize > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        printf("[-] Invalid final output size.\n");
        return false;
    }
    printf("[+] Rebuilt file size: "
           "0x%llX (%llu bytes)\n",
           static_cast<unsigned long long>(finalFileSize), static_cast<unsigned long long>(finalFileSize));
    // =========================================================================
    // 6. 创建输出缓冲区
    // =========================================================================
    std::vector<uint8_t> output;
    try {
        output.resize(static_cast<size_t>(finalFileSize), 0);
    } catch (const std::bad_alloc &) {
        printf("[-] Failed to allocate "
               "%llu bytes for output image.\n",
               static_cast<unsigned long long>(finalFileSize));
        return false;
    }
    // =========================================================================
    // 7. Dump Header
    // =========================================================================
    MemoryReadStats headerStats{};
    if (!ReadMemoryBlock(memory, base_address, output.data(), nt.OptionalHeader.SizeOfHeaders, true,
                         &headerStats)) {
        printf("[-] Failed to dump complete PE headers.\n");
        return false;
    }
    if (memcmp(output.data(), &dos, sizeof(dos)) != 0 ||
        memcmp(output.data() + dos.e_lfanew, &nt, ntBytes) != 0 ||
        memcmp(output.data() + sectionTableOffset, sections.data(), sectionTableSize) != 0) {
        printf("[-] PE metadata changed during header acquisition.\n");
        return false;
    }
    const std::vector<uint8_t> originalHeaders(output.begin(), output.begin() + nt.OptionalHeader.SizeOfHeaders);
    // =========================================================================
    // 8. 修复输出 NT Header
    // =========================================================================
    NtHeaders rebuiltNt = nt;
    // 因为数据来源是已经 relocation 后的运行时映像，
    // 所以将 ImageBase 修改成此次实际 Runtime Base。
    rebuiltNt.OptionalHeader.ImageBase = static_cast<decltype(rebuiltNt.OptionalHeader.ImageBase)>(base_address);
    rebuiltNt.OptionalHeader.SizeOfHeaders = static_cast<DWORD>(rebuiltHeadersSize);
    // 内容已经被修改，原校验和没有意义。
    rebuiltNt.OptionalHeader.CheckSum = 0;
    // Security Directory 的 VirtualAddress 实际上是文件偏移，
    // 我们重排了 Raw layout，因此原值已经无效。
    if (rebuiltNt.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY) {
        rebuiltNt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = {};
    }
    const uint64_t ntEnd = static_cast<uint64_t>(dos.e_lfanew) + ntBytes;
    if (ntEnd > output.size()) {
        printf("[-] NT header patch would exceed output buffer.\n");
        return false;
    }
    memcpy(output.data() + dos.e_lfanew, &rebuiltNt, ntBytes);
    // =========================================================================
    // 9. 写回重建后的 Section Table
    // =========================================================================
    if (sectionTableEnd > output.size()) {
        printf("[-] Section table patch exceeds output buffer.\n");
        return false;
    }
    memcpy(output.data() + static_cast<size_t>(sectionTableOffset), rebuiltSections.data(),
           rebuiltSections.size() * sizeof(IMAGE_SECTION_HEADER));
    // =========================================================================
    // 10. Dump Sections
    // =========================================================================
    uint64_t totalRequestedBytes = 0;
    uint64_t totalCopiedBytes = 0;
    uint64_t totalFailedBytes = 0;
    bool targetExited = false;
    std::vector<MemoryReadStats> sectionStats(numSections);
    printf("\n"
           "------------------------------------------------------------\n"
           "[*] Dumping Sections\n"
           "------------------------------------------------------------\n");
    for (uint32_t i = 0; i < numSections; ++i) {
        const auto &original = sections[i];
        const auto &rebuilt = rebuiltSections[i];
        const uint64_t copySize = runtimeCopySizes[i];
        char name[9]{};
        memcpy(name, original.Name, 8);
        printf("[*] %-8s "
               "RVA=0x%08X "
               "VirtualSize=0x%08llX "
               "RawOffset=0x%08X "
               "RawSize=0x%08X\n",
               name, original.VirtualAddress, static_cast<unsigned long long>(copySize),
               rebuilt.PointerToRawData, rebuilt.SizeOfRawData);
        if (copySize == 0) {
            printf("    [i] Empty section, skipped.\n");
            continue;
        }
        uint64_t sourceAddress = 0;
        if (!CheckedAddU64(base_address, original.VirtualAddress, sourceAddress)) {
            printf("    [-] Runtime source address overflow.\n");
            return false;
        }
        uint64_t rawEnd = 0;
        if (!CheckedAddU64(rebuilt.PointerToRawData, copySize, rawEnd)) {
            printf("    [-] Raw destination range overflow.\n");
            return false;
        }
        if (rawEnd > output.size()) {
            printf("    [-] Raw destination exceeds output buffer.\n");
            return false;
        }
        if (copySize > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
            printf("    [-] Section is too large for size_t.\n");
            return false;
        }
        const auto sectionStarted = std::chrono::steady_clock::now();
        MemoryReadStats stats{};
        bool complete = false;
        if (targetExited) {
            stats.requested = copySize;
            stats.failed = copySize;
            stats.target_exited = true;
            std::memset(output.data() + rebuilt.PointerToRawData, 0, static_cast<size_t>(copySize));
        } else {
            complete = ReadMemoryBlock(memory, sourceAddress, output.data() + rebuilt.PointerToRawData,
                                       static_cast<size_t>(copySize), false, &stats);
        }
        targetExited = targetExited || stats.target_exited;
        totalRequestedBytes += stats.requested;
        totalCopiedBytes += stats.copied;
        totalFailedBytes += stats.failed;
        sectionStats[i] = stats;
        printf("    TimeMs   : %lld\n", static_cast<long long>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - sectionStarted).count()));
        if (complete) {
            printf("    [+] Complete: "
                   "%llu bytes copied.\n",
                   static_cast<unsigned long long>(stats.copied));
        } else {
            printf("    [!] PARTIAL\n"
                   "        Requested : %llu\n"
                   "        Copied    : %llu\n"
                   "        Failed    : %llu\n",
                   static_cast<unsigned long long>(stats.requested),
                   static_cast<unsigned long long>(stats.copied),
                   static_cast<unsigned long long>(stats.failed));
        }
    }
    // =========================================================================
    // 11. 保存 EXE
    // =========================================================================
    bool finalHeadersVerified = false;
    if (!targetExited) {
        std::vector<uint8_t> finalHeaders(originalHeaders.size());
        MemoryReadStats finalHeaderStats{};
        if (!ReadMemoryBlock(memory, base_address, finalHeaders.data(), finalHeaders.size(), true,
                             &finalHeaderStats)) {
            if (!finalHeaderStats.target_exited) {
                printf("[-] PE headers became unreadable; export rejected before saving.\n");
                return false;
            }
            targetExited = true;
        } else if (finalHeaders != originalHeaders) {
            printf("[-] PE headers changed; export rejected before saving.\n");
            return false;
        } else {
            finalHeadersVerified = true;
        }
    }
    printf("\n"
           "------------------------------------------------------------\n"
           "[*] Writing output file\n"
           "------------------------------------------------------------\n");
    std::ofstream out(output_filename, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        printf("[-] Failed to create output file: %s\n", PathText(output_filename).c_str());
        return false;
    }
    if (output.size() > static_cast<size_t>(std::numeric_limits<std::streamsize>::max())) {
        printf("[-] Output is too large for std::ofstream::write.\n");
        out.close();
        return false;
    }
    out.write(reinterpret_cast<const char *>(output.data()), static_cast<std::streamsize>(output.size()));
    if (!out.good()) {
        printf("[-] Failed while writing output file.\n");
        out.close();
        return false;
    }
    out.flush();
    if (!out.good()) {
        printf("[-] Failed while flushing output file.\n");
        out.close();
        return false;
    }
    out.close();
    if (out.fail()) {
        printf("[-] Failed while closing output file.\n");
        return false;
    }
    // =========================================================================
    // 12. 生成信息文件
    // =========================================================================
    auto infoFilename = output_filename;
    infoFilename += L".info.txt";
    std::ofstream info(infoFilename, std::ios::trunc);
    if (info.is_open()) {
        info << "Runtime PE Dump Information\n"
             << "===========================\n\n";
        info << std::hex << std::uppercase;
        info << "Architecture=" << (is32 ? "x86" : "x64") << "\n";
        info << "PEFormat=" << (is32 ? "PE32" : "PE32+") << "\n";
        info << "Machine=0x" << nt.FileHeader.Machine << "\n";
        info << "RuntimeBase=0x" << base_address << "\n";
        info << "OriginalPreferredImageBase=0x" << nt.OptionalHeader.ImageBase << "\n";
        info << "OutputImageBase=0x" << rebuiltNt.OptionalHeader.ImageBase << "\n";
        info << "SizeOfImage=0x" << nt.OptionalHeader.SizeOfImage << "\n";
        info << "OriginalSizeOfHeaders=0x" << nt.OptionalHeader.SizeOfHeaders << "\n";
        info << "RebuiltSizeOfHeaders=0x" << rebuiltNt.OptionalHeader.SizeOfHeaders << "\n";
        info << "TimeDateStamp=0x" << nt.FileHeader.TimeDateStamp << "\n";
        info << std::dec;
        info << "NumberOfSections=" << numSections << "\n";
        info << "RequestedBytes=" << totalRequestedBytes << "\n";
        info << "CopiedBytes=" << totalCopiedBytes << "\n";
        info << "UnreadableBytes=" << totalFailedBytes << "\n\n";
        info << "Result=" << (targetExited ? "PARTIAL_TARGET_EXITED"
            : totalFailedBytes ? "PARTIAL" : "COMPLETE") << "\n";
        info << "TargetExitedDuringCapture=" << (targetExited ? "true" : "false") << "\n";
        info << "FinalHeadersVerified=" << (finalHeadersVerified ? "true" : "false") << "\n";
        info << "ZeroFillPolicy=unreadable bytes are placeholders, not observed zeros\n";
        info << "Snapshot=sequential runtime reads; not atomic\n\n";
        for (uint32_t i = 0; i < numSections; ++i) {
            char name[9]{};
            memcpy(name, sections[i].Name, 8);
            info << "[" << name << "]\n";
            info << std::hex << std::uppercase;
            info << "RVA=0x" << sections[i].VirtualAddress << "\n";
            info << "OriginalVirtualSize=0x" << sections[i].Misc.VirtualSize << "\n";
            info << "RuntimeCopySize=0x" << runtimeCopySizes[i] << "\n";
            info << "OriginalRawOffset=0x" << sections[i].PointerToRawData << "\n";
            info << "OriginalRawSize=0x" << sections[i].SizeOfRawData << "\n";
            info << "RebuiltRawOffset=0x" << rebuiltSections[i].PointerToRawData << "\n";
            info << "RebuiltRawSize=0x" << rebuiltSections[i].SizeOfRawData << "\n\n";
            info << std::dec << "CopiedBytes=" << sectionStats[i].copied << "\n";
            info << "UnreadableBytes=" << sectionStats[i].failed << "\n";
            info << "FailureSampleCount=" << sectionStats[i].failure_sample_count << "\n";
            for (size_t sample = 0; sample < sectionStats[i].failure_sample_count; ++sample) {
                const auto& failure = sectionStats[i].failure_samples[sample];
                info << "FailureSample" << sample << "=RVA:0x" << std::hex << std::uppercase
                     << (failure.address - base_address) << std::dec
                     << ",Kind:" << FailureKindName(failure.kind) << "\n";
            }
            info << "\n";
        }
        info.flush();
        info.close();
        if (info.fail()) {
            printf("[-] Failed while writing info sidecar file.\n");
            return false;
        }
    } else {
        printf("[-] Could not create info sidecar file.\n");
        return false;
    }
    // =========================================================================
    // 13. 最终结果
    // =========================================================================
    printf("\n"
           "============================================================\n"
           "[+] Runtime PE Dump Completed\n"
           "============================================================\n"
           "    Output           : %s\n"
           "    Info             : %s\n"
           "    Runtime Base     : 0x%llX\n"
           "    Final File Size  : %llu bytes\n"
           "    Requested Bytes  : %llu\n"
           "    Copied Bytes     : %llu\n"
           "    Unreadable Bytes : %llu\n"
           "============================================================\n",
           PathText(output_filename).c_str(), PathText(infoFilename).c_str(),
           static_cast<unsigned long long>(base_address), static_cast<unsigned long long>(output.size()),
           static_cast<unsigned long long>(totalRequestedBytes),
           static_cast<unsigned long long>(totalCopiedBytes),
           static_cast<unsigned long long>(totalFailedBytes));
    if (totalFailedBytes != 0) {
        printf("\n"
               "[!] WARNING:\n"
               "    Some runtime bytes could not be read.\n"
               "    Those bytes were zero-filled in the output file.\n"
               "    Check the section log above before analyzing in IDA.\n"
               "\n");
    }
    if (summary) {
        *summary = {totalRequestedBytes, totalCopiedBytes, totalFailedBytes,
                    targetExited, finalHeadersVerified};
        for (const auto& section : sectionStats)
            if (section.failure_sample_count &&
                section.failure_samples[0].kind == ReadFailureKind::TranslationZero)
                summary->walk_samples.push_back(section.failure_samples[0]);
    }
    return true;
}
bool DumpProcessMemory(const ReadMemory& memory, uint64_t base_address,
    const std::filesystem::path& output_filename, DumpSummary* summary) {
    if (summary) *summary = {};
    IMAGE_DOS_HEADER dos{};
    uint64_t magicAddress{};
    WORD magic{};
    if (!ReadMemoryBlock(memory, base_address, &dos, sizeof(dos), true)
        || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000
        || !CheckedAddU64(base_address, uint64_t(dos.e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), magicAddress)
        || !ReadMemoryBlock(memory, magicAddress, &magic, sizeof(magic), true)) {
        printf("[-] Invalid or unreadable PE format header.\n");
        return false;
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        return DumpImage<IMAGE_NT_HEADERS32>(memory, base_address, output_filename, summary);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return DumpImage<IMAGE_NT_HEADERS64>(memory, base_address, output_filename, summary);
    printf("[-] Unsupported optional header magic: 0x%04X\n", magic);
    return false;
}
} // namespace dumper
