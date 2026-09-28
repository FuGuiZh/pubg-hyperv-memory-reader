#pragma once
#include "monitor/monitor.hpp"
#include <algorithm>
#include <cstring>

namespace monitor {
struct ProcessIdentity {
    u32 pid = 0;
    u64 sequence = 0;
    std::wstring image;
};

// SystemBasicProcessInformation is available on this project's Windows 11
// baseline (26100.4770+). The OS sequence identifies PID reuse without opening
// a target process handle. It is not a process creation timestamp.
inline std::optional<ProcessIdentity> ParseProcessIdentity(const void* data, std::size_t size, u32 pid) {
    using Entry = SYSTEM_BASICPROCESS_INFORMATION;
    static_assert(sizeof(Entry) == 48 && offsetof(Entry, SequenceNumber) == 24);
    const auto* bytes = static_cast<const u8*>(data);
    std::size_t offset = 0;
    for (;;) {
        if (!bytes || offset > size || size - offset < sizeof(Entry))
            Fail(Code::IdentityUnavailable, "PROCESS_LIST", "Truncated process list");
        Entry entry{};
        std::memcpy(&entry, bytes + offset, sizeof(entry));
        if (entry.NextEntryOffset && (entry.NextEntryOffset < sizeof(Entry)
            || entry.NextEntryOffset % alignof(Entry) != 0 || entry.NextEntryOffset > size - offset - sizeof(Entry)))
            Fail(Code::IdentityUnavailable, "PROCESS_LIST", "Invalid process list offset");
        if (reinterpret_cast<ULONG_PTR>(entry.UniqueProcessId) == pid) {
            const auto length = entry.ImageName.Length;
            const auto address = reinterpret_cast<ULONG_PTR>(entry.ImageName.Buffer);
            const auto base = reinterpret_cast<ULONG_PTR>(bytes);
            if (!entry.SequenceNumber || !length || length % sizeof(wchar_t) || length > entry.ImageName.MaximumLength
                || address < base || address - base > size || length > size - (address - base))
                Fail(Code::IdentityUnavailable, "PROCESS_LIST", "Invalid process identity or name range");
            std::wstring image(length / sizeof(wchar_t), L'\0');
            std::memcpy(image.data(), entry.ImageName.Buffer, length);
            if (image.find(L'\0') != std::wstring::npos)
                Fail(Code::IdentityUnavailable, "PROCESS_LIST", "Embedded null in process name");
            return ProcessIdentity{pid, entry.SequenceNumber, std::move(image)};
        }
        if (!entry.NextEntryOffset) return std::nullopt;
        offset += entry.NextEntryOffset;
    }
}

inline std::optional<ProcessIdentity> QueryProcessIdentity(u32 pid) {
    const auto ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query = ntdll ? reinterpret_cast<decltype(&NtQuerySystemInformation)>(GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    if (!query) Fail(Code::IdentityUnavailable, "PROCESS_LIST", "System process query unavailable");
    std::vector<u8> buffer(128 * 1024);
    constexpr NTSTATUS mismatch = static_cast<NTSTATUS>(0xC0000004UL);
    constexpr NTSTATUS too_small = static_cast<NTSTATUS>(0xC0000023UL);
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        ULONG returned = 0;
        const auto status = query(SystemBasicProcessInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &returned);
        if (status == mismatch || status == too_small) {
            const auto required = std::max<std::size_t>(returned, buffer.size() * 2);
            if (required > 16 * 1024 * 1024) break;
            buffer.resize(required); continue;
        }
        if (status < 0)
            throw Fault(Issue{Code::IdentityUnavailable, "PROCESS_LIST",
                "SystemBasicProcessInformation failed; requires Windows 11 26100.4770 or later", 0, 0, 0, static_cast<u32>(status)});
        if (!returned || returned > buffer.size())
            Fail(Code::IdentityUnavailable, "PROCESS_LIST", "Invalid process list length");
        return ParseProcessIdentity(buffer.data(), returned, pid);
    }
    Fail(Code::IdentityUnavailable, "PROCESS_LIST", "Process list changed beyond retry limit");
}
}
