#include "monitor/monitor.hpp"
#include "platform/windows/kernel_queries.hpp"
#if !defined(_WIN32)
#error kernel_queries.cpp requires a Windows x64 target.
#endif
static_assert(sizeof(void*) == 8, "Build this target as x64.");
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")

// ============================================================================
// Kernel module and symbol queries
// ============================================================================
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <vector>

namespace monitor {
    namespace {
        struct ModuleEntry {
            HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags;
            USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName;
            UCHAR FullPathName[256];
        };
        struct Modules { ULONG Count; ModuleEntry Items[1]; };
        [[noreturn]] void WinFail(const char* stage, const char* text, DWORD error = GetLastError()) {
            throw Fault(Issue{ Code::BackendUnavailable,stage,text,0,0,0,error });
        }
        // Recent Windows builds can redact kernel module addresses to zero unless
        // SeDebugPrivilege is enabled, even when this process is elevated.
        // Only adjust our effective token for this query; never open the target process.
        class KernelQueryPrivilege {
            struct Token {
                HANDLE value = nullptr;
                ~Token() { if (value) CloseHandle(value); }
            } token_;
            TOKEN_PRIVILEGES previous_{};
            bool changed_ = false;
        public:
            KernelQueryPrivilege() {
                if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, &token_.value)) {
                    const auto error = GetLastError();
                    if (error != ERROR_NO_TOKEN) WinFail("KERNEL_PRIVILEGE", "Could not query own thread token", error);
                    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token_.value))
                        WinFail("KERNEL_PRIVILEGE", "Could not query own process token");
                }
                TOKEN_PRIVILEGES requested{};
                requested.PrivilegeCount = 1;
                if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &requested.Privileges[0].Luid))
                    WinFail("KERNEL_PRIVILEGE", "SeDebugPrivilege lookup failed");
                requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                DWORD bytes = 0;
                const auto adjusted = AdjustTokenPrivileges(token_.value, FALSE, &requested,
                    sizeof(previous_), &previous_, &bytes);
                const auto error = GetLastError();
                changed_ = adjusted && previous_.PrivilegeCount != 0;
                if (!adjusted || error != ERROR_SUCCESS)
                    WinFail("KERNEL_PRIVILEGE", "Could not enable SeDebugPrivilege for the kernel module query; run elevated", error);
            }
            ~KernelQueryPrivilege() {
                if (changed_) AdjustTokenPrivileges(token_.value, FALSE, &previous_, 0, nullptr, nullptr);
            }
            KernelQueryPrivilege(const KernelQueryPrivilege&) = delete;
            KernelQueryPrivilege& operator=(const KernelQueryPrivilege&) = delete;
        };
        std::wstring DebuggersPath() {
            for (REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
                HKEY h = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots", 0, KEY_READ | view, &h) != ERROR_SUCCESS) continue;
                wchar_t value[32768]{}; DWORD bytes = sizeof(value), type = 0;
                const LSTATUS s = RegQueryValueExW(h, L"KitsRoot10", nullptr, &type, reinterpret_cast<BYTE*>(value), &bytes);
                RegCloseKey(h);
                if (s != ERROR_SUCCESS || type != REG_SZ || bytes < sizeof(wchar_t) || bytes>sizeof(value)) continue;
                value[32767] = L'\0';
                return (std::filesystem::path(value) / L"Debuggers" / L"x64").wstring();
            }
            Fail(Code::BackendUnavailable, "SYMBOL_SDK", "Windows SDK Debugging Tools x64 not found");
        }
        struct Library {
            HMODULE handle = nullptr;
            explicit Library(const std::wstring& path) {
                handle = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                if (!handle) WinFail("SYMBOL_DLL", "Could not load SDK dbghelp/symsrv");
            }
            ~Library() { if (handle) FreeLibrary(handle); }
            Library(const Library&) = delete;
        };
        template<class T> T Function(HMODULE h, const char* name) {
            const auto p = GetProcAddress(h, name);
            if (!p) WinFail("SYMBOL_DLL", "Required DbgHelp export missing");
            return reinterpret_cast<T>(p);
        }
    }
    u64 QueryKernelBase() {
        KernelQueryPrivilege privilege;
        using Query = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) WinFail("KERNEL_MODULES", "ntdll unavailable");
        const auto q = Function<Query>(ntdll, "NtQuerySystemInformation");
        constexpr auto cls = static_cast<SYSTEM_INFORMATION_CLASS>(11);
        constexpr NTSTATUS mismatch = static_cast<NTSTATUS>(0xC0000004UL);
        for (int attempt = 0; attempt < 4; ++attempt) {
            ULONG required = 0; q(cls, nullptr, 0, &required);
            if (required < offsetof(Modules, Items) || required>16U * 1024U * 1024U)
                Fail(Code::BackendUnavailable, "KERNEL_MODULES", "Unexpected module buffer length");
            std::vector<u8> buffer(static_cast<std::size_t>(required) + 0x4000);
            ULONG returned = 0;
            const auto status = q(cls, buffer.data(), static_cast<ULONG>(buffer.size()), &returned);
            if (status == mismatch) continue;
            if (status < 0) throw Fault(Issue{ Code::BackendUnavailable,"KERNEL_MODULES","NtQuerySystemInformation failed",0,0,0,static_cast<u32>(status) });
            const std::size_t valid = returned ? std::min<std::size_t>(returned, buffer.size()) : buffer.size();
            if (valid < offsetof(Modules, Items)) Fail(Code::InvalidLayout, "KERNEL_MODULES", "Short module result");
            ULONG count = 0; std::memcpy(&count, buffer.data(), sizeof(count));
            const auto capacity = (valid - offsetof(Modules, Items)) / sizeof(ModuleEntry);
            if (count > capacity) Fail(Code::InvalidLayout, "KERNEL_MODULES", "Module count exceeds returned buffer");
            for (ULONG i = 0; i < count; ++i) {
                ModuleEntry e{}; std::memcpy(&e, buffer.data() + offsetof(Modules, Items) + i * sizeof(e), sizeof(e));
                if (e.OffsetToFileName >= sizeof(e.FullPathName)) continue;
                const char* n = reinterpret_cast<const char*>(e.FullPathName) + e.OffsetToFileName;
                const auto max = sizeof(e.FullPathName) - e.OffsetToFileName;
                if (!std::memchr(n, 0, max)) continue;
                if (_stricmp(n, "ntoskrnl.exe") == 0 || _stricmp(n, "ntkrnlmp.exe") == 0
                    || _stricmp(n, "ntkrnlpa.exe") == 0 || _stricmp(n, "ntkrpamp.exe") == 0) {
                    const auto base = reinterpret_cast<u64>(e.ImageBase);
                    if (base < 0xffff800000000000ULL || (base & 0xfff))
                        Fail(Code::BackendUnavailable, "KERNEL_BASE_REDACTED",
                            "Windows returned a zero or invalid kernel base; refusing to use a symbol RVA as a virtual address", base);
                    return base;
                }
            }
            break;
        }
        Fail(Code::BackendUnavailable, "KERNEL_MODULES", "Kernel base unavailable");
    }
    static u64 QueryProcessSymbols(ProcessImageLayout* layout) {
        const auto dir = std::filesystem::path(DebuggersPath());
        Library symsrv((dir / L"symsrv.dll").wstring());
        Library dbg((dir / L"dbghelp.dll").wstring());
        const auto set = Function<decltype(&SymSetOptions)>(dbg.handle, "SymSetOptions");
        const auto get_options = Function<decltype(&SymGetOptions)>(dbg.handle, "SymGetOptions");
        const auto init = Function<decltype(&SymInitializeW)>(dbg.handle, "SymInitializeW");
        const auto load = Function<decltype(&SymLoadModuleExW)>(dbg.handle, "SymLoadModuleExW");
        const auto find = Function<decltype(&SymFromName)>(dbg.handle, "SymFromName");
        const auto unload = Function<decltype(&SymUnloadModule64)>(dbg.handle, "SymUnloadModule64");
        const auto cleanup = Function<decltype(&SymCleanup)>(dbg.handle, "SymCleanup");
        // Each executable invokes these DbgHelp queries from one thread.
        const auto cache = std::filesystem::temp_directory_path() / L"resolver-monitor-symbols";
        std::filesystem::create_directories(cache);
        const std::wstring path = L"srv*" + cache.wstring() + L"*https://msdl.microsoft.com/download/symbols";
        const HANDLE process = GetCurrentProcess();
        const DWORD old_options = get_options();
        set(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS
            | (layout ? SYMOPT_EXACT_SYMBOLS : 0));
        struct RestoreOptions { decltype(set) fn; DWORD old; ~RestoreOptions() { fn(old); } } restore{ set,old_options };
        if (!init(process, path.c_str(), FALSE)) WinFail("SYMBOL_INIT", "SymInitializeW failed");
        struct Cleanup { decltype(cleanup) fn; HANDLE p; ~Cleanup() { fn(p); } } guard{ cleanup,process };
        wchar_t system[MAX_PATH]{};
        const UINT n = GetSystemDirectoryW(system, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) WinFail("SYMBOL_KERNEL_PATH", "System directory unavailable");
        const auto kernel = (std::filesystem::path(system) / L"ntoskrnl.exe").wstring();
        const u64 loaded = load(process, nullptr, kernel.c_str(), nullptr, 0x10000000, 0, nullptr, 0);
        if (!loaded) WinFail("SYMBOL_LOAD", "SymLoadModuleExW failed");
        struct Unload { decltype(unload) fn; HANDLE p; u64 base; ~Unload() { fn(p, base); } } mod{ unload,process,loaded };
        alignas(SYMBOL_INFO) unsigned char storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{};
        auto* symbol = reinterpret_cast<PSYMBOL_INFO>(storage);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO); symbol->MaxNameLen = MAX_SYM_NAME;
        if (!find(process, "ntoskrnl!PsActiveProcessHead", symbol) && !find(process, "PsActiveProcessHead", symbol))
            WinFail("SYMBOL_LOOKUP", "PsActiveProcessHead symbol unavailable");
        if (symbol->Address <= loaded || symbol->Address - loaded > 0x20000000ULL)
            Fail(Code::InvalidLayout, "SYMBOL_LOOKUP", "Unexpected symbol RVA");
        if (layout) {
            const auto type = Function<decltype(&SymGetTypeFromName)>(dbg.handle, "SymGetTypeFromName");
            const auto info = Function<decltype(&SymGetTypeInfo)>(dbg.handle, "SymGetTypeInfo");
            const auto module_info = Function<decltype(&SymGetModuleInfo64)>(dbg.handle, "SymGetModuleInfo64");
            const auto field = [&](const char* type_name, const wchar_t* field_name, u64 expected_size) -> u32 {
                alignas(SYMBOL_INFO) unsigned char type_storage[sizeof(SYMBOL_INFO) + MAX_SYM_NAME]{};
                auto* t = reinterpret_cast<SYMBOL_INFO*>(type_storage);
                t->SizeOfStruct = sizeof(SYMBOL_INFO); t->MaxNameLen = MAX_SYM_NAME;
                if (!type(process, loaded, type_name, t)) WinFail("SYMBOL_TYPE", "Required kernel type unavailable");
                ULONG64 type_length{};
                ULONG count{};
                if (!info(process, loaded, t->TypeIndex, TI_GET_LENGTH, &type_length)
                    || !info(process, loaded, t->TypeIndex, TI_GET_CHILDRENCOUNT, &count) || count > 4096)
                    Fail(Code::InvalidLayout, "SYMBOL_TYPE", "Invalid kernel type metadata");
                std::vector<ULONG> child_storage(2 + count);
                auto* children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(child_storage.data());
                children->Count = count; children->Start = 0;
                if (count && !info(process, loaded, t->TypeIndex, TI_FINDCHILDREN, children))
                    WinFail("SYMBOL_FIELDS", "Kernel fields unavailable");
                for (ULONG i = 0; i < count; ++i) {
                    WCHAR* name{};
                    if (!info(process, loaded, children->ChildId[i], TI_GET_SYMNAME, &name)) continue;
                    const bool matches = name && wcscmp(name, field_name) == 0;
                    LocalFree(name);
                    if (!matches) continue;
                    ULONG offset{}, field_type{}; ULONG64 length{};
                    if (!info(process, loaded, children->ChildId[i], TI_GET_OFFSET, &offset)
                        || !info(process, loaded, children->ChildId[i], TI_GET_TYPEID, &field_type)
                        || !info(process, loaded, field_type, TI_GET_LENGTH, &length)
                        || (expected_size && length != expected_size)
                        || offset > type_length || length > type_length - offset || offset > 0x10000)
                        Fail(Code::InvalidLayout, "SYMBOL_FIELD", "Invalid kernel field offset or width");
                    return offset;
                }
                Fail(Code::InvalidLayout, "SYMBOL_FIELD", "Required kernel field absent from matching PDB");
            };
            layout->head_rva = symbol->Address - loaded;
            layout->pid = field("_EPROCESS", L"UniqueProcessId", 8);
            layout->links = field("_EPROCESS", L"ActiveProcessLinks", 16);
            layout->image_base = field("_EPROCESS", L"SectionBaseAddress", 8);
            layout->cr3 = field("_EPROCESS", L"Pcb", 0) + field("_KPROCESS", L"DirectoryTableBase", 8);
            IMAGEHLP_MODULE64 module{}; module.SizeOfStruct = sizeof(module);
            if (!module_info(process, loaded, &module) || !module.TypeInfo
                || module.PdbUnmatched || module.DbgUnmatched || module.SymType != SymPdb
                || !module.ImageSize || layout->head_rva >= module.ImageSize)
                Fail(Code::InvalidLayout, "SYMBOL_MATCH", "Exact kernel PDB/type information unavailable");
            layout->kernel_timestamp = module.TimeDateStamp;
            layout->kernel_image_size = module.ImageSize;
        }
        return symbol->Address - loaded;
    }
    u64 QueryProcessHeadOffset() { return QueryProcessSymbols(nullptr); }
    ProcessImageLayout QueryProcessImageLayout() {
        ProcessImageLayout result;
        QueryProcessSymbols(&result);
        return result;
    }
}
