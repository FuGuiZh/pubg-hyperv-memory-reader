// Standalone entry migrated from Hyper_rw/dump.cpp. PE reconstruction is in pe_dump.cpp.
#include "monitor/monitor.hpp"
#include "app/pid_input.hpp"
#include "platform/windows/guest_memory.hpp"
#include "platform/windows/kernel_queries.hpp"
#include "platform/windows/process_identity.hpp"
#include "process_image.hpp"
#include "pe_dump.hpp"
#include "output_files.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace {
std::atomic_bool stopped{false};
struct TargetExitedError : std::runtime_error {
    TargetExitedError() : std::runtime_error("Target process exited during dump.") {}
};
dumper::ReadFailureKind FailureKind(GuestReadFailure::Reason reason) {
    using Reason = GuestReadFailure::Reason;
    using Kind = dumper::ReadFailureKind;
    switch (reason) {
    case Reason::InvalidArguments: return Kind::InvalidRange;
    case Reason::TranslationZero: return Kind::TranslationZero;
    case Reason::CopyShort: return Kind::CopyShort;
    case Reason::CopyOversized: return Kind::CopyOversized;
    case Reason::MappingChanged: return Kind::MappingChanged;
    case Reason::ChainUnavailable: return Kind::ChainUnavailable;
    default: return Kind::Unknown;
    }
}
const char* WalkOutcomeName(std::uint64_t status) {
    switch (status & 0xFF) {
    case 1: return "Success";
    case 2: return "NotPresent";
    case 3: return "TableMappingFailed";
    default: return "Unknown";
    }
}
const char* WalkLevelName(std::uint64_t status) {
    switch ((status >> 8) & 0xFF) {
    case 1: return "PT";
    case 2: return "PD";
    case 3: return "PDPT";
    case 4: return "PML4";
    default: return "Unknown";
    }
}
BOOL WINAPI StopHandler(DWORD event) {
    if (event != CTRL_C_EVENT && event != CTRL_BREAK_EVENT) return FALSE;
    stopped.store(true, std::memory_order_relaxed);
    return TRUE;
}
struct Options {
    std::uint32_t pid = 0;
    std::filesystem::path output_directory;
    bool help = false;
    bool warm_symbols = false;
};
Options ParseOptions(int argc, wchar_t** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg = argv[i];
        if (arg == L"--help" || arg == L"-h") options.help = true;
        else if (arg == L"--warm-symbols") options.warm_symbols = true;
        else if (arg == L"--pid") {
            throw std::runtime_error("--pid is no longer supported. Enter the PID at the startup prompt.");
        } else if (arg == L"--output") {
            if (++i == argc || !*argv[i]) throw std::runtime_error("--output requires a NEW directory path.");
            options.output_directory = argv[i];
        } else throw std::runtime_error("Unknown argument. Use --help for usage.");
    }
    return options;
}
std::filesystem::path ExecutableDirectory() {
    std::wstring path(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!n || n >= path.size()) throw std::runtime_error("Executable path unavailable.");
    path.resize(n);
    return std::filesystem::path(path).parent_path();
}
std::filesystem::path CreateOutputDirectory(const Options& options) {
    if (!options.output_directory.empty()) {
        const auto path = std::filesystem::absolute(options.output_directory);
        if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
        if (!std::filesystem::create_directory(path))
            throw std::runtime_error("Output directory already exists; choose a new directory.");
        return path;
    }
    const auto parent = ExecutableDirectory() / L"dumped-files";
    std::filesystem::create_directories(parent);
    return parent;
}
std::filesystem::path CreateStagingDirectory(const std::filesystem::path& parent, std::uint32_t pid) {
    SYSTEMTIME time{};
    GetLocalTime(&time);
    wchar_t name[128]{};
    swprintf_s(name, L"incomplete-%04u-%02u-%02u-%02u%02u%02u-pid%u",
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, pid);
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        const auto suffix = attempt ? L"-" + std::to_wstring(attempt) : std::wstring{};
        const auto path = parent / (std::wstring(name) + suffix);
        if (std::filesystem::create_directory(path)) return path;
    }
    throw std::runtime_error("Could not create a unique dump directory.");
}
void VerifyIdentity(const monitor::ProcessIdentity& expected) {
    const auto current = monitor::QueryProcessIdentity(expected.pid);
    if (!current) throw TargetExitedError{};
    if (current->sequence != expected.sequence
        || _wcsicmp(current->image.c_str(), expected.image.c_str()) != 0)
        throw std::runtime_error("Target PID was reused or the process identity changed during dump.");
}
}

int wmain(int argc, wchar_t** argv) {
    Options options;
    try { options = ParseOptions(argc, argv); }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 2; }
    if (options.help) {
        std::cout << "dumper - runtime PE export for offline analysis\n"
            "Usage: dumper.exe [--output <NEW directory>] [--warm-symbols] [--help]\n"
            "Enter the target PID at startup every time; q cancels. No default PID is stored.\n"
            "--warm-symbols prepares symbols and the hypervisor backend, then prints DUMPER_READY_FOR_PID.\n"
            "Dumps the selected process's main x86/x64 PE image; architecture is detected automatically.\n"
            "Default output: dumped-files/<process-name>-<file-version-with-hyphens>.exe beside dumper.exe\n"
            "Requires administrator privileges, matching hyper-reV and Windows SDK Debugging Tools x64.\n"
            "Ctrl+C stops the operation. Repeated file versions replace the existing EXE and information file.\n"
            "Exit codes: 0=complete copy; 3=partial copy with zero-filled holes; 2=error; 130=cancelled.\n"
            "The reconstructed PE is an analysis artifact, not a guaranteed runnable executable.\n";
        return 0;
    }
    try {
        monitor::ProcessImageLayout layout{};
        std::uint64_t kernel_base = 0;
        std::uint64_t head = 0;
        hypercall::Capabilities caps{};
        GuestMemory kernel_memory;
        auto kernel_deadline = monitor::Clock::now() + std::chrono::seconds(10);
        const dumper::ReadMemory kernel_read = [&](std::uint64_t address, void* out, std::size_t size) {
            if (stopped.load()) throw std::runtime_error("Dump cancelled.");
            if (monitor::Clock::now() >= kernel_deadline) throw std::runtime_error("Kernel metadata query timed out.");
            return kernel_memory.ReadVirtual(address, out, size) == size;
        };
        const auto prepare_backend = [&] {
            layout = monitor::QueryProcessImageLayout();
            kernel_base = monitor::QueryKernelBase();
            if (!kernel_base)
                throw std::runtime_error("Kernel image address is hidden/unavailable. Run dumper as administrator with kernel-address query privileges.");
            head = monitor::Add(kernel_base, layout.head_rva, "PROCESS_HEAD");
            caps = hypercall::diagnostic_capabilities();
            if (!caps.version) throw std::runtime_error("Compatible hyper-reV backend unavailable.");
            kernel_memory.set_default_cr3(hypercall::read_guest_cr3());
            kernel_deadline = monitor::Clock::now() + std::chrono::seconds(10);
            dumper::VerifyKernelImage(kernel_read, kernel_base, layout);
        };
        if (options.warm_symbols) {
            prepare_backend();
            std::cout << "DUMPER_READY_FOR_PID\n" << std::flush;
        }
        const auto pid = app::PromptForPid(std::cin, std::cout, "target process");
        if (!pid) return 130;
        options.pid = *pid;
        const auto identity = monitor::QueryProcessIdentity(options.pid);
        if (!identity)
            throw std::runtime_error("No process with the entered PID was found. Enter its current PID.");
        dumper::ValidateImageName(identity->image);
        std::wcout << L"Target process: " << identity->image << L'\n';
        if (!SetConsoleCtrlHandler(StopHandler, TRUE)) throw std::runtime_error("Could not install Ctrl+C handler.");
        struct HandlerGuard { ~HandlerGuard() { SetConsoleCtrlHandler(StopHandler, FALSE); } } handler;
        if (!options.warm_symbols) prepare_backend();
        if (stopped.load()) return 130;
        const auto lookup_started = monitor::Clock::now();
        kernel_deadline = lookup_started + std::chrono::seconds(10);
        const auto image = dumper::FindProcessImage(kernel_read, head, options.pid, layout);
        const auto cr3 = image.cr3, base = image.base;
        const auto verify_target = [&] {
            kernel_deadline = monitor::Clock::now() + std::chrono::seconds(2);
            VerifyIdentity(*identity);
            for (unsigned attempt = 0; attempt < 5; ++attempt) {
                try {
                    dumper::VerifyProcessImage(kernel_read, image, layout);
                    break;
                } catch (const dumper::IncompleteKernelMetadataError&) {
                    VerifyIdentity(*identity); // Distinguish natural exit from a transient read.
                    if (attempt == 4) throw;
                    Sleep(2);
                } catch (...) {
                    VerifyIdentity(*identity);
                    throw;
                }
            }
            VerifyIdentity(*identity);
        };
        verify_target();
        const auto lookup_completed = monitor::Clock::now();
        GuestMemory memory(cr3);
        memory.set_diagnostics_version(caps.version);
        std::cout << "PID=" << options.pid << " process_sequence=0x" << std::hex << identity->sequence
            << " CR3=0x" << cr3 << " EPROCESS=0x" << image.process << " base=0x" << base << std::dec
            << " backend=v" << caps.version << " base_source=EPROCESS.SectionBaseAddress\n";
        const auto directory = CreateOutputDirectory(options);
        std::wcout << L"Output directory: " << directory.wstring() << L'\n';
        const auto staging = CreateStagingDirectory(directory, options.pid);
        std::wcout << L"Staging directory (retained on failure): " << staging.wstring() << L'\n';
        auto next_identity = monitor::Clock::now() + std::chrono::seconds(1);
        bool target_exited = false;
        const dumper::ReadMemory read = [&](std::uint64_t address, void* out, std::size_t size)
            -> dumper::ReadResult {
            if (stopped.load(std::memory_order_relaxed)) throw std::runtime_error("Dump cancelled.");
            if (target_exited) return dumper::ReadResult{dumper::ReadState::TargetExited};
            if (monitor::Clock::now() >= next_identity) {
                try { verify_target(); }
                catch (const TargetExitedError&) {
                    target_exited = true;
                    return dumper::ReadResult{dumper::ReadState::TargetExited};
                }
                next_identity = monitor::Clock::now() + std::chrono::seconds(1);
            }
            if (!monitor::UserRange(address, size))
                return dumper::ReadResult{dumper::ReadState::Incomplete,
                    dumper::ReadFailureKind::InvalidRange};
            const auto copied = memory.ReadVirtual(address, out, size);
            if (copied == size) return true;
            GuestReadFailure failure{};
            const auto checked = memory.ReadVirtual(address, out, size, &failure);
            if (checked == size) return true;
            if (!copied && !checked
                && failure.reason == GuestReadFailure::Reason::TranslationZero)
                return dumper::ReadResult{dumper::ReadState::PageUnavailable,
                    dumper::ReadFailureKind::TranslationZero};
            return dumper::ReadResult{dumper::ReadState::Incomplete,
                FailureKind(failure.reason)};
        };
        dumper::DumpSummary summary;
        const auto staged_image = staging / L"image-pending.exe";
        const auto capture_started = monitor::Clock::now();
        const bool saved = dumper::DumpProcessMemory(read, base, staged_image, &summary);
        const auto capture_completed = monitor::Clock::now();
        std::cout << "TimingMs ProcessLookup="
            << std::chrono::duration_cast<std::chrono::milliseconds>(lookup_completed - lookup_started).count()
            << " ImageCapture="
            << std::chrono::duration_cast<std::chrono::milliseconds>(capture_completed - capture_started).count()
            << '\n';
        if (!saved) { std::cerr << "DUMP FAILED. No complete export was produced.\n"; return 2; }
        bool exited_after_capture = false;
        if (summary.target_exited) {
            const auto current = monitor::QueryProcessIdentity(identity->pid);
            if (current && (current->sequence != identity->sequence
                || _wcsicmp(current->image.c_str(), identity->image.c_str()) != 0))
                throw std::runtime_error("Target PID was reused after exit; refusing partial publication.");
        } else {
            try { verify_target(); }
            catch (const TargetExitedError&) { exited_after_capture = true; }
        }
        std::string page_walk_status = "NoTranslationSamples";
        std::ostringstream page_walks;
        if (!summary.walk_samples.empty()) {
            if (summary.target_exited || exited_after_capture) {
                page_walk_status = "TargetExited";
            } else if (caps.version < 3) {
                page_walk_status = "BackendV3Required";
            } else {
                for (const auto& sample : summary.walk_samples) {
                    const auto walk = hypercall::translate_chain(sample.address, cr3);
                    page_walks << "PageWalkRVA=0x" << std::hex << std::uppercase
                        << (sample.address - base) << std::dec;
                    if (!walk.valid) {
                        page_walks << ",Status:Unavailable\n";
                        continue;
                    }
                    const auto& terminal = walk.chain.entries[walk.chain.count - 1];
                    page_walks << ",Outcome:" << WalkOutcomeName(terminal.status)
                        << ",Level:" << WalkLevelName(terminal.status)
                        << ",Entry:0x" << std::hex << std::uppercase << terminal.entry << std::dec << '\n';
                }
                try {
                    const auto current = monitor::QueryProcessIdentity(identity->pid);
                    page_walk_status = current && current->sequence == identity->sequence
                        && _wcsicmp(current->image.c_str(), identity->image.c_str()) == 0
                        ? "VerifiedAfterSamples" : "TargetExitedOrChanged";
                } catch (...) {
                    page_walk_status = "IdentityUnavailableAfterSamples";
                }
            }
        }
        auto staged_info = staged_image;
        staged_info += L".info.txt";
        {
            std::ofstream info(staged_info, std::ios::app);
            info << "PostCaptureIdentity="
                 << (summary.target_exited ? "ExitedDuringCapture"
                     : exited_after_capture ? "ExitedAfterCapture" : "Verified") << '\n';
            info << "PageWalkPhase=PostCapture\n"
                 << "PageWalkStatus=" << page_walk_status << '\n';
            if (page_walk_status == "VerifiedAfterSamples") info << page_walks.str();
            if (!info) throw std::runtime_error("Could not record post-capture process identity.");
        }
        const auto output = dumper::PublishDump(staged_image, directory, identity->image);
        std::error_code cleanup_error;
        std::filesystem::remove(staging, cleanup_error); // Empty directory only; never recursive.
        std::wcout << L"Saved EXE: " << output.wstring() << L'\n';
        if (summary.unreadable || summary.target_exited) {
            std::cout << "PARTIAL DUMP: " << summary.unreadable << " unreadable bytes are zero placeholders."
                << (summary.target_exited ? " Target exited before final header verification." : "") << '\n';
            return 3;
        }
        std::cout << "DUMP COMPLETE: all requested section bytes copied.\n";
        return 0;
    } catch (const monitor::Fault& e) {
        std::cerr << e.issue().stage << ": " << e.what();
        if (e.issue().native_error) std::cerr << " (native error " << *e.issue().native_error << ')';
        std::cerr << '\n';
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; }
    return stopped.load() ? 130 : 2;
}
