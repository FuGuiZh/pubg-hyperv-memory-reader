#include "monitor/monitor.hpp"
#include "platform/windows/kernel_queries.hpp"
// ============================================================================
// Original GuestMemory adapter; explicit PID only
// ============================================================================
#include <algorithm>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "platform/windows/process_lookup.hpp"
#include "platform/windows/process_identity.hpp"
#include "platform/windows/guest_memory.hpp"
#include "platform/windows/read_diagnostics.hpp"
#include "platform/windows/module_lookup.hpp"

namespace monitor {
    namespace {
        void VerifyIdentity(u32 pid, u64 sequence, const char* stage) {
            const auto identity = QueryProcessIdentity(pid);
            if (!identity) Fail(Code::ProcessExited, stage, "Process no longer present in system process list");
            if (identity->sequence != sequence || _wcsicmp(identity->image.c_str(), L"TslGame.exe") != 0)
                Fail(Code::SessionChanged, stage, "Process identity changed");
        }
        class GuestBackend final : public IBackend {
        public:
            Session Attach(const Config& c, const std::atomic_bool& stop) override {
                Detach();
                if (stop.load()) Fail(Code::Cancelled, "ATTACH", "Stop requested");
                const u32 pid = c.requested_pid;
                if (!pid) Fail(Code::NoProcess, "PID_CONFIG",
                    "Enter a nonzero PID at startup.");
                const auto identity = QueryProcessIdentity(pid);
                if (!identity) Fail(Code::NoProcess, "PROCESS_LIST", "Entered PID is not running. Restart and enter the current PID.");
                const u64 sequence = identity->sequence;
                if (_wcsicmp(identity->image.c_str(), L"TslGame.exe") != 0)
                    Fail(Code::SessionChanged, "PROCESS_IMAGE",
                        "Entered PID does not identify TslGame.exe. Restart and enter its current PID.");
                if (pinned_sequence_ && (pid != pinned_pid_ || sequence != pinned_sequence_))
                    Fail(Code::SessionChanged, "PROCESS_INSTANCE",
                        "The PID now belongs to a different process instance. Restart and enter the current PID.");
                if (!kernel_) kernel_ = QueryKernelBase();
                if (!head_offset_) head_offset_ = QueryProcessHeadOffset();
                if (stop.load()) Fail(Code::Cancelled, "ATTACH", "Stop requested");
                const u64 head = Add(kernel_, head_offset_, "PROCESS_HEAD");
                Cr3LookupDiagnostics lookup{};
                const u64 cr3 = ::GetProcessCr3(pid, head, &lookup);
                if (!cr3) Fail(Code::BackendUnavailable, lookup.stage,
                    DescribeCr3Lookup(lookup) + " kernel=" + Hex(kernel_) + " head_rva=" + Hex(head_offset_),
                    lookup.address, static_cast<std::size_t>(lookup.requested));
                const u64 peb = ::FindPebByCr3_Raw(cr3, head);
                if (!peb) Fail(Code::BackendUnavailable, "PEB_LOOKUP", "Existing FindPebByCr3_Raw returned zero");
                VerifyIdentity(pid, sequence, "ATTACH_RECHECK");
                mem.set_default_cr3(cr3);
                capabilities_ = hypercall::diagnostic_capabilities();
                mem.set_diagnostics_version(capabilities_.version);
                read_ready_ = true; // Provisional transport only; the session is not yet attached.
                try {
                    Reader r(*this, Budget{ &stop,Clock::now() + std::chrono::seconds(3) }, c.read_attempts);
                    const auto module=FindModuleChecked(r,peb,"TslGame.exe");
                    const u64 base=module.base;
                    const auto dos = r.Value<IMAGE_DOS_HEADER>(base, "IMAGE_DOS_READ");
                    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0x40 || dos.e_lfanew>0x100000)
                        Fail(Code::ImageMismatch, "IMAGE_DOS_VALIDATE", "Not an expected PE DOS header", base);
                    const auto nt = r.Value<IMAGE_NT_HEADERS64>(Add(base, u64(dos.e_lfanew), "IMAGE_NT_READ"), "IMAGE_NT_READ");
                    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
                        || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                        Fail(Code::ImageMismatch, "IMAGE_NT_VALIDATE", "Not a PE32+ AMD64 image", base);
                    if (nt.OptionalHeader.SizeOfImage < Offset::UWorld + 8 || nt.OptionalHeader.SizeOfImage>0x80000000U)
                        Fail(Code::ImageMismatch, "IMAGE_RVA_VALIDATE", "Required RVA is outside the declared image", base);
                    if (c.verify_expected_image && (nt.FileHeader.TimeDateStamp != c.expected_timestamp
                        || nt.OptionalHeader.SizeOfImage != c.expected_image_size)) {
                        Fail(Code::ImageMismatch, "IMAGE_FINGERPRINT", "Observed timestamp=" + Hex(nt.FileHeader.TimeDateStamp)
                            + " size=" + Hex(nt.OptionalHeader.SizeOfImage) + "; confirm exact build before changing config", base);
                    }
                    module.Verify(r);
                    VerifyIdentity(pid, sequence, "ATTACH_RECHECK");
                    // Pin the first successfully validated process instance for this tool run.
                    // Detach() retains this identity: recovery must not silently switch targets.
                    if (!pinned_sequence_) { pinned_pid_ = pid; pinned_sequence_ = sequence; }
                    session_ = Session{ pid,sequence,cr3,peb,base,++generation_,nt.OptionalHeader.SizeOfImage,nt.FileHeader.TimeDateStamp };
                    bound_=true;
                    return session_;
                }
                catch (const Fault& error) {
                    bound_=read_ready_=false;
                    auto issue=error.issue();
                    issue.detail+="; attach CR3="+Hex(cr3)+" PEB="+Hex(peb);
                    throw Fault(std::move(issue));
                }
                catch (...) { bound_=read_ready_=false; throw; }
            }
            bool Alive() override {
                if (!bound_) return false;
                const auto identity = QueryProcessIdentity(session_.pid);
                return identity && identity->sequence == session_.process_sequence
                    && _wcsicmp(identity->image.c_str(), L"TslGame.exe") == 0;
            }
            std::optional<u64> QueryAddressSpace(const Budget& budget) override {
                if (!bound_) return std::nullopt;
                budget.Check("ADDRESS_SPACE_PROBE");
                VerifyIdentity(session_.pid, session_.process_sequence, "ADDRESS_SPACE_IDENTITY");
                budget.Check("ADDRESS_SPACE_PROBE");
                const auto observed = ::ProbeProcessCr3(session_.pid,
                    Add(kernel_, head_offset_, "PROCESS_HEAD"), budget.stop, budget.deadline);
                budget.Check("ADDRESS_SPACE_PROBE");
                if (!observed) return std::nullopt;
                VerifyIdentity(session_.pid, session_.process_sequence, "ADDRESS_SPACE_RECHECK");
                budget.Check("ADDRESS_SPACE_PROBE");
                // Attach separately validates PEB, module and PE fingerprint before use.
                return observed;
            }
            void Detach() noexcept override {
                bound_ = read_ready_ = false; session_ = {}; mem.set_default_cr3(0);
                diagnostics_.ResetHistory(); capabilities_ = {}; mem.set_diagnostics_version(0);
            }
            void BeginDiagnostics(u64 frame) override { diagnostics_.Begin(frame); }
            void ReadContext(const char* stage, unsigned attempt) override { diagnostics_.Context(stage, attempt); }
            std::string DrainDiagnostics() override { return diagnostics_.Drain(); }
            bool ExtendedDiagnostics() const noexcept override { return capabilities_.version != 0; }
            unsigned DiagnosticsVersion() const noexcept override { return capabilities_.version; }
            u64 DiagnosticBuildStamp() const noexcept override { return capabilities_.build_stamp; }
            Transfer Read(u64 address, void* output, std::size_t bytes) override {
                if (!read_ready_ || (!output && bytes) || !UserRange(address, bytes)) return {};
                return ReadGuestBytes(mem, diagnostics_, address, output, bytes);
            }
        private:
            Session session_;
            u64 kernel_ = 0, head_offset_ = 0, generation_ = 0;
            u32 pinned_pid_ = 0;
            u64 pinned_sequence_ = 0;
            bool bound_ = false, read_ready_ = false;
            GuestMemory mem;
            ReadDiagnostics diagnostics_;
            hypercall::Capabilities capabilities_;
        };
    }
    std::unique_ptr<IBackend> MakeGuestBackend() { return std::make_unique<GuestBackend>(); }
}
