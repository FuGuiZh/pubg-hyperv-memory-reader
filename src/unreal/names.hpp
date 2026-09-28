#pragma once
#include "monitor/monitor.hpp"
#include "arch/x64/resolver.hpp"

namespace monitor::unreal {
u32 DecodeNameIndex(u32 raw) noexcept;
u32 DecodeNameNumber(u32 raw) noexcept;

// One resolver per bounded capture. All roots, links, object identity and code
// are checked before returning a publishable name. No remote code is executed.
class NameResolver {
public:
    NameResolver(Reader& memory, FrameResolver& cipher, u64 base, std::vector<std::string>* trace=nullptr)
        : memory_(memory), cipher_(cipher), base_(base), trace_(trace) {}
    void ReadObject(u64 object, ObjectName& output, std::size_t max_units=1024);
private:
    Reader& memory_;
    FrameResolver& cipher_;
    u64 base_;
    std::vector<std::string>* trace_;
};
// Optional World-name telemetry. Rejected core frames acquire a fresh root and
// independently check its context. Success never authorizes player positions.
void CaptureWorldName(IBytes& backend, Snapshot& frame, const Config& config, const std::atomic_bool& stop);
}
