#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <vector>

namespace dumper {
enum class ReadState { Complete, Incomplete, PageUnavailable, TargetExited };
enum class ReadFailureKind {
    None, InvalidRange, TranslationZero, CopyShort, CopyOversized,
    MappingChanged, ChainUnavailable, Unknown
};
struct ReadResult {
    ReadState state = ReadState::Incomplete;
    ReadFailureKind failure = ReadFailureKind::Unknown;
    ReadResult() = default;
    ReadResult(bool complete) : state(complete ? ReadState::Complete : ReadState::Incomplete),
        failure(complete ? ReadFailureKind::None : ReadFailureKind::Unknown) {}
    explicit ReadResult(ReadState value, ReadFailureKind kind = ReadFailureKind::Unknown)
        : state(value), failure(kind) {}
    explicit operator bool() const { return state == ReadState::Complete; }
};
// A read is complete only when every requested byte was copied. PageUnavailable
// means address translation failed for the current page; TargetExited is sticky.
using ReadMemory = std::function<ReadResult(std::uint64_t, void*, std::size_t)>;
struct FailureSample {
    std::uint64_t address = 0;
    ReadFailureKind kind = ReadFailureKind::Unknown;
};
struct DumpSummary {
    std::uint64_t requested = 0, copied = 0, unreadable = 0;
    bool target_exited = false;
    bool final_headers_verified = false;
    std::vector<FailureSample> walk_samples; // At most one failed page per section.
};
// Returns true when the PE and sidecar were saved. Inspect unreadable separately:
// missing runtime bytes are zero placeholders, not observed zero-valued memory.
bool DumpProcessMemory(const ReadMemory& memory, std::uint64_t base_address,
    const std::filesystem::path& output_filename, DumpSummary* summary = nullptr);
}
