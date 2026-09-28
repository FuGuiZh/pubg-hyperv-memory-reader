#include "monitor/monitor.hpp"

// ============================================================================
// CORE implementation
// ============================================================================
#include <algorithm>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace monitor {
const char* CodeName(Code c) noexcept {
#define ITEM(x) case Code::x: return #x
    switch (c) {
    ITEM(None); ITEM(Cancelled); ITEM(Deadline); ITEM(ReadFailed); ITEM(InvalidAddress);
    ITEM(InvalidLayout); ITEM(NullObject); ITEM(NoProcess); ITEM(MultipleProcesses);
    ITEM(ProcessExited); ITEM(IdentityUnavailable); ITEM(SessionChanged); ITEM(ImageMismatch);
    ITEM(BackendUnavailable); ITEM(UnsupportedInstruction); ITEM(UnsupportedPrefix);
    ITEM(UnknownRegister); ITEM(CodeChanged); ITEM(SnapshotChanged); ITEM(InstructionLimit);
    ITEM(NoReference); ITEM(InternalError);
    }
#undef ITEM
    return "Unknown";
}
std::string Hex(u64 x) {
    std::ostringstream o;
    o << "0x" << std::hex << std::uppercase << std::setw(16) << std::setfill('0') << x;
    return o.str();
}
std::string Describe(const Issue& x) {
    if (!x) return "OK";
    std::ostringstream o;
    o << '[' << x.stage << "] " << CodeName(x.code) << ": " << x.detail;
    if (x.address) o << " address=" << Hex(x.address);
    if (x.bytes) o << " bytes=" << x.bytes;
    if (x.attempts) o << " attempts=" << x.attempts;
    if (x.native_error) o << " native=" << *x.native_error;
    return o.str();
}
void Reader::Bytes(u64 address, void* output, std::size_t bytes, const char* stage) {
    budget_.Check(stage);
    if (!bytes) return;
    if (!output || !UserRange(address, bytes))
        Fail(Code::InvalidAddress, stage, "Invalid output pointer or user-address range", address, bytes);
    // A failed multi-chunk read must never publish a partially assembled object.
    std::array<u8, 256> local{};
    std::vector<u8> large;
    u8* temporary = local.data();
    if (bytes > local.size()) { large.resize(bytes); temporary = large.data(); }
    Transfer last;
    auto& stats=stats_[stage ? stage : "UNSPECIFIED"];
    for (unsigned attempt = 1; attempt <= attempts_; ++attempt) {
        budget_.Check(stage);
        std::fill_n(temporary, bytes, u8(0));
        ++calls_; ++stats.attempts;
        backend_.ReadContext(stage, attempt);
        last = backend_.Read(address, temporary, bytes);
        if (last.ok && last.bytes == bytes) {
            budget_.Check(stage);
            std::memcpy(output, temporary, bytes);
            return;
        }
        ++failed_; ++stats.failed_attempts;
        if (!stats.first_failed_address) {
            stats.first_failed_address=address;
            stats.first_requested_bytes=bytes;
        }
    }
    ++stats.exhausted_requests;
    throw Fault(Issue{Code::ReadFailed, stage,
        "Backend did not return the complete requested range; received="+std::to_string(last.bytes)
            +" requested="+std::to_string(bytes)+" backend_ok="+std::to_string(last.ok)
            +"; see transport.log for original call evidence",
        address, bytes, attempts_, last.native_error});
}
std::string ArrayHeaderText(const ArrayHeader& a) {
    return "{Data="+Hex(a.data)+" Num="+std::to_string(a.num)+" Max="+std::to_string(a.max)+"}";
}
void ValidateArray(const ArrayHeader& a, i32 limit, const char* stage) {
    if (a.num < 0 || a.max < 0 || a.num > a.max || a.num > limit)
        Fail(Code::InvalidLayout, stage, "Array counts outside the checked layout/budget");
    if (a.num > 0 && !UserRange(a.data, static_cast<std::size_t>(a.num) * sizeof(u64)))
        Fail(Code::InvalidAddress, stage, "Nonempty array has an invalid element range", a.data);
}
std::vector<u64> ArrayValues(Reader& m, u64 at, i32 limit, const char* stage, ArrayHeader* observed) {
    const auto before = m.Value<ArrayHeader>(at, stage);
    ValidateArray(before, limit, stage);
    if (observed) *observed=before; // Diagnostic evidence, even when this attempt is rejected.
    std::vector<u64> values(static_cast<std::size_t>(before.num));
    if (!values.empty()) m.Bytes(before.data, values.data(), values.size() * sizeof(u64), stage);
    const auto after = m.Value<ArrayHeader>(at, stage);
    if (!(before == after)) Fail(Code::SnapshotChanged, stage,
        "Array header changed during copy; before="+ArrayHeaderText(before)+" after="+ArrayHeaderText(after), at, sizeof(ArrayHeader));
    if (observed) *observed = before;
    return values; // Header reread detects some races, not an atomic target snapshot.
}
bool ValidPosition(const Vec3& v) noexcept {
    constexpr float bound = 50000000.0f;
    return std::isfinite(v.x) && std::isfinite(v.y) && std::isfinite(v.z)
        && std::fabs(v.x) < bound && std::fabs(v.y) < bound && std::fabs(v.z) < bound;
}
double Distance2D(const Vec3& a, const Vec3& b) noexcept {
    return std::hypot(double(a.x)-b.x, double(a.y)-b.y);
}
double Distance3D(const Vec3& a, const Vec3& b) noexcept {
    return std::hypot(std::hypot(double(a.x)-b.x, double(a.y)-b.y), double(a.z)-b.z);
}
}
