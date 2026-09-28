#pragma once
#include "hypervisor/hypercall.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

struct GuestCallEvidence {
    hypercall::Result result{};
    PROCESSOR_NUMBER before{}, after{};
    bool invoked = false;
    hypercall_walk::Chain chain{};
    std::uint64_t chain_bytes = 0;
    bool chain_requested = false, chain_valid = false;
};
struct GuestReadFailure {
    enum class Reason { None, InvalidArguments, TranslationZero, CopyShort, CopyOversized, MappingChanged, ChainUnavailable };
    Reason reason = Reason::None;
    std::uint64_t va = 0, target_cr3 = 0, destination_va = 0;
    std::size_t requested = 0;
    GuestCallEvidence translation, copy, post_translation;
    enum class Consistency { NotChecked, Unavailable, SameObserved, EntryBitsChanged, MappingChanged };
    Consistency consistency = Consistency::NotChecked;
    std::uint64_t entry_change_mask = 0, mapping_change_mask = 0;
};

// Read-only subset of the original GuestMemory adapter by wz5200.
// Upstream notices are retained in docs/upstream/README.md.
class GuestMemory {
public:
    explicit GuestMemory(std::uint64_t cr3 = 0) : default_cr3_(cr3) {}

    void set_default_cr3(std::uint64_t cr3) { default_cr3_ = cr3; }
    void set_diagnostics_supported(bool supported) { diagnostics_version_ = supported ? 1 : 0; }
    void set_diagnostics_version(unsigned version) { diagnostics_version_ = version; }

    std::size_t ReadVirtual(std::uint64_t address, void* buffer, std::size_t size, GuestReadFailure* failure = nullptr, bool detailed = false) {
        if (failure) *failure = {};
        if (!buffer || !default_cr3_ || !hypercall_walk::IsCanonicalRange48(address, size)) {
            if (failure) {
                failure->reason = GuestReadFailure::Reason::InvalidArguments;
                failure->va = address; failure->target_cr3 = default_cr3_; failure->requested = size;
            }
            return 0;
        }
        constexpr std::size_t page_size = 0x1000;
        auto* output = static_cast<std::uint8_t*>(buffer);
        std::size_t total = 0;
        while (total < size) {
            const auto current = address + total;
            const auto page_offset = static_cast<std::size_t>(current & (page_size - 1));
            const auto count = std::min(size - total, page_size - page_offset);
            GuestReadFailure evidence;
            evidence.va = current; evidence.target_cr3 = default_cr3_;
            evidence.destination_va = reinterpret_cast<std::uint64_t>(output + total);
            evidence.requested = count;
            auto& translation = evidence.translation;
            translation.invoked = true;
            if (failure) GetCurrentProcessorNumberEx(&translation.before);
            const bool chain = failure && detailed && diagnostics_version_ >= 3;
            if (chain) CaptureChain(translation, current);
            else if (failure && diagnostics_version_) translation.result = hypercall::translate_diagnostic(current, default_cr3_, diagnostics_version_ >= 2);
            else translation.result.value = hypercall::translate_guest_virtual_address(current, default_cr3_);
            if (failure) GetCurrentProcessorNumberEx(&translation.after);
            if (chain && !translation.chain_valid) {
                evidence.consistency = GuestReadFailure::Consistency::Unavailable;
                evidence.reason = GuestReadFailure::Reason::ChainUnavailable;
                *failure = evidence;
                break;
            }
            const auto physical = translation.result.value;
            if (!physical) {
                evidence.reason = GuestReadFailure::Reason::TranslationZero;
                if (failure) *failure = evidence;
                break;
            }
            auto& copy = evidence.copy;
            copy.invoked = true;
            if (failure) GetCurrentProcessorNumberEx(&copy.before);
            if (failure && diagnostics_version_) copy.result = hypercall::read_physical_diagnostic(output + total, physical, count);
            else copy.result.value = hypercall::read_guest_physical_memory(output + total, physical, count);
            if (failure) GetCurrentProcessorNumberEx(&copy.after);
            const auto received = copy.result.value;
            if (chain) {
                auto& post = evidence.post_translation;
                post.invoked = true;
                GetCurrentProcessorNumberEx(&post.before);
                CaptureChain(post, current);
                GetCurrentProcessorNumberEx(&post.after);
                evidence.consistency = GuestReadFailure::Consistency::Unavailable;
                if (translation.chain_valid && post.chain_valid && copy.result.marker == hypercall::diagnostic_marker) {
                    const auto difference = hypercall_walk::Compare(translation.chain, post.chain);
                    evidence.entry_change_mask = difference.raw_mask;
                    evidence.mapping_change_mask = difference.mapping_mask;
                    const bool context_changed = translation.result.saved_slat != post.result.saved_slat
                        || translation.result.active_slat != post.result.active_slat
                        || translation.result.saved_slat != copy.result.saved_slat
                        || translation.result.active_slat != copy.result.active_slat;
                    evidence.consistency = (difference.mapping_mask || context_changed || translation.result.value != post.result.value)
                        ? GuestReadFailure::Consistency::MappingChanged : difference.raw_mask
                        ? GuestReadFailure::Consistency::EntryBitsChanged : GuestReadFailure::Consistency::SameObserved;
                }
            }
            if (received != count) {
                evidence.reason = received > count ? GuestReadFailure::Reason::CopyOversized : GuestReadFailure::Reason::CopyShort;
            }
            else if (evidence.consistency == GuestReadFailure::Consistency::MappingChanged)
                evidence.reason = GuestReadFailure::Reason::MappingChanged;
            else if (evidence.consistency == GuestReadFailure::Consistency::Unavailable)
                evidence.reason = GuestReadFailure::Reason::ChainUnavailable;
            if (failure) *failure = evidence; // Retain the last subrequest on success as well.
            // A copied buffer is not a successful read when its checked mapping
            // changed or could not be verified. ReadValue discards these bytes.
            if (evidence.reason == GuestReadFailure::Reason::MappingChanged
                || evidence.reason == GuestReadFailure::Reason::ChainUnavailable) break;
            if (received > count) break;
            total += received;
            if (received != count) break;
        }
        return total;
    }

    template<class T>
    bool ReadValue(std::uint64_t address, T& value, GuestReadFailure* failure = nullptr, bool detailed = false) {
        static_assert(std::is_trivially_copyable_v<T> && !std::is_pointer_v<T>,
                      "ReadValue requires a trivially copyable non-pointer type");
        std::uint8_t bytes[sizeof(T)]{};
        if (ReadVirtual(address, bytes, sizeof(T), failure, detailed) != sizeof(T)) {
            value = T{};
            return false;
        }
        std::memcpy(&value, bytes, sizeof(T));
        return true;
    }

private:
    void CaptureChain(GuestCallEvidence& evidence, std::uint64_t address) {
        const auto capture = hypercall::translate_chain(address, default_cr3_);
        evidence.result = capture.result;
        evidence.chain_requested = true;
        evidence.chain_bytes = capture.bytes_written;
        evidence.chain_valid = capture.valid;
        if (capture.valid) evidence.chain = capture.chain;
    }
    std::uint64_t default_cr3_ = 0;
    unsigned diagnostics_version_ = 0;
};
