#include "hypervisor/hypercall.hpp"
#include "hypervisor/protocol.hpp"

extern "C" std::uint64_t launch_raw_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9);
extern "C" void launch_diagnostic_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9, hypercall::Result* result);
extern "C" void launch_walk_hypercall(hypercall_info_t rcx, std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9, hypercall::Result* result);

static hypercall::Result DiagnosticCall(hypercall_type_t type, std::uint64_t a, std::uint64_t b, std::uint64_t c, bool walk = false, bool chain = false) {
    hypercall_info_t info{};
    info.primary_key = hypercall_primary_key;
    info.secondary_key = hypercall_secondary_key;
    info.call_type = type;
    info.call_reserved_data = 2 | (walk ? hypercall_walk::request_flag : 0) | (chain ? hypercall_walk::chain_request_flag : 0);
    hypercall::Result result;
    if (walk) launch_walk_hypercall(info, a, b, c, &result);
    else launch_diagnostic_hypercall(info, a, b, c, &result);
    return result;
}
hypercall::Capabilities hypercall::diagnostic_capabilities() {
    const auto result = DiagnosticCall(hypercall_type_t::diagnostic_capabilities, 0, 0, 0, true, true);
    if (result.value != diagnostic_marker || result.marker != diagnostic_marker) return {};
    if (result.walk.status == hypercall_walk::chain_capability) return {3, result.walk.entry};
    if (result.walk.status == hypercall_walk::capability) return {2, result.walk.entry};
    return {1, 0};
}
bool hypercall::diagnostics_supported() { return diagnostic_capabilities().version != 0; }
hypercall::Result hypercall::translate_diagnostic(std::uint64_t address, std::uint64_t cr3, bool walk) {
    if (!hypercall_walk::IsCanonical48(address)) return {};
    return DiagnosticCall(hypercall_type_t::translate_guest_virtual_address, address, cr3, 0, walk);
}
hypercall::ChainResult hypercall::translate_chain(std::uint64_t address, std::uint64_t cr3) {
    ChainResult capture{}; // Touch the entire destination before the hypervisor writes it.
    if (!hypercall_walk::IsCanonical48(address)) return capture;
    capture.result = DiagnosticCall(hypercall_type_t::diagnostic_page_chain, address, cr3,
        reinterpret_cast<std::uint64_t>(&capture.chain), true, true);
    const auto acknowledgement = capture.result.walk;
    capture.bytes_written = acknowledgement.entry;
    capture.valid = capture.result.marker == diagnostic_marker
        && acknowledgement.status == hypercall_walk::chain_capability
        && acknowledgement.entry == sizeof(capture.chain)
        && acknowledgement.entry_gpa == address && acknowledgement.entry_hpa == cr3
        && capture.chain.va == address && capture.chain.cr3 == cr3
        && capture.chain.physical == capture.result.value && hypercall_walk::ValidChain(capture.chain);
    capture.result.walk = capture.valid ? capture.chain.entries[capture.chain.count - 1] : hypercall_walk::Evidence{};
    return capture;
}
hypercall::Result hypercall::read_physical_diagnostic(void* output, std::uint64_t address, std::uint64_t size) {
    return DiagnosticCall(hypercall_type_t::guest_physical_memory_operation, address, reinterpret_cast<std::uint64_t>(output), size);
}

std::uint64_t make_hypercall(hypercall_type_t call_type, std::uint64_t call_reserved_data, std::uint64_t rdx, std::uint64_t r8, std::uint64_t r9)
{
	hypercall_info_t hypercall_info = { };

	hypercall_info.primary_key = hypercall_primary_key;
	hypercall_info.secondary_key = hypercall_secondary_key;
	hypercall_info.call_type = call_type;
	hypercall_info.call_reserved_data = call_reserved_data;

	return launch_raw_hypercall(hypercall_info, rdx, r8, r9);
}

std::uint64_t hypercall::read_guest_physical_memory(void* guest_destination_buffer, std::uint64_t guest_source_physical_address, std::uint64_t size)
{
	hypercall_type_t call_type = hypercall_type_t::guest_physical_memory_operation;

	std::uint64_t call_data = static_cast<std::uint64_t>(memory_operation_t::read_operation);

	std::uint64_t guest_destination_virtual_address = reinterpret_cast<std::uint64_t>(guest_destination_buffer);

	return make_hypercall(call_type, call_data, guest_source_physical_address, guest_destination_virtual_address, size);
}

std::uint64_t hypercall::read_guest_virtual_memory(void* guest_destination_buffer, std::uint64_t guest_source_virtual_address, std::uint64_t source_cr3, std::uint64_t size)
{
    if (!guest_destination_buffer
        || !hypercall_walk::IsCanonicalRange48(guest_source_virtual_address, size)
        || !hypercall_walk::IsCanonicalRange48(reinterpret_cast<std::uint64_t>(guest_destination_buffer), size)) return 0;
	virt_memory_op_hypercall_info_t memory_op_call = { };

	memory_op_call.call_type = hypercall_type_t::guest_virtual_memory_operation;
	memory_op_call.memory_operation = memory_operation_t::read_operation;
	memory_op_call.address_of_page_directory = source_cr3 >> 12;

	hypercall_info_t hypercall_info = { .value = memory_op_call.value };

	std::uint64_t guest_destination_virtual_address = reinterpret_cast<std::uint64_t>(guest_destination_buffer);

	return make_hypercall(hypercall_info.call_type, hypercall_info.call_reserved_data, guest_destination_virtual_address, guest_source_virtual_address, size);
}

std::uint64_t hypercall::translate_guest_virtual_address(std::uint64_t guest_virtual_address, std::uint64_t guest_cr3)
{
    if (!hypercall_walk::IsCanonical48(guest_virtual_address)) return 0;
	hypercall_type_t call_type = hypercall_type_t::translate_guest_virtual_address;

	return make_hypercall(call_type, 0, guest_virtual_address, guest_cr3, 0);
}

std::uint64_t hypercall::read_guest_cr3()
{
	hypercall_type_t call_type = hypercall_type_t::read_guest_cr3;

	return make_hypercall(call_type, 0, 0, 0, 0);
}
