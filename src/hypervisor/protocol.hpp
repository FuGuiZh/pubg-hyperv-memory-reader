#pragma once
#include <cstdint>
#include "hypervisor/memory_operation.hpp"

enum class hypercall_type_t : std::uint64_t
{
    // Preserve the numeric IDs used by the existing hypervisor backend.
    guest_physical_memory_operation = 0,
    guest_virtual_memory_operation = 1,
    translate_guest_virtual_address = 2,
    read_guest_cr3 = 3,
    diagnostic_capabilities = 10,
    diagnostic_page_chain = 11
};

#pragma warning(push)
#pragma warning(disable: 4201)

constexpr std::uint64_t hypercall_primary_key = 0x4E47;
constexpr std::uint64_t hypercall_secondary_key = 0x7F;

union hypercall_info_t
{
    std::uint64_t value;

    struct
    {
        std::uint64_t primary_key : 16;
        hypercall_type_t call_type : 4;
        std::uint64_t secondary_key : 7;
        std::uint64_t call_reserved_data : 37;
    };
};

union virt_memory_op_hypercall_info_t
{
    std::uint64_t value;

    struct
    {
        std::uint64_t primary_key : 16;
        hypercall_type_t call_type : 4;
        std::uint64_t secondary_key : 7;
        memory_operation_t memory_operation : 1;
        std::uint64_t address_of_page_directory : 36; // we will construct the other cr3 (aside from the caller process) involved in the operation from this
    };
};

#pragma warning(pop)

static_assert(sizeof(hypercall_info_t) == sizeof(std::uint64_t));
static_assert(sizeof(virt_memory_op_hypercall_info_t) == sizeof(std::uint64_t));
