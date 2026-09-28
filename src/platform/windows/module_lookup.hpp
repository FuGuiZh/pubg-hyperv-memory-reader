#pragma once
#include "monitor/monitor.hpp"
#include "platform/windows/process_lookup.hpp"
#include <string_view>

namespace monitor {
// Evidence from one bounded loader traversal. Verify again after reading PE
// headers so a changed loader chain cannot authorize a new backend session.
struct ModuleReference {
    u64 base=0, peb=0, ldr=0, entry=0;
    UNICODE_STRING_RAW descriptor{};
    std::vector<u16> name;
    std::vector<std::pair<u64,u64>> links;
    void Verify(Reader& memory) const;
};
ModuleReference FindModuleChecked(Reader& memory,u64 peb,std::string_view wanted);
}
