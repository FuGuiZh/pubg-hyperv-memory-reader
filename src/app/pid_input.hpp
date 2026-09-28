#pragma once
#include <charconv>
#include <cstdint>
#include <istream>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>

namespace app {
// Called before the reader switches the console to raw input or creates logs.
inline std::optional<std::uint32_t> PromptForPid(std::istream& input, std::ostream& output,
    std::string_view target = "TslGame.exe") {
    for (;;) {
        output << "Enter " << target << " PID (q to quit): " << std::flush;
        std::string line;
        if (!std::getline(input, line)) {
            output << "\nPID input cancelled.\n";
            return std::nullopt;
        }
        std::string_view value(line);
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first != std::string_view::npos) {
            value = value.substr(first, value.find_last_not_of(" \t\r\n") - first + 1);
            if (value == "q" || value == "Q") return std::nullopt;
            std::uint32_t pid = 0;
            const auto parsed = std::from_chars(value.data(), value.data() + value.size(), pid);
            if (parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && pid)
                return pid;
        }
        output << "Invalid PID. Enter a decimal number from 1 to 4294967295.\n";
    }
}
}
