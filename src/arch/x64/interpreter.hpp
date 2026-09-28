#pragma once

#include <cstddef>
#include <cstdint>
#include <map>

namespace monitor {
class Reader;

// Executes the bounded x64 arithmetic subset observed in the target's dynamic
// resolver stubs. The guest code is interpreted; it is never called natively.
class Interpreter {
public:
    explicit Interpreter(Reader& memory) : memory_(memory) {}
    std::uint64_t Execute(std::uint64_t entry, std::uint32_t selector, std::uint64_t state);
    void VerifyCode(); // Code cache lives for one capture only.
    std::size_t LastSteps() const noexcept { return steps_; }

private:
    std::uint8_t Byte(std::uint64_t address);
    Reader& memory_;
    std::map<std::uint64_t, std::uint8_t> code_;
    std::size_t steps_ = 0;
};

}
