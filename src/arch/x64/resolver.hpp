#pragma once

#include "arch/x64/interpreter.hpp"
#include <map>
#include <string>
#include <vector>

namespace monitor {
struct Issue;

enum class Cipher {
    Plain, World, GameState, GameInstance, CurrentLevel, RootComponent,
    PlayerState, LocalPlayer, ControlPointer, Actors,
    NamesGlobal20, NamesGlobal10, NamesContainer, NamesContainerEncode,
    NamesContainerDecode, NamesBlocks, NamesEntryEncode, NamesEntryDecode, NamesHeader
};

std::uint64_t StaticResolve(Cipher cipher, std::uint64_t state) noexcept;

// Per-capture, per-field resolver. Mode, target and interpreted code bytes are
// checked again before the collector publishes a frame.
class FrameResolver {
public:
    FrameResolver(Reader& memory, std::uint64_t base, std::vector<std::string>* trace = nullptr)
        : memory_(memory), interpreter_(memory), base_(base), trace_(trace) {}
    std::uint64_t World(std::uint64_t raw);
    std::uint64_t GameState(std::uint64_t raw);
    std::uint64_t Actors(std::uint64_t raw);
    // Names contain encoded pointers and scalar headers, not UObject-shaped values.
    std::uint64_t Resolve(std::uint64_t raw, Cipher cipher) { return Transform(raw, cipher); }
    std::uint64_t Object(std::uint64_t raw, Cipher cipher = Cipher::Plain);
    std::uint64_t Field(std::uint64_t object, std::uint64_t offset, Cipher cipher, const char* stage,
                        std::uint64_t* raw = nullptr);
    void Verify();

private:
    struct Mode { std::uint64_t value = 0, target = 0, slot = 0; };
    Mode Metadata(std::uint64_t mode_rva, std::uint64_t slot_rva);
    std::uint64_t Transform(std::uint64_t raw, Cipher cipher);
    bool ObjectShape(std::uint64_t address, Issue* read_issue = nullptr);
    Reader& memory_;
    Interpreter interpreter_;
    std::uint64_t base_;
    std::vector<std::string>* trace_;
    std::map<std::pair<std::uint64_t, std::uint64_t>, Mode> modes_;
};

}
