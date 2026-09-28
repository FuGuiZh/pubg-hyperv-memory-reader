#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace dumper {
std::optional<std::wstring> ReadFileVersion(const std::filesystem::path& image);
// Require a single Windows filename, never a path or alternate data stream.
void ValidateImageName(std::wstring_view image_name);
// Publishes an already-written EXE and its .info.txt companion, replacing the
// same version. An unversioned result remains in its unique staging directory.
std::filesystem::path PublishDump(const std::filesystem::path& staged_image,
    const std::filesystem::path& directory, std::wstring_view image_name);
}
