#include "output_files.hpp"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winver.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <vector>
#pragma comment(lib, "version.lib")

namespace dumper {
void ValidateImageName(std::wstring_view name) {
    if (name.empty() || name.size() > 255 || name.back() == L'.' || name.back() == L' '
        || name.find_first_of(L"<>:\"/\\|?*") != std::wstring_view::npos
        || std::any_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; }))
        throw std::runtime_error("Process image name is not a valid output filename.");
}

std::optional<std::wstring> ReadFileVersion(const std::filesystem::path& image) {
    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, image.c_str(), &ignored);
    if (!size || size > 16U * 1024U * 1024U) return std::nullopt;
    std::vector<unsigned char> bytes(size);
    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, image.c_str(), 0, size, bytes.data()))
        return std::nullopt;
    void* value = nullptr;
    UINT length = 0;
    if (!VerQueryValueW(bytes.data(), L"\\", &value, &length) || !value || length < sizeof(VS_FIXEDFILEINFO))
        return std::nullopt;
    VS_FIXEDFILEINFO info{};
    std::memcpy(&info, value, sizeof(info));
    if (info.dwSignature != 0xFEEF04BD) return std::nullopt;
    return std::to_wstring(HIWORD(info.dwFileVersionMS)) + L"."
        + std::to_wstring(LOWORD(info.dwFileVersionMS)) + L"."
        + std::to_wstring(HIWORD(info.dwFileVersionLS)) + L"."
        + std::to_wstring(LOWORD(info.dwFileVersionLS));
}

std::filesystem::path PublishDump(const std::filesystem::path& staged_image,
    const std::filesystem::path& directory, std::wstring_view image_name) {
    ValidateImageName(image_name);
    const std::filesystem::path original_name{image_name};
    auto staged_info = staged_image;
    staged_info += L".info.txt";
    if (!std::filesystem::is_regular_file(staged_image) || !std::filesystem::is_regular_file(staged_info))
        throw std::runtime_error("Dump EXE and information must both be saved before publication.");
    const auto version = ReadFileVersion(staged_image);
    std::wstring label = version.value_or(L"unknown-version");
    std::replace(label.begin(), label.end(), L'.', L'-');
    if (!version) std::cerr << "Warning: dumped file version unavailable; using unknown-version.\n";
    {
        std::ofstream info(staged_info, std::ios::app);
        std::string text;
        // ReadFileVersion formats only ASCII digits and dots; fallback is ASCII.
        for (const wchar_t c : version.value_or(L"unknown")) text.push_back(static_cast<char>(c));
        info << "\nFileVersion=" << text << '\n'
             << "FileVersionSource=dumped PE fixed file version resource\n";
        info.close();
        if (info.fail()) throw std::runtime_error("Could not record file version in dump information.");
    }
    // A missing version cannot establish that an earlier dump is the same build.
    // Keep that result in its unique staging directory instead of overwriting it.
    const auto destination = version ? directory : staged_image.parent_path();
    const auto extension = original_name.has_extension() ? original_name.extension().wstring() : L".exe";
    const auto image = destination / (original_name.stem().wstring() + L"-" + label + extension);
    auto info = image;
    info += L".info.txt";
    constexpr DWORD flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    if (!MoveFileExW(staged_image.c_str(), image.c_str(), flags))
        throw std::system_error(GetLastError(), std::system_category(), "Could not publish dump EXE; staging files retained");
    if (!MoveFileExW(staged_info.c_str(), info.c_str(), flags))
        throw std::system_error(GetLastError(), std::system_category(), "EXE saved, but information replacement failed; new information remains in staging");
    return image;
}
}
