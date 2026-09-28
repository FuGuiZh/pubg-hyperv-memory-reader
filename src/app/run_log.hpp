#pragma once
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>

namespace monitor {
std::filesystem::path ExecutablePath();
std::string FileSha256(const std::filesystem::path& path);

class Log {
public:
    explicit Log(const std::filesystem::path& executable_directory = ExecutablePath().parent_path());
    const std::filesystem::path& Directory() const noexcept { return directory_; }
    const std::string& BuildHash() const noexcept { return build_hash_; }
    void Write(const char* filename, const std::string& text);
private:
    std::filesystem::path directory_;
    std::string run_id_, build_hash_;
    std::mutex mutex_;
    std::unordered_map<std::string, unsigned> segments_;
};
}
