#include "app/run_log.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

namespace monitor {
namespace {
void Checked(NTSTATUS status) {
    if (status < 0) throw std::runtime_error("Windows SHA256/random provider failed");
}
class Sha256 {
public:
    Sha256() {
        Checked(BCryptOpenAlgorithmProvider(&algorithm_, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
        const auto status = BCryptCreateHash(algorithm_, &hash_, nullptr, 0, nullptr, 0, 0);
        if (status < 0) { BCryptCloseAlgorithmProvider(algorithm_, 0); Checked(status); }
    }
    ~Sha256() { BCryptDestroyHash(hash_); BCryptCloseAlgorithmProvider(algorithm_, 0); }
    Sha256(const Sha256&) = delete;
    void Add(const void* bytes, ULONG size) {
        Checked(BCryptHashData(hash_, static_cast<PUCHAR>(const_cast<void*>(bytes)), size, 0));
    }
    std::string Finish() {
        std::array<unsigned char, 32> digest{};
        Checked(BCryptFinishHash(hash_, digest.data(), static_cast<ULONG>(digest.size()), 0));
        std::ostringstream out;
        for (const auto byte : digest) out << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte);
        return out.str();
    }
private:
    BCRYPT_ALG_HANDLE algorithm_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
};
}
std::filesystem::path ExecutablePath() {
    std::vector<wchar_t> path(512);
    for (;;) {
        const auto n = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (!n) throw std::runtime_error("Cannot determine executable path");
        if (n < path.size()) return std::wstring(path.data(), n);
        if (path.size() >= 32768) throw std::runtime_error("Executable path is too long");
        path.resize(std::min<std::size_t>(path.size() * 2, 32768));
    }
}
std::string FileSha256(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open executable for build fingerprint");
    Sha256 hash;
    std::array<char, 65536> bytes{};
    while (input.read(bytes.data(), bytes.size()) || input.gcount())
        hash.Add(bytes.data(), static_cast<ULONG>(input.gcount()));
    if (!input.eof()) throw std::runtime_error("Cannot read executable build fingerprint");
    return hash.Finish();
}
Log::Log(const std::filesystem::path& executable_directory) : build_hash_(FileSha256(ExecutablePath())) {
    const auto parent = executable_directory / L"log-files";
    SYSTEMTIME local{};
    GetLocalTime(&local);
    std::ostringstream prefix;
    prefix << "logs-" << std::setfill('0') << std::setw(4) << local.wYear << '-'
           << std::setw(2) << local.wMonth << '-' << std::setw(2) << local.wDay << '-';
    std::filesystem::create_directories(parent);
    for (unsigned attempt = 0; attempt < 64; ++attempt) {
        std::array<unsigned char, 32> nonce{};
        Checked(BCryptGenRandom(nullptr, nonce.data(), static_cast<ULONG>(nonce.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
        Sha256 hash;
        hash.Add(nonce.data(), static_cast<ULONG>(nonce.size()));
        run_id_ = prefix.str() + hash.Finish().substr(0, 8);
        directory_ = parent / run_id_;
        // Atomic creation: never append into a previous run, even on a hash collision.
        if (std::filesystem::create_directory(directory_)) {
            Write("manifest.log", "RUN_ID=" + run_id_ + " exe_sha256=" + build_hash_
                  + " reader_pid=" + std::to_string(GetCurrentProcessId())
                  + " diagnostic_schema=3 cpu_samples=windows_before_after;hypervisor_when_supported");
            return;
        }
    }
    throw std::runtime_error("Cannot allocate a unique log directory");
}
void Log::Write(const char* filename, const std::string& text) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& segment = segments_[filename];
    auto path = directory_ / filename;
    for (;;) {
        path = directory_ / filename;
        if (segment) path = path.parent_path() / (path.stem().string() + "." + std::to_string(segment) + path.extension().string());
        if (!std::filesystem::exists(path) || std::filesystem::file_size(path) <= 8 * 1024 * 1024) break;
        ++segment; // Retain every segment; do not delete earlier evidence.
    }
    std::ofstream out(path, std::ios::app);
    const auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    out << "[epoch_ms=" << epoch << " run=" << run_id_ << " build=" << build_hash_.substr(0, 16) << "] " << text << '\n';
    out.flush();
    if (!out) throw std::runtime_error("Cannot write run log");
}
}
