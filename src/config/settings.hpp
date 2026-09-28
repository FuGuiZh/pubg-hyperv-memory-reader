#pragma once
#include <cstddef>
#include <cstdint>

// Reader timing and collection settings. The PID is entered at every startup.
namespace UserSettings {
inline constexpr int kRefreshIntervalMs = 300;
// Maximum age measured from original capture start; failures never reset it.
inline constexpr int kRetainedDisplayMs = 3000;
inline constexpr int kCaptureBudgetMs = 1500;
inline constexpr unsigned kReadAttempts = 2;
inline constexpr int kRootFailureRebindMs = 8000; // fallback; a verified CR3 change bypasses this delay
inline constexpr int kRebindDelayMs = 1500;
inline constexpr int kHeartbeatMs = 1000;
inline constexpr bool kIncludeNamesInReports = true;
// Actor 只负责低频发现；每个普通采集帧重新验证缓存关系并读取位置。
inline constexpr int kDiscoveryIntervalMs = 1000;
inline constexpr int kDiscoveryMinIntervalMs = 500;
inline constexpr int kFirstDiscoverySliceMs = 300;
inline constexpr std::size_t kFirstDiscoveryActorsPerSlice = 2048;
inline constexpr int kDiscoverySliceMs = 60;
inline constexpr std::size_t kDiscoveryActorsPerSlice = 256; // baseline; queue size/age increases quota within 60 ms
inline constexpr int kDiscoveryCycleTimeoutMs = 5000;
inline constexpr int kAssociationTtlMs = 8000;
inline constexpr int kObjectDiagnosticsIntervalMs = 5000;
// 构建指纹保留在 monitor.hpp。不要为了绕过版本错误而盲目关闭。
inline constexpr bool kVerifyExpectedImage = true;
}
