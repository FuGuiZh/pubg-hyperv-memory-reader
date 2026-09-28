#pragma once
#include "monitor/monitor.hpp"
#include <string>
#include <vector>

namespace monitor::radar {
inline constexpr unsigned kSchemaVersion = 1;
inline constexpr unsigned short kPort = 13101;
inline constexpr std::size_t kMaxDatagramBytes = 60000;
enum class FrameStatus : unsigned { Accepted = 1, Rejected = 2, Disconnected = 3, Stopped = 4 };

// Protocol DTO. Kept separate from collection: unknown properties stay absent.
struct Actor {
    u64 actor_id=0, player_state_id=0, raw_actor_value=0, class_id=0, root_component_id=0, root_component_raw=0;
    std::optional<i32> roster_index, team_id, item_count,actor_array_index;
    std::optional<u32> name_id, item_id, status_raw, dbno_raw, killed_raw,object_id_raw;
    std::optional<Vec3> position;
    std::optional<WorldOrigin> origin;
    std::string name, type_name, availability, source, vehicle_type, item_name;
    u64 observed_at_monotonic_ms=0;
};
struct Metadata {
    std::string stream_id, build_sha256;
    u64 sequence=0, sent_at_unix_ms=0;
    unsigned interval_ms=300;
    double meters_per_unit=0.01;
};

// Emits standard protobuf wire encoding for protocol/radar.proto; no runtime DLL.
// All supplied actors are retained. Oversized frames split at actor boundaries.
std::vector<std::string> Encode(const Snapshot& frame, const Metadata& metadata,
    const std::vector<Actor>& actors, FrameStatus status,
    std::size_t max_datagram_bytes=kMaxDatagramBytes);
std::vector<Actor> PlayerActors(const Snapshot& frame);
std::vector<Actor> AllActors(const Snapshot& frame);
}
