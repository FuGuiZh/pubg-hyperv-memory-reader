#include "telemetry/publisher.hpp"

namespace monitor::radar {
std::string Publisher::Publish(const Snapshot& frame,FrameStatus status) {
    ++stats_.frames;
    metadata_.sequence=stats_.frames;
    metadata_.sent_at_unix_ms=static_cast<u64>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    try {
        const auto actors=status==FrameStatus::Accepted && frame.complete?AllActors(frame):std::vector<Actor>{};
        const auto packets=Encode(frame,metadata_,actors,status);
        const auto result=sender_.Send(packets);
        stats_.datagrams+=result.datagrams;stats_.sent+=result.sent;stats_.bytes+=result.bytes;
        if(result.error) {
            ++stats_.failed_frames;
            return "winsock="+std::to_string(result.error)+" sent="+std::to_string(result.sent)+"/"+std::to_string(result.datagrams);
        }
    } catch(const std::exception& error) {
        ++stats_.failed_frames;
        return std::string("encoding=")+error.what();
    }
    return {};
}
}
