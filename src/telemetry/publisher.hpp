#pragma once
#include "telemetry/udp_sender.hpp"

namespace monitor::radar {
struct PublishStats { u64 frames=0,datagrams=0,sent=0,bytes=0,failed_frames=0; };
class Publisher {
public:
    explicit Publisher(Metadata metadata,unsigned short port=kPort) : metadata_(std::move(metadata)),sender_(port) {}
    // Network/encoding failures are reported to the caller, never made capture failures.
    std::string Publish(const Snapshot& frame,FrameStatus status);
    const PublishStats& Stats() const noexcept {return stats_;}
private:
    Metadata metadata_;
    UdpSender sender_;
    PublishStats stats_;
};
}
