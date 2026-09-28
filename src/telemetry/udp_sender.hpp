#pragma once
#include "telemetry/radar_protocol.hpp"

namespace monitor::radar {
struct SendResult {
    std::size_t datagrams=0,sent=0,bytes=0;
    int error=0; // Winsock error; successful send means queued locally, not received.
};
class UdpSender {
public:
    explicit UdpSender(unsigned short port=kPort) noexcept;
    ~UdpSender();
    UdpSender(const UdpSender&)=delete;
    UdpSender& operator=(const UdpSender&)=delete;
    SendResult Send(const std::vector<std::string>& datagrams) noexcept;
private:
    SOCKET socket_=INVALID_SOCKET;
    bool wsa_started_=false;
    int init_error_=0;
    sockaddr_in destination_{};
};
}
