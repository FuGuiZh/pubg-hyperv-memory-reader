#include "telemetry/udp_sender.hpp"
#pragma comment(lib,"ws2_32.lib")

namespace monitor::radar {
UdpSender::UdpSender(unsigned short port) noexcept {
    destination_.sin_family=AF_INET;
    destination_.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    destination_.sin_port=htons(port);
    WSADATA data{};
    init_error_=WSAStartup(MAKEWORD(2,2),&data);
    if(init_error_)return;
    wsa_started_=true;
    socket_=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(socket_==INVALID_SOCKET){init_error_=WSAGetLastError();return;}
    u_long nonblocking=1;
    if(ioctlsocket(socket_,FIONBIO,&nonblocking)==SOCKET_ERROR) {
        init_error_=WSAGetLastError();closesocket(socket_);socket_=INVALID_SOCKET;return;
    }
    sockaddr_in local{};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(socket_,reinterpret_cast<const sockaddr*>(&local),sizeof(local))==SOCKET_ERROR) {
        init_error_=WSAGetLastError();closesocket(socket_);socket_=INVALID_SOCKET;
    }
}
UdpSender::~UdpSender() {if(socket_!=INVALID_SOCKET)closesocket(socket_);if(wsa_started_)WSACleanup();}
SendResult UdpSender::Send(const std::vector<std::string>& datagrams) noexcept {
    SendResult r;r.datagrams=datagrams.size();
    if(socket_==INVALID_SOCKET){r.error=init_error_?init_error_:WSAENOTSOCK;return r;}
    for(const auto& bytes:datagrams) {
        if(bytes.empty() || bytes.size()>kMaxDatagramBytes){r.error=WSAEMSGSIZE;break;}
        const int sent=sendto(socket_,bytes.data(),static_cast<int>(bytes.size()),0,
            reinterpret_cast<const sockaddr*>(&destination_),sizeof(destination_));
        if(sent==SOCKET_ERROR){r.error=WSAGetLastError();break;}
        if(static_cast<std::size_t>(sent)!=bytes.size()){r.error=WSAEMSGSIZE;break;}
        ++r.sent;r.bytes+=sent;
    }
    return r;
}
}
