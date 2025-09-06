#include "ntp_client.hpp"

#include <cstring>

#include <chrono>
#include <future>
#include <thread>
#include <iostream>
#include <unordered_map>

#include <sys/types.h>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>

#define close(X) closesocket(X)
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif


namespace {

#pragma pack(push, 1)
struct NTPPacket
{
    std::uint8_t li_vn_mode; // Eight bits. li, vn, and mode.
    // li.   Two bits.   Leap indicator.
    // vn.   Three bits. Version number of the protocol.
    // mode. Three bits. Client will pick mode 3 for client.

    // Eight bits. Stratum level of the local clock.
    std::uint8_t stratum;

    // Eight bits. Maximum interval between successive messages.
    std::uint8_t poll;

    // Eight bits. Precision of the local clock.
    std::uint8_t precision;

    // 32 bits. Total round trip delay time.
    std::uint32_t rootDelay;

    // 32 bits. Max error aloud from primary clock source.
    std::uint32_t root_dispersion;

    // 32 bits. Reference clock identifier.
    std::uint32_t ref_id;

    // 32 bits. Reference time-stamp seconds.
    std::uint32_t ref_timestamp_sec;

    // 32 bits. Reference time-stamp fraction of a second.
    std::uint32_t ref_timestamp_sec_frac;

    // 32 bits. Originate time-stamp seconds.
    std::uint32_t orig_timestamp_sec;

    // 32 bits. Originate time-stamp fraction of a second.
    std::uint32_t orig_timestamp_sec_frac;

    // 32 bits. Received time-stamp seconds.
    std::uint32_t received_timestamp_sec;

    // 32 bits. Received time-stamp fraction of a second.
    std::uint32_t received_timestamp_sec_frac;

    // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
    std::uint32_t transmitted_timestamp_sec;

    // 32 bits. Transmit time-stamp fraction of a second.
    std::uint32_t transmitted_timestamp_sec_frac;
};
#pragma pack(pop)

static_assert(sizeof(NTPPacket) == 48, "Invalid NTP packet size");


std::string resolve_hostname(const std::string& host) {
    static std::unordered_map<std::string, std::string> cache;
    static std::mutex cache_mutex;

    {
        // check cache
        const std::lock_guard<std::mutex> lock(cache_mutex);  // mutex

        const auto it = cache.find(host);
        if (it != cache.end()) {
            return it->second;
        }
    }

    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo* addr_info = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &addr_info) != 0) {
        return {};
    }

    std::string ip_address;
    for (struct addrinfo* p = addr_info; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            char ip_str[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr, ip_str, sizeof(ip_str));
            ip_address = ip_str;
            break;
        }
    }
    freeaddrinfo(addr_info);

    // cache address
    if (!ip_address.empty()) {
        const std::lock_guard<std::mutex> lock(cache_mutex);  // mutex
        cache[host] = ip_address;
    }
    return ip_address;
}

}  // namespace


using ntp::NTPClient;


NTPClient::NTPClient(std::string hostname, std::uint16_t port) :
        hostname_(std::move(hostname)),
        port_(port),
        socket_fd(-1),
        socket_client{}
{
#ifdef _WIN32
    WSADATA wsa = {};
    (void)WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

bool NTPClient::build_connection()
{
    std::memset(&socket_client, 0, sizeof(socket_client));

    // Creating socket file descriptor
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)
    {
        return false;
    }

    // Set timeout
#ifdef _WIN32
    const DWORD timeout_ms = 5000;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) < 0)
    {
        return false;
    }
#else
    struct timeval timeout = {};
    timeout.tv_sec = 5;  // set timeout in seconds
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        return false;
    }
#endif

    // Filling server information
    const std::string ntp_server_ip = hostname_to_ip(hostname_);
    if (ntp_server_ip.empty()) {
        return false;
    }
    socket_client.sin_family = AF_INET;
    socket_client.sin_port = htons(port_);
    if (inet_pton(AF_INET, ntp_server_ip.c_str(), &socket_client.sin_addr) <= 0) {
        return false;
    }
    return true;
}

NTPClient::~NTPClient()
{
    close_socket();
#ifdef _WIN32
    WSACleanup();
#endif
}

std::uint64_t NTPClient::request_time()
{
    std::size_t response = 0;  // return result from writing/reading from the socket

    if (!build_connection()) {
        return 0;
    }

    if (connect(socket_fd, reinterpret_cast<struct sockaddr*>(&socket_client), sizeof(socket_client)) < 0)
    {
        return 0;
    }

    NTPPacket packet = {};
    packet.li_vn_mode = 0x1b;

#ifdef _WIN32
    response = sendto(socket_fd, reinterpret_cast<char*>(&packet), sizeof(NTPPacket), 0,
                      reinterpret_cast<struct sockaddr*>(&socket_client), sizeof(socket_client));
#else
    response = write(socket_fd, reinterpret_cast<char*>(&packet), sizeof(NTPPacket));
#endif

    if (response < 0)
    {
        return 0;
    }
#ifdef _WIN32
    response = recv(socket_fd, (char*)&packet, sizeof(NTPPacket), 0);
#else
    response = read(socket_fd, reinterpret_cast<char*>(&packet), sizeof(NTPPacket));
#endif

    if (response < 0)
    {
        close_socket();
        return 0;
    }

    // These two fields contain the time-stamp seconds as the packet left the NTP
    // server. The number of seconds correspond to the seconds passed since 1900.
    // ntohl() converts the bit/byte order from the network's to host's
    // "endianness".

    packet.transmitted_timestamp_sec = ntohl(packet.transmitted_timestamp_sec);           // Time-stamp seconds.
    packet.transmitted_timestamp_sec_frac = ntohl(packet.transmitted_timestamp_sec_frac); // Time-stamp fraction of a second.

    // Extract the 32 bits that represent the time-stamp seconds (since NTP epoch)
    // from when the packet left the server. Subtract 70 years worth of seconds
    // from the seconds since 1900. This leaves the seconds since the UNIX epoch
    // of 1970.
    // (1900)---------(1970)**********(Time Packet Left the Server)
    /// @brief Delta between epoch time and ntp time
    constexpr unsigned long long NTP_TIMESTAMP_DELTA{2208988800ull};

    const std::uint32_t seconds_since_1900 = packet.transmitted_timestamp_sec;
    const std::uint32_t seconds_since_1970 = seconds_since_1900 - NTP_TIMESTAMP_DELTA;
    // Convert to milliseconds
    return static_cast<std::uint64_t>(seconds_since_1970) * 1000;
}

std::string NTPClient::hostname_to_ip(const std::string& host)
{
    std::promise<std::string> promise;
    std::future<std::string> future = promise.get_future();

    std::thread thread([host, p = std::move(promise)]() mutable {
        const auto result = resolve_hostname(host);
        p.set_value(result);
    });
    thread.detach();

    constexpr auto timeout = std::chrono::seconds(5);
    if (future.wait_for(timeout) == std::future_status::ready) {
        try {
            return future.get();
        } catch (...) {
            std::cerr << "future error\n";
        }
    }
    return {};
}

void NTPClient::close_socket()
{
    if (socket_fd != -1)
    {
        close(socket_fd);
        socket_fd = -1;
    }
}
