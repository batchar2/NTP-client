#include "ntp_client.hpp"

#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <sys/types.h>
#include <thread>
#include <unordered_map>
#ifdef _WIN32
#include <WinSock2.h>
#include <Ws2tcpip.h>

#define close(X) closesocket(X)
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

namespace {
#pragma pack(push, 1)
    struct NTPPacket {
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

        // 32 bits and the most important field the client cares about. Transmit
        // time-stamp seconds.
        std::uint32_t transmitted_timestamp_sec;

        // 32 bits. Transmit time-stamp fraction of a second.
        std::uint32_t transmitted_timestamp_sec_frac;
    };
#pragma pack(pop)

    static_assert(sizeof(NTPPacket) == 48, "Invalid NTP packet size");

    std::string resolve_hostname(const std::string &host) {
        static std::unordered_map<std::string, std::string> cache;
        static std::mutex cache_mutex; {
            // check cache
            const std::lock_guard<std::mutex> lock(cache_mutex); // mutex

            const auto it = cache.find(host);
            if (it != cache.end()) {
                return it->second;
            }
        }

        struct addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        struct addrinfo *addr_info = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &addr_info) != 0) {
            return {};
        }

        std::string ip_address;
        for (struct addrinfo *p = addr_info; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET) {
                char ip_str[INET_ADDRSTRLEN] = {};
                inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(p->ai_addr)->sin_addr,
                          ip_str, sizeof(ip_str));
                ip_address = ip_str;
                break;
            }
        }
        freeaddrinfo(addr_info);

        // cache address
        if (!ip_address.empty()) {
            const std::lock_guard<std::mutex> lock(cache_mutex); // mutex
            cache[host] = ip_address;
        }
        return ip_address;
    }

    std::string hostname_to_ip(const std::string &host) {
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
} // namespace

using ntp::NTPClient;

NTPClient::NTPClient(std::string hostname, std::uint16_t port)
    : hostname_(std::move(hostname)),
      port_(port),
      socket_fd(-1),
      socket_client{} {
#ifdef _WIN32
  WSADATA wsa = {};
  (void)WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

bool NTPClient::build_connection() {
    std::memset(&socket_client, 0, sizeof(socket_client));

    // Creating socket file descriptor
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        return false;
    }

    // Set timeout
#ifdef _WIN32
  const DWORD timeout_ms = 5000;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
          reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms)) < 0) {
    return false;
  }
#else
    struct timeval timeout = {};
    timeout.tv_sec = 5; // set timeout in seconds
    if (setsockopt(
            socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
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

NTPClient::~NTPClient() {
    close_socket();
#ifdef _WIN32
  WSACleanup();
#endif
}

std::uint64_t NTPClient::request_time() {
    if (!build_connection()) {
        std::cerr << "Failed to build connection" << std::endl;
        return 0;
    }

    if (connect(socket_fd, reinterpret_cast<struct sockaddr *>(&socket_client),
                sizeof(socket_client)) < 0) {
        std::cerr << "Connect failed" << std::endl;
        return 0;
    }

    NTPPacket packet = {};
    std::memset(&packet, 0, sizeof(packet));
    packet.li_vn_mode = 0x1b; // LI=0, VN=3, Mode=3 (client)

    int response = send(socket_fd, reinterpret_cast<const char *>(&packet), sizeof(packet), 0);
    if (response < 0) {
        std::cerr << "Send failed: " << errno << std::endl;
        close_socket();
        return 0;
    }

    response = recv(socket_fd, reinterpret_cast<char *>(&packet), sizeof(packet), 0);
    if (response < static_cast<int>(sizeof(packet))) {
        std::cerr << "Recv failed, received " << response << " bytes, expected "
                << sizeof(packet) << std::endl;
        close_socket();
        return 0;
    }

    packet.transmitted_timestamp_sec = ntohl(packet.transmitted_timestamp_sec);

    constexpr std::uint64_t NTP_TO_UNIX_EPOCH = 2208988800ULL;
    const std::uint64_t ntp_seconds = packet.transmitted_timestamp_sec;

    if (ntp_seconds == 0 || ntp_seconds < NTP_TO_UNIX_EPOCH) {
        std::cerr << "Invalid NTP time: " << ntp_seconds << std::endl;
        close_socket();
        return 0;
    }

    std::uint64_t unix_seconds = ntp_seconds - NTP_TO_UNIX_EPOCH;
    close_socket();
    return unix_seconds * 1000;
}

void NTPClient::close_socket() {
    if (socket_fd != -1) {
        close(socket_fd);
        socket_fd = -1;
    }
}
