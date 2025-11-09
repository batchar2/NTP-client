#pragma once

#include <cstdint>
#include <string>

#ifdef _WIN32
#include <WinSock2.h>
#else
#include <netinet/in.h>
#endif

namespace ntp {

#ifdef _WIN32
    using Socket = SOCKET;
#else
    using Socket = int;
#endif

struct NTPClient
{
    NTPClient(std::string host, std::uint16_t port);
    ~NTPClient();

    /**
   * @brief Transmits an NTP request to the defined server and returns the
   * timestamp
   *
   * @return (uint64_t) the number of milliseconds since 1970. Return 0 if fail.
   */
    std::uint64_t request_time();

protected:
    /// @brief Build the connection. Set all the params for the socket_client.
    bool build_connection();

    /// @brief Close the connection. Set -1 to socket_fd.
    void close_socket();

private:
    /// @brief NTP server IP address
    std::string hostname_;

    /// @brief NTP server port
    std::size_t port_;

    /// @brief Socket file descriptor
    Socket socket_fd;

    /// @brief Server address data structure
    struct sockaddr_in socket_client;
};
}  // namespace ntp
