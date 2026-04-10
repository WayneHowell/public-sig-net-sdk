//==============================================================================
// Sig-Net Protocol Framework - Node UDP Socket/Group Helpers
//==============================================================================

#ifndef SIGNET_NODE_UDP_SOCKET_HPP
#define SIGNET_NODE_UDP_SOCKET_HPP

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#include "sig-net.hpp"

namespace SigNet {
namespace Node {

struct UdpGroupState {
    bool joined_manager_poll_group;
    bool joined_manager_send_group;
    bool joined_ep1_universe_group;
    char ep1_multicast_ip[16];

    UdpGroupState()
        : joined_manager_poll_group(false)
        , joined_manager_send_group(false)
        , joined_ep1_universe_group(false)
    {
        ep1_multicast_ip[0] = 0;
    }
};

typedef void (*UdpLogCallback)(const char* message, bool is_error, void* user_context);

inline void EmitUdpLog(UdpLogCallback callback, void* user_context, bool is_error, const char* message)
{
    if (callback && message) {
        callback(message, is_error, user_context);
    }
}

inline void ResetUdpGroupState(UdpGroupState& groups)
{
    groups.joined_manager_poll_group = false;
    groups.joined_manager_send_group = false;
    groups.joined_ep1_universe_group = false;
    groups.ep1_multicast_ip[0] = 0;
}

inline bool EnsureSocketInitialized(SOCKET& udp_socket,
                                    bool& winsock_started,
                                    bool& socket_initialized,
                                    UdpLogCallback log_callback,
                                    void* user_context)
{
    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        return true;
    }

    if (!winsock_started) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            char msg[128];
            sprintf(msg, "WSAStartup failed: %d", result);
            EmitUdpLog(log_callback, user_context, true, msg);
            return false;
        }
        winsock_started = true;
    }

    if (udp_socket != INVALID_SOCKET) {
        closesocket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket == INVALID_SOCKET) {
        char msg[128];
        sprintf(msg, "Socket creation failed: WSA %d", WSAGetLastError());
        EmitUdpLog(log_callback, user_context, true, msg);
        return false;
    }

    {
        int reuse_addr = 1;
        if (setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse_addr, sizeof(reuse_addr)) == SOCKET_ERROR) {
            char msg[128];
            sprintf(msg, "WARNING: SO_REUSEADDR set failed: %d", WSAGetLastError());
            EmitUdpLog(log_callback, user_context, false, msg);
        }
    }

    sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);

    if (bind(udp_socket, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        char msg[160];
        sprintf(msg, "Bind to UDP/%u failed: %d (10013=Permission, 10048=PortInUse)",
                SigNet::SIGNET_UDP_PORT, err);
        EmitUdpLog(log_callback, user_context, true, msg);
        closesocket(udp_socket);
        udp_socket = INVALID_SOCKET;
        return false;
    }

    {
        u_long non_blocking = 1;
        if (ioctlsocket(udp_socket, FIONBIO, &non_blocking) == SOCKET_ERROR) {
            char msg[128];
            sprintf(msg, "ioctlsocket(FIONBIO) failed: %d", WSAGetLastError());
            EmitUdpLog(log_callback, user_context, true, msg);
            closesocket(udp_socket);
            udp_socket = INVALID_SOCKET;
            return false;
        }
    }

    {
        char loopback = 1;
        if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) == SOCKET_ERROR) {
            char msg[128];
            sprintf(msg, "WARNING: Set multicast loopback failed: %d", WSAGetLastError());
            EmitUdpLog(log_callback, user_context, false, msg);
        }
    }

    {
        unsigned char ttl = 16;
        if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
            char msg[128];
            sprintf(msg, "WARNING: Set TTL failed: %d", WSAGetLastError());
            EmitUdpLog(log_callback, user_context, false, msg);
        }
    }

    {
        int broadcast = 1;
        setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
    }

    socket_initialized = true;
    EmitUdpLog(log_callback, user_context, false, "Socket ready on UDP/5683");
    return true;
}

inline void ShutdownSocket(SOCKET& udp_socket,
                           bool& winsock_started,
                           bool& socket_initialized,
                           UdpGroupState& groups)
{
    ResetUdpGroupState(groups);

    if (udp_socket != INVALID_SOCKET) {
        closesocket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }

    socket_initialized = false;

    if (winsock_started) {
        WSACleanup();
        winsock_started = false;
    }
}

inline bool JoinMulticastGroup(SOCKET udp_socket,
                               bool socket_initialized,
                               const char* multicast_ip,
                               const char* selected_nic_ip,
                               UdpLogCallback log_callback,
                               void* user_context)
{
    if (!socket_initialized || udp_socket == INVALID_SOCKET || !multicast_ip) {
        return false;
    }

    ip_mreq group;
    memset(&group, 0, sizeof(group));
    group.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    group.imr_interface.s_addr = INADDR_ANY;

    char nic_ip[16];
    nic_ip[0] = 0;
    if (selected_nic_ip) {
        SigNet::ExtractIPv4Token(selected_nic_ip, nic_ip, sizeof(nic_ip));
        if (nic_ip[0] == 0 && selected_nic_ip[0] != 0) {
            // Fallback for plain IP strings if token extraction returns empty.
            strncpy(nic_ip, selected_nic_ip, sizeof(nic_ip) - 1);
            nic_ip[sizeof(nic_ip) - 1] = 0;

            // Trim leading whitespace before trimming at the first separator space.
            char* p = nic_ip;
            while (*p == ' ' || *p == '\t') {
                ++p;
            }
            if (p != nic_ip) {
                memmove(nic_ip, p, strlen(p) + 1);
            }

            char* space = strchr(nic_ip, ' ');
            if (space) {
                *space = 0;
            }
        }
    }

    {
        char msg[160];
        sprintf(msg, "Join attempt group=%s via selected NIC %s", multicast_ip, nic_ip);
        EmitUdpLog(log_callback, user_context, false, msg);
    }

    // Prefer explicit NIC if available; only fall back to INADDR_ANY for loopback or if explicit NIC fails
    if (nic_ip[0] != 0 && strncmp(nic_ip, "127.", 4) != 0) {
        group.imr_interface.s_addr = inet_addr(nic_ip);
        if (setsockopt(udp_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) == SOCKET_ERROR) {
            int err_nic = WSAGetLastError();
            char msg[192];
            sprintf(msg, "Join multicast %s failed with explicit NIC (WSA %d); falling back to INADDR_ANY", 
                    multicast_ip, err_nic);
            EmitUdpLog(log_callback, user_context, false, msg);
            
            // Fall back to INADDR_ANY
            group.imr_interface.s_addr = INADDR_ANY;
            if (setsockopt(udp_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) == SOCKET_ERROR) {
                int err_any = WSAGetLastError();
                char msg2[192];
                sprintf(msg2, "Join multicast %s failed (NIC WSA %d, ANY WSA %d)", multicast_ip, err_nic, err_any);
                EmitUdpLog(log_callback, user_context, true, msg2);
                return false;
            }
            {
                char msg2[160];
                sprintf(msg2, "Joined multicast %s using INADDR_ANY (fallback)", multicast_ip);
                EmitUdpLog(log_callback, user_context, false, msg2);
            }
            return true;
        }
        {
            char msg[192];
            sprintf(msg, "Joined multicast %s using explicit NIC %s", multicast_ip, nic_ip);
            EmitUdpLog(log_callback, user_context, false, msg);
        }
        return true;
    }

    // For loopback, use INADDR_ANY
    if (setsockopt(udp_socket, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&group, sizeof(group)) == SOCKET_ERROR) {
        int err_any = WSAGetLastError();
        char msg[160];
        sprintf(msg, "Join multicast %s failed: WSA %d", multicast_ip, err_any);
        EmitUdpLog(log_callback, user_context, true, msg);
        return false;
    }

    {
        char msg[160];
        sprintf(msg, "Joined multicast %s using INADDR_ANY", multicast_ip);
        EmitUdpLog(log_callback, user_context, false, msg);
    }
    return true;
}

inline bool LeaveMulticastGroup(SOCKET udp_socket,
                                bool socket_initialized,
                                const char* multicast_ip,
                                UdpLogCallback log_callback,
                                void* user_context)
{
    if (!socket_initialized || udp_socket == INVALID_SOCKET || !multicast_ip) {
        return false;
    }

    ip_mreq group;
    memset(&group, 0, sizeof(group));
    group.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    group.imr_interface.s_addr = INADDR_ANY;

    if (setsockopt(udp_socket, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&group, sizeof(group)) == SOCKET_ERROR) {
        char msg[160];
        sprintf(msg, "Leave multicast %s failed: WSA %d", multicast_ip, WSAGetLastError());
        EmitUdpLog(log_callback, user_context, true, msg);
        return false;
    }

    {
        char msg[128];
        sprintf(msg, "Left multicast %s", multicast_ip);
        EmitUdpLog(log_callback, user_context, false, msg);
    }
    return true;
}

inline void LeaveAllReceiverGroups(SOCKET udp_socket,
                                   bool socket_initialized,
                                   UdpGroupState& groups,
                                   UdpLogCallback log_callback,
                                   void* user_context)
{
    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        if (groups.joined_manager_poll_group) {
            LeaveMulticastGroup(udp_socket, socket_initialized, SigNet::MULTICAST_MANAGER_POLL_IP, log_callback, user_context);
        }
        if (groups.joined_manager_send_group) {
            LeaveMulticastGroup(udp_socket, socket_initialized, SigNet::MULTICAST_MANAGER_SEND_IP, log_callback, user_context);
        }
        if (groups.joined_ep1_universe_group && groups.ep1_multicast_ip[0] != 0) {
            LeaveMulticastGroup(udp_socket, socket_initialized, groups.ep1_multicast_ip, log_callback, user_context);
        }
    }

    ResetUdpGroupState(groups);
}

inline void RefreshReceiverGroups(SOCKET udp_socket,
                                  bool socket_initialized,
                                  const char* selected_nic_ip,
                                  uint16_t ep1_universe,
                                  UdpGroupState& groups,
                                  UdpLogCallback log_callback,
                                  void* user_context)
{
    if (!socket_initialized || udp_socket == INVALID_SOCKET) {
        return;
    }

    if (!groups.joined_manager_poll_group) {
        groups.joined_manager_poll_group = JoinMulticastGroup(udp_socket,
                                                              socket_initialized,
                                                              SigNet::MULTICAST_MANAGER_POLL_IP,
                                                              selected_nic_ip,
                                                              log_callback,
                                                              user_context);
        EmitUdpLog(log_callback,
                   user_context,
                   false,
                   groups.joined_manager_poll_group ? "Manager poll group status: joined"
                                                    : "Manager poll group status: not joined");
    }

    if (!groups.joined_manager_send_group) {
        groups.joined_manager_send_group = JoinMulticastGroup(udp_socket,
                                                              socket_initialized,
                                                              SigNet::MULTICAST_MANAGER_SEND_IP,
                                                              selected_nic_ip,
                                                              log_callback,
                                                              user_context);
        EmitUdpLog(log_callback,
                   user_context,
                   false,
                   groups.joined_manager_send_group ? "Manager send group status: joined"
                                                    : "Manager send group status: not joined");
    }

    char desired_ip[16];
    desired_ip[0] = 0;
    if (SigNet::CalculateMulticastAddress(ep1_universe, desired_ip) != SigNet::SIGNET_SUCCESS) {
        return;
    }

    if (!groups.joined_ep1_universe_group || strcmp(groups.ep1_multicast_ip, desired_ip) != 0) {
        if (groups.joined_ep1_universe_group && groups.ep1_multicast_ip[0] != 0) {
            LeaveMulticastGroup(udp_socket, socket_initialized, groups.ep1_multicast_ip, log_callback, user_context);
            groups.joined_ep1_universe_group = false;
        }

        if (JoinMulticastGroup(udp_socket,
                               socket_initialized,
                               desired_ip,
                               selected_nic_ip,
                               log_callback,
                               user_context)) {
            strncpy(groups.ep1_multicast_ip, desired_ip, sizeof(groups.ep1_multicast_ip) - 1);
            groups.ep1_multicast_ip[sizeof(groups.ep1_multicast_ip) - 1] = 0;
            groups.joined_ep1_universe_group = true;

            char msg[128];
            sprintf(msg, "EP1 universe group status: joined %s", desired_ip);
            EmitUdpLog(log_callback, user_context, false, msg);
        }
    }
}

} // namespace Node
} // namespace SigNet

#endif // SIGNET_NODE_UDP_SOCKET_HPP
