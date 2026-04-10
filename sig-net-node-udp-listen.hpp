//==============================================================================
// Sig-Net Protocol Framework - Node UDP Listen Helpers
//==============================================================================

#ifndef SIGNET_NODE_UDP_LISTEN_HPP
#define SIGNET_NODE_UDP_LISTEN_HPP

#include <winsock2.h>
#include <ws2tcpip.h>

#include "sig-net.hpp"
#include "sig-net-parse.hpp"

namespace SigNet {
namespace Node {

typedef void (*UdpPacketCallback)(const uint8_t* packet,
                                  uint16_t packet_len,
                                  const sockaddr_in& source_addr,
                                  void* user_context);

inline int32_t PollUdpSocket(SOCKET udp_socket,
                             uint16_t max_payload,
                             int packet_budget,
                             UdpPacketCallback callback,
                             void* user_context,
                             bool& saw_packet_out,
                             int& last_error_out)
{
    saw_packet_out = false;
    last_error_out = 0;

    if (udp_socket == INVALID_SOCKET) {
        return SigNet::SIGNET_ERROR_INVALID_ARG;
    }

    uint8_t rx_buffer[SigNet::MAX_UDP_PAYLOAD];
    if (max_payload > SigNet::MAX_UDP_PAYLOAD) {
        max_payload = SigNet::MAX_UDP_PAYLOAD;
    }

    while (packet_budget-- > 0) {
        sockaddr_in source_addr;
        int source_len = sizeof(source_addr);
        int bytes_read = recvfrom(udp_socket,
                                  (char*)rx_buffer,
                                  max_payload,
                                  0,
                                  (sockaddr*)&source_addr,
                                  &source_len);

        if (bytes_read == SOCKET_ERROR) {
            last_error_out = WSAGetLastError();
            if (last_error_out == WSAEWOULDBLOCK) {
                return SigNet::SIGNET_SUCCESS;
            }
            return SigNet::SIGNET_ERROR_NETWORK;
        }

        if (bytes_read > 0) {
            saw_packet_out = true;
            if (callback) {
                callback(rx_buffer,
                         static_cast<uint16_t>(bytes_read),
                         source_addr,
                         user_context);
            }
        }
    }

    return SigNet::SIGNET_SUCCESS;
}

inline bool ParseUniverseFromURI(const char* uri, uint16_t& universe_out)
{
    if (!uri) {
        return false;
    }

    const char* level_ptr = strstr(uri, "/level/");
    if (!level_ptr) {
        return false;
    }

    const char* value_ptr = level_ptr + 7;
    if (*value_ptr == 0) {
        return false;
    }

    int parsed = 0;
    while (*value_ptr != 0) {
        if (*value_ptr < '0' || *value_ptr > '9') {
            return false;
        }
        parsed = (parsed * 10) + (*value_ptr - '0');
        value_ptr++;
    }

    if (parsed < SigNet::MIN_UNIVERSE || parsed > SigNet::MAX_UNIVERSE) {
        return false;
    }

    universe_out = static_cast<uint16_t>(parsed);
    return true;
}

inline bool ExtractPayload(const uint8_t* packet,
                           uint16_t packet_len,
                           const SigNet::CoAPHeader& coap_header,
                           SigNet::SigNetOptions& options_out,
                           char* uri_out,
                           uint16_t uri_out_size,
                           const uint8_t*& payload_out,
                           uint16_t& payload_len_out)
{
    payload_out = 0;
    payload_len_out = 0;

    SigNet::Parse::PacketReader uri_reader(packet, packet_len);
    SigNet::CoAPHeader temp_header;
    if (SigNet::Parse::ParseCoAPHeader(uri_reader, temp_header) != SigNet::SIGNET_SUCCESS) {
        return false;
    }
    if (SigNet::Parse::SkipToken(uri_reader, coap_header.GetTokenLength()) != SigNet::SIGNET_SUCCESS) {
        return false;
    }
    uint16_t uri_len = 0;
    if (SigNet::Parse::ExtractURIString(uri_reader, uri_out, uri_out_size, uri_len) != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    SigNet::Parse::PacketReader option_reader(packet, packet_len);
    if (SigNet::Parse::ParseCoAPHeader(option_reader, temp_header) != SigNet::SIGNET_SUCCESS) {
        return false;
    }
    if (SigNet::Parse::SkipToken(option_reader, coap_header.GetTokenLength()) != SigNet::SIGNET_SUCCESS) {
        return false;
    }
    if (SigNet::Parse::ParseSigNetOptions(option_reader, options_out) != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    uint8_t marker = 0;
    if (!option_reader.PeekByte(marker)) {
        return true;
    }
    if (marker != SigNet::COAP_PAYLOAD_MARKER) {
        return true;
    }

    option_reader.ReadByte(marker);
    payload_out = option_reader.GetCurrentPtr();
    payload_len_out = option_reader.GetRemaining();
    return true;
}

inline const uint8_t* SelectValidationKey(const char* uri,
                                          const uint8_t* manager_global_key,
                                          const uint8_t* sender_key)
{
    if (!uri) {
        return 0;
    }

    if (strstr(uri, "/poll") != 0) {
        return manager_global_key;
    }
    if (strstr(uri, "/node/") != 0) {
        return manager_global_key;
    }
    if (strstr(uri, "/level/") != 0 || strstr(uri, "/priority/") != 0 || strstr(uri, "/sync") != 0) {
        return sender_key;
    }
    return manager_global_key;
}

} // namespace Node
} // namespace SigNet

#endif // SIGNET_NODE_UDP_LISTEN_HPP
