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
    if (SigNet::Parse::ValidateSigNetURI(uri_out) != SigNet::SIGNET_SUCCESS) {
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
                                          const uint8_t* manager_local_key,
                                          const uint8_t* citizen_key,
                                          const uint8_t* sender_key)
{
    if (!uri) {
        return 0;
    }

    if (strstr(uri, "/poll") != 0) {
        return manager_global_key;
    }
    if (strstr(uri, "/manager/") != 0) {
        return manager_local_key;
    }
    if (strstr(uri, "/node/") != 0) {
        return citizen_key;
    }
    if (strstr(uri, "/level/") != 0 || strstr(uri, "/priority/") != 0 ||
        strstr(uri, "/sync") != 0 || strstr(uri, "/timecode/") != 0 ||
        strstr(uri, "/preview/") != 0 || strstr(uri, "/aux/") != 0) {
        return sender_key;
    }
    return 0;
}

inline bool TryParseTargetUriEndpoint(const char* uri, uint16_t& endpoint_out)
{
    endpoint_out = 0;
    if (!uri) {
        return false;
    }

    const char* node_ptr = strstr(uri, "/node/");
    const char* manager_ptr = strstr(uri, "/manager/");
    if (!node_ptr && !manager_ptr) {
        return false;
    }

    const char* endpoint_ptr = strrchr(uri, '/');
    if (!endpoint_ptr || *(endpoint_ptr + 1) == 0) {
        return false;
    }

    endpoint_ptr++;
    uint32_t parsed = 0;
    while (*endpoint_ptr != 0) {
        if (*endpoint_ptr < '0' || *endpoint_ptr > '9') {
            return false;
        }
        parsed = (parsed * 10U) + static_cast<uint32_t>(*endpoint_ptr - '0');
        if (parsed > 65535U) {
            return false;
        }
        endpoint_ptr++;
    }

    endpoint_out = static_cast<uint16_t>(parsed);
    return true;
}

inline bool IsTidAllowedForIncomingEndpoint(uint16_t tid, uint16_t endpoint)
{
    bool is_root_ep = (endpoint == 0);
    bool is_data_ep = !is_root_ep;
    return SigNet::Node::IsTidAllowedForEndpoint(tid, is_root_ep, is_data_ep);
}

inline bool IsTidAllowedForUriLane(const char* uri, uint16_t tid)
{
    if (!uri) {
        return false;
    }

    if (strstr(uri, "/poll") != 0) {
        return (tid == SigNet::TID_POLL);
    }

    if (strstr(uri, "/manager/") != 0) {
        if (tid == SigNet::TID_LEVEL || tid == SigNet::TID_PRIORITY ||
            tid == SigNet::TID_SYNC || tid == SigNet::TID_TIMECODE ||
            tid == SigNet::TID_OSC) {
            return false;
        }
        return true;
    }

    if (strstr(uri, "/node/") != 0) {
        return false;
    }

    if (strstr(uri, "/level/") != 0) {
        return (tid == SigNet::TID_LEVEL);
    }
    if (strstr(uri, "/priority/") != 0) {
        return (tid == SigNet::TID_PRIORITY);
    }
    if (strstr(uri, "/sync") != 0) {
        return (tid == SigNet::TID_SYNC);
    }
    if (strstr(uri, "/timecode/") != 0) {
        return (tid == SigNet::TID_TIMECODE);
    }
    if (strstr(uri, "/aux/") != 0) {
        return (tid == SigNet::TID_OSC);
    }

    return false;
}

struct SessionTrackEntry {
    bool used;
    uint8_t sender_tuid[6];
    uint32_t session_id;
    uint32_t last_seen_ms;
};

struct SequenceTrackEntry {
    bool used;
    uint8_t sender_id[8];
    uint32_t session_id;
    uint32_t sequence_num;
    uint32_t last_seen_ms;
};

struct FreshnessTracker {
    SessionTrackEntry session_tracks[32];
    SequenceTrackEntry sequence_tracks[32];
};

inline void ResetFreshnessTracker(FreshnessTracker& tracker)
{
    memset(&tracker, 0, sizeof(tracker));
}

inline int FindSessionTrack(const FreshnessTracker& tracker, const uint8_t sender_tuid[6])
{
    int i;
    for (i = 0; i < 32; ++i) {
        if (tracker.session_tracks[i].used && memcmp(tracker.session_tracks[i].sender_tuid, sender_tuid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

inline int FindSequenceTrack(const FreshnessTracker& tracker, const uint8_t sender_id[8])
{
    int i;
    for (i = 0; i < 32; ++i) {
        if (tracker.sequence_tracks[i].used && memcmp(tracker.sequence_tracks[i].sender_id, sender_id, 8) == 0) {
            return i;
        }
    }
    return -1;
}

inline int AcquireSessionTrackSlot(const FreshnessTracker& tracker, uint32_t now_ms)
{
    int i;
    int oldest_index = -1;
    uint32_t oldest_age = 0;
    for (i = 0; i < 32; ++i) {
        if (!tracker.session_tracks[i].used) {
            return i;
        }
        uint32_t age = now_ms - tracker.session_tracks[i].last_seen_ms;
        if (age > oldest_age) {
            oldest_age = age;
            oldest_index = i;
        }
    }

    if (oldest_index >= 0 && oldest_age >= 3600000UL) {
        return oldest_index;
    }
    return -1;
}

inline int AcquireSequenceTrackSlot(const FreshnessTracker& tracker, uint32_t now_ms)
{
    int i;
    int oldest_index = -1;
    uint32_t oldest_age = 0;
    for (i = 0; i < 32; ++i) {
        if (!tracker.sequence_tracks[i].used) {
            return i;
        }
        uint32_t age = now_ms - tracker.sequence_tracks[i].last_seen_ms;
        if (age > oldest_age) {
            oldest_age = age;
            oldest_index = i;
        }
    }

    if (oldest_index >= 0 && oldest_age >= 3600000UL) {
        return oldest_index;
    }
    return -1;
}

inline bool ValidateAndCommitFreshness(FreshnessTracker& tracker,
                                       const SigNet::SigNetOptions& options,
                                       uint32_t now_ms)
{
    const uint8_t* sender_tuid = options.sender_id;

    int session_index = FindSessionTrack(tracker, sender_tuid);
    if (session_index >= 0) {
        if (options.session_id < tracker.session_tracks[session_index].session_id) {
            return false;
        }
    } else {
        session_index = AcquireSessionTrackSlot(tracker, now_ms);
        if (session_index < 0) {
            return false;
        }
        tracker.session_tracks[session_index].used = true;
        memcpy(tracker.session_tracks[session_index].sender_tuid, sender_tuid, 6);
        tracker.session_tracks[session_index].session_id = 0;
    }

    int sequence_index = FindSequenceTrack(tracker, options.sender_id);
    if (sequence_index >= 0) {
        if (options.session_id < tracker.sequence_tracks[sequence_index].session_id) {
            return false;
        }
        if (options.session_id == tracker.sequence_tracks[sequence_index].session_id &&
            options.seq_num <= tracker.sequence_tracks[sequence_index].sequence_num) {
            return false;
        }
    } else {
        sequence_index = AcquireSequenceTrackSlot(tracker, now_ms);
        if (sequence_index < 0) {
            return false;
        }
        tracker.sequence_tracks[sequence_index].used = true;
        memcpy(tracker.sequence_tracks[sequence_index].sender_id, options.sender_id, 8);
        tracker.sequence_tracks[sequence_index].session_id = 0;
        tracker.sequence_tracks[sequence_index].sequence_num = 0;
    }

    tracker.session_tracks[session_index].session_id = options.session_id;
    tracker.session_tracks[session_index].last_seen_ms = now_ms;

    tracker.sequence_tracks[sequence_index].session_id = options.session_id;
    tracker.sequence_tracks[sequence_index].sequence_num = options.seq_num;
    tracker.sequence_tracks[sequence_index].last_seen_ms = now_ms;

    return true;
}

} // namespace Node
} // namespace SigNet

#endif // SIGNET_NODE_UDP_LISTEN_HPP
