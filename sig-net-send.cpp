//==============================================================================
// Sig-Net Protocol Framework - Packet Assembly Implementation
//==============================================================================
//
// Copyright (c) 2026 Singularity (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//==============================================================================
// Author:       Wayne Howell
// Date:         March 28, 2026
// Description:  High-level packet assembly orchestrating CoAP, security, HMAC,
//               and TLV components. Multicast address calculation and sequence
//               number management for Sig-Net transmitter applications.
//==============================================================================

#include "sig-net-send.hpp"
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

namespace SigNet {

//------------------------------------------------------------------------------
// Calculate Multicast Address (String Format)
//------------------------------------------------------------------------------
int32_t CalculateMulticastAddress(
    uint16_t universe,
    char* ip_output
) {
    if (!ip_output) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Multicast Folding Formula: Index = ((Universe - 1) % 100) + 1
    uint8_t index = static_cast<uint8_t>(((universe - 1) % 100) + 1);
    
    // Build IP address using proper network functions
    struct in_addr addr;
    addr.S_un.S_un_b.s_b1 = MULTICAST_BASE_OCTET_0;
    addr.S_un.S_un_b.s_b2 = MULTICAST_BASE_OCTET_1;
    addr.S_un.S_un_b.s_b3 = MULTICAST_BASE_OCTET_2;
    addr.S_un.S_un_b.s_b4 = index;
    
    // Use inet_ntoa to convert to string
    char* ip_str = inet_ntoa(addr);
    if (ip_str) {
        strcpy(ip_output, ip_str);
    } else {
        // Fallback if inet_ntoa fails
        sprintf(ip_output, "239.254.0.%d", (int)index);
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Get Multicast IP Octets (for direct socket API use)
//------------------------------------------------------------------------------
int32_t GetMulticastOctets(
    uint16_t universe,
    uint8_t* octet0,
    uint8_t* octet1,
    uint8_t* octet2,
    uint8_t* octet3
) {
    if (!octet0 || !octet1 || !octet2 || !octet3) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Multicast Folding Formula
    uint8_t index = static_cast<uint8_t>(((universe - 1) % 100) + 1);
    
    *octet0 = MULTICAST_BASE_OCTET_0;  // 239
    *octet1 = MULTICAST_BASE_OCTET_1;  // 254
    *octet2 = MULTICAST_BASE_OCTET_2;  // 0
    *octet3 = index;                    // 1-100
    
    return SIGNET_SUCCESS;
}

    int32_t ExtractIPv4Token(
        const char* raw,
        char* token_output,
        uint32_t output_size
    ) {
        if (!token_output || output_size == 0) {
            return SIGNET_ERROR_INVALID_ARG;
        }

        token_output[0] = '\0';
        if (!raw) {
            return SIGNET_ERROR_INVALID_ARG;
        }

        const char* cursor = raw;
        while (*cursor != '\0') {
            char c = *cursor;
            if ((c >= '0' && c <= '9') || c == '.') {
                break;
            }
            cursor++;
        }

        if (*cursor == '\0') {
            return SIGNET_SUCCESS;
        }

        uint32_t out_pos = 0;
        while (*cursor != '\0') {
            char c = *cursor;
            if (!((c >= '0' && c <= '9') || c == '.')) {
                break;
            }
            if (out_pos + 1 >= output_size) {
                return SIGNET_ERROR_ENCODE;
            }
            token_output[out_pos++] = c;
            cursor++;
        }

        token_output[out_pos] = '\0';
        return SIGNET_SUCCESS;
    }

//------------------------------------------------------------------------------
// Build Common Sig-Net Options (without HMAC)
//------------------------------------------------------------------------------
int32_t BuildCommonSigNetOptions(
    PacketBuffer& buffer,
    const uint8_t* tuid,
    uint16_t endpoint,
    uint16_t mfg_code,
    uint32_t session_id,
    uint32_t seq_num,
    SigNetOptions* options_output
) {
    if (!tuid || !options_output) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    options_output->security_mode = SECURITY_MODE_HMAC_SHA256;
    options_output->mfg_code = mfg_code;
    options_output->session_id = session_id;
    options_output->seq_num = seq_num;

    int32_t result = Security::BuildSenderID(tuid, endpoint, options_output->sender_id);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    return Security::BuildSigNetOptionsWithoutHMAC(
        buffer,
        *options_output,
        COAP_OPTION_URI_PATH
    );
}

//------------------------------------------------------------------------------
// Build Node URI-Path Options and URI String (/sig-net/v1/{scope}/node/{tuid}/{endpoint})
//------------------------------------------------------------------------------
int32_t BuildNodeURIPathOptions(
    PacketBuffer& buffer,
    const uint8_t* tuid,
    uint16_t endpoint,
    char* uri_output,
    uint32_t uri_output_size
) {
    if (!tuid || !uri_output || uri_output_size == 0) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    char tuid_hex[TUID_HEX_LENGTH + 1];
    tuid_hex[TUID_HEX_LENGTH] = '\0';
    Crypto::TUID_ToHexString(tuid, tuid_hex);

    char endpoint_str[6];
    int endpoint_written = snprintf(endpoint_str, sizeof(endpoint_str), "%u", endpoint);
    if (endpoint_written <= 0 || endpoint_written >= static_cast<int>(sizeof(endpoint_str))) {
        return SIGNET_ERROR_ENCODE;
    }

    int uri_written = snprintf(
        uri_output,
        uri_output_size,
        "/%s/%s/%s/%s/%s/%s",
        SIGNET_URI_PREFIX,
        SIGNET_URI_VERSION,
        CoAP::GetURIScope(),
        SIGNET_URI_NODE,
        tuid_hex,
        endpoint_str
    );
    if (uri_written < 0 || static_cast<uint32_t>(uri_written) >= uri_output_size) {
        return SIGNET_ERROR_ENCODE;
    }

    uint16_t prev_option = 0;
    int32_t result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_PREFIX),
        strlen(SIGNET_URI_PREFIX)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    prev_option = COAP_OPTION_URI_PATH;

    result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_VERSION),
        strlen(SIGNET_URI_VERSION)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(CoAP::GetURIScope()),
        strlen(CoAP::GetURIScope())
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_NODE),
        strlen(SIGNET_URI_NODE)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(tuid_hex),
        strlen(tuid_hex)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    return CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(endpoint_str),
        strlen(endpoint_str)
    );
}

//------------------------------------------------------------------------------
// Build Poll URI-Path Options and URI String (/sig-net/v1/{scope}/poll)
//------------------------------------------------------------------------------
static int32_t BuildPollURIPathOptions(
    PacketBuffer& buffer,
    char* uri_output,
    uint32_t uri_output_size
) {
    if (!uri_output || uri_output_size == 0) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    int uri_written = snprintf(
        uri_output,
        uri_output_size,
        "/%s/%s/%s/%s",
        SIGNET_URI_PREFIX,
        SIGNET_URI_VERSION,
        CoAP::GetURIScope(),
        SIGNET_URI_POLL
    );
    if (uri_written < 0 || static_cast<uint32_t>(uri_written) >= uri_output_size) {
        return SIGNET_ERROR_ENCODE;
    }

    uint16_t prev_option = 0;
    int32_t result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_PREFIX),
        strlen(SIGNET_URI_PREFIX)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    prev_option = COAP_OPTION_URI_PATH;

    result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_VERSION),
        strlen(SIGNET_URI_VERSION)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    result = CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(CoAP::GetURIScope()),
        strlen(CoAP::GetURIScope())
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    return CoAP::EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_POLL),
        strlen(SIGNET_URI_POLL)
    );
}

//------------------------------------------------------------------------------
// Finalize Packet: HMAC option + payload marker + payload
//------------------------------------------------------------------------------
int32_t FinalizePacketWithHMACAndPayload(
    PacketBuffer& buffer,
    const char* uri_string,
    SigNetOptions& options,
    const uint8_t* payload_data,
    uint16_t payload_len,
    const uint8_t* signing_key
) {
    if (!uri_string || !signing_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    if (payload_len > 0 && !payload_data) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    int32_t result = Security::CalculateAndEncodeHMAC(
        buffer,
        uri_string,
        options,
        payload_data,
        payload_len,
        signing_key,
        SIGNET_OPTION_SEQ_NUM
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    if (payload_len > 0) {
        result = buffer.WriteByte(COAP_PAYLOAD_MARKER);
        if (result != SIGNET_SUCCESS) {
            return result;
        }

        result = buffer.WriteBytes(payload_data, payload_len);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Build Complete DMX Packet
//------------------------------------------------------------------------------
int32_t BuildDMXPacket(
    PacketBuffer& buffer,
    uint16_t universe,
    const uint8_t* dmx_data,
    uint16_t slot_count,
    const uint8_t* tuid,
    uint16_t endpoint,
    uint16_t mfg_code,
    uint32_t session_id,
    uint32_t seq_num,
    const uint8_t* sender_key,
    uint16_t message_id
) {
    // Validate inputs
    if (!dmx_data || !tuid || !sender_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (slot_count < 1 || slot_count > MAX_DMX_SLOTS) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Reset buffer for new packet
    buffer.Reset();
    
    int32_t result = CoAP::BuildCoAPHeader(buffer, message_id);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    result = CoAP::BuildURIPathOptions(buffer, universe);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    SigNetOptions options;
    result = BuildCommonSigNetOptions(
        buffer,
        tuid,
        endpoint,
        mfg_code,
        session_id,
        seq_num,
        &options
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    PacketBuffer payload;
    result = TLV::BuildDMXLevelPayload(payload, dmx_data, slot_count);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    char uri_string[URI_STRING_MIN_BUFFER];
    result = CoAP::BuildURIString(universe, uri_string, sizeof(uri_string));
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    return FinalizePacketWithHMACAndPayload(
        buffer,
        uri_string,
        options,
        payload.GetBuffer(),
        payload.GetSize(),
        sender_key
    );
}

//------------------------------------------------------------------------------
// Build Startup Announce Packet
//------------------------------------------------------------------------------
int32_t BuildAnnouncePacket(
    PacketBuffer& buffer,
    const uint8_t* tuid,
    uint16_t mfg_code,
    uint16_t product_variant_id,
    uint16_t firmware_version_id,
    const char* firmware_version_string,
    uint8_t protocol_version,
    uint8_t role_capability_bits,
    uint16_t change_count,
    uint32_t session_id,
    uint32_t seq_num,
    const uint8_t* citizen_key,
    uint16_t message_id
) {
    if (!tuid || !firmware_version_string || !citizen_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    buffer.Reset();
    int32_t result = CoAP::BuildCoAPHeader(buffer, message_id);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    char uri_string[URI_STRING_MIN_BUFFER];
    result = BuildNodeURIPathOptions(buffer, tuid, 0, uri_string, sizeof(uri_string));
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    SigNetOptions options;
    result = BuildCommonSigNetOptions(
        buffer,
        tuid,
        0,
        mfg_code,
        session_id,
        seq_num,
        &options
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    PacketBuffer payload;
    result = TLV::BuildStartupAnnouncePayload(
        payload,
        tuid,
        mfg_code,
        product_variant_id,
        firmware_version_id,
        firmware_version_string,
        protocol_version,
        role_capability_bits,
        change_count
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    const uint8_t* payload_data = payload.GetBuffer();
    uint16_t payload_len = payload.GetSize();


    return FinalizePacketWithHMACAndPayload(
        buffer,
        uri_string,
        options,
        payload_data,
        payload_len,
        citizen_key
    );
}

//------------------------------------------------------------------------------
// Build Manager Poll Packet (/sig-net/v1/{scope}/poll)
//------------------------------------------------------------------------------
int32_t BuildPollPacket(
    PacketBuffer& buffer,
    const uint8_t* manager_tuid,
    uint16_t mfg_code,
    uint16_t product_variant_id,
    const uint8_t* tuid_lo,
    const uint8_t* tuid_hi,
    uint16_t target_endpoint,
    uint8_t query_level,
    uint32_t session_id,
    uint32_t seq_num,
    const uint8_t* manager_global_key,
    uint16_t message_id
) {
    if (!manager_tuid || !tuid_lo || !tuid_hi || !manager_global_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    if (query_level > QUERY_EXTENDED) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    buffer.Reset();
    int32_t result = CoAP::BuildCoAPHeader(buffer, message_id);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    char uri_string[URI_STRING_MIN_BUFFER];
    result = BuildPollURIPathOptions(buffer, uri_string, sizeof(uri_string));
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    SigNetOptions options;
    result = BuildCommonSigNetOptions(
        buffer,
        manager_tuid,
        0,
        0x0000,
        session_id,
        seq_num,
        &options
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    PacketBuffer payload;
    result = TLV::BuildPollPayload(
        payload,
        manager_tuid,
        mfg_code,
        product_variant_id,
        tuid_lo,
        tuid_hi,
        target_endpoint,
        query_level
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    return FinalizePacketWithHMACAndPayload(
        buffer,
        uri_string,
        options,
        payload.GetBuffer(),
        payload.GetSize(),
        manager_global_key
    );
}

} // namespace SigNet
