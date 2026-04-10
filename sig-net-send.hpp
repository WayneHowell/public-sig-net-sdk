//==============================================================================
// Sig-Net Protocol Framework - Packet Assembly and Transmission
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
//               Orchestrates CoAP, security, HMAC, and TLV components.
//               Includes multicast address calculation and sequence management.
//==============================================================================

#ifndef SIGNET_SEND_HPP
#define SIGNET_SEND_HPP

#include "sig-net-constants.hpp"
#include "sig-net-types.hpp"
#include "sig-net-crypto.hpp"
#include "sig-net-coap.hpp"
#include "sig-net-security.hpp"
#include "sig-net-tlv.hpp"
#include <stdint.h>

namespace SigNet {

//------------------------------------------------------------------------------
// Multicast Address Calculation
//------------------------------------------------------------------------------

// Calculate multicast IP address for a given universe (Section 9.2.3)
// 
// Multicast Folding Formula:
//   Index = ((Universe - 1) % 100) + 1
//   IP Address = 239.254.0.{Index}
//
// Examples:
//   Universe 1    -> 239.254.0.1
//   Universe 100  -> 239.254.0.100
//   Universe 101  -> 239.254.0.1
//   Universe 517  -> 239.254.0.18
//
// Parameters:
//   universe    - Universe number (1-63999)
//   ip_output   - Buffer to receive IP address string (must be at least 16 bytes)
//
// Returns:
//   SIGNET_SUCCESS on success
//   SIGNET_ERROR_INVALID_ARG if universe out of range
int32_t CalculateMulticastAddress(
    uint16_t universe,
    char* ip_output
);

// Get multicast IP octets (for direct use with socket APIs)
int32_t GetMulticastOctets(
    uint16_t universe,
    uint8_t* octet0,
    uint8_t* octet1,
    uint8_t* octet2,
    uint8_t* octet3
);

int32_t ExtractIPv4Token(
    const char* raw,
    char* token_output,
    uint32_t output_size
);

//------------------------------------------------------------------------------
// Packet Building
//------------------------------------------------------------------------------

// Build and encode Sig-Net options up to Seq-Num (without HMAC).
// Also returns the filled SigNetOptions struct for later HMAC calculation.
int32_t BuildCommonSigNetOptions(
    PacketBuffer& buffer,
    const uint8_t* tuid,
    uint16_t endpoint,
    uint16_t mfg_code,
    uint32_t session_id,
    uint32_t seq_num,
    SigNetOptions* options_output
);

// Build URI-Path options for /sig-net/v1/node/{tuid}/{endpoint}
// and also write the same URI string to uri_output for HMAC input.
int32_t BuildNodeURIPathOptions(
    PacketBuffer& buffer,
    const uint8_t* tuid,
    uint16_t endpoint,
    char* uri_output,
    uint32_t uri_output_size
);

// Finalize a packet by encoding HMAC option then payload marker+payload.
int32_t FinalizePacketWithHMACAndPayload(
    PacketBuffer& buffer,
    const char* uri_string,
    SigNetOptions& options,
    const uint8_t* payload_data,
    uint16_t payload_len,
    const uint8_t* signing_key
);

// Build a complete SigNet packet for DMX level transmission
// 
// This function orchestrates the entire packet construction process:
//   1. CoAP header
//   2. Uri-Path options (/SigNet/v1/level/{universe})
//   3. SigNet custom options (Security-Mode, Sender-ID, Mfg-Code, Session-ID, Seq-Num)
//   4. TLV payload (TID_LEVEL with DMX data)
//   5. HMAC calculation and encoding
//
// Parameters:
//   buffer      - Packet buffer to construct packet in (will be reset)
//   universe    - Universe number (1-63999)
//   dmx_data    - DMX slot values (0-255)
//   slot_count  - Number of DMX slots (1-512)
//   tuid        - Transmitter Unique ID (6 bytes)
//   endpoint    - Endpoint number (16-bit)
//   mfg_code    - ESTA Manufacturer Code (0x0000 for standard messages)
//   session_id  - Session ID (boot counter, persisted in NVM)
//   seq_num     - Sequence number (auto-increments per packet)
//   sender_key  - Derived sender key (Ks, 32 bytes)
//   message_id  - CoAP message ID (typically incrementing counter)
//
// Returns:
//   SIGNET_SUCCESS on success
//   Error code on failure
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
);

// Build startup announce packet (/sig-net/v1/node/{tuid}/0) signed with Kc.
// Payload TLVs are packed in this order:
//   1) TID_POLL_REPLY
//   2) TID_RT_FIRMWARE_VERSION
//   3) TID_RT_PROTOCOL_VERSION
//   4) TID_RT_ROLE_CAPABILITY
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
);

// Build manager poll packet (/sig-net/v1/poll) containing a TID_POLL TLV,
// signed with Km_global.
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
);

//------------------------------------------------------------------------------
// Sequence Number Management
//------------------------------------------------------------------------------

// Increment sequence number with rollover handling
// Returns the new sequence number after increment
//
// When sequence reaches 0xFFFFFFFF, the caller should:
//   1. Increment session_id
//   2. Persist new session_id to NVM
//   3. Reset sequence to 1 (not 0)
inline uint32_t IncrementSequence(uint32_t current_seq) {
    if (current_seq == 0xFFFFFFFF) {
        return 1;  // Rollover to 1 (not 0)
    }
    return current_seq + 1;
}

// Check if sequence number has rolled over and session should increment
inline bool ShouldIncrementSession(uint32_t seq_num) {
    return (seq_num == 0xFFFFFFFF);
}

} // namespace SigNet

#endif // SIGNET_SEND_HPP
