//==============================================================================
// Sig-Net Protocol Framework - Master Include File
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
// Description:  Master include file for Sig-Net C++ Helper Library.
//               Provides all functionality for constructing and transmitting
//               authenticated Sig-Net packets for entertainment lighting control.
//==============================================================================

#ifndef SIGNET_HPP
#define SIGNET_HPP
//
// USAGE EXAMPLE:
// --------------
//
//   #include "sig-net.hpp"
//   using namespace SigNet;
//
//   // 1. Derive sender key from K0 root key
//   uint8_t k0[32] = { /* your 256-bit root key */ };
//   uint8_t sender_key[32];
//   Crypto::DeriveSenderKey(k0, sender_key);
//
//   // 2. Prepare packet parameters
//   uint16_t universe = 517;
//   uint8_t dmx_data[512] = { /* your DMX values */ };
//   uint16_t slot_count = 512;
//   uint8_t tuid[6] = { 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC };
//   uint16_t endpoint = 0;
//   uint16_t mfg_code = 0x0000;  // Standard message
//   uint32_t session_id = 1;     // Boot counter from NVM
//   uint32_t seq_num = 1;        // Sequence counter
//   uint16_t message_id = 1;     // CoAP message ID
//
//   // 3. Build packet
//   PacketBuffer buffer;
//   int32_t result = BuildDMXPacket(
//       buffer, universe, dmx_data, slot_count,
//       tuid, endpoint, mfg_code,
//       session_id, seq_num, sender_key, message_id
//   );
//
//   // 4. Get multicast address
//   char multicast_ip[16];
//   CalculateMulticastAddress(universe, multicast_ip, sizeof(multicast_ip));
//
//   // 5. Send via UDP (using your UDP component)
//   if (result == SIGNET_SUCCESS) {
//       // Send buffer.GetBuffer(), buffer.GetSize() bytes
//       // to multicast_ip:5683
//       udp->RemoteHost = multicast_ip;
//       udp->RemotePort = SIGNET_UDP_PORT;
//       udp->SendBytes((char*)buffer.GetBuffer(), buffer.GetSize());
//   }
//
//   // 6. Increment sequence for next packet
//   seq_num = IncrementSequence(seq_num);
//
// FEATURES:
// ---------
// - CoAP packet construction (RFC 7252)
// - HMAC-SHA256 authentication (RFC 2104)
// - HKDF key derivation (RFC 5869)
// - TLV payload encoding
// - Multicast address calculation
// - Sequence number management
//
// REQUIREMENTS:
// -------------
// - mbedTLS library (for HMAC-SHA256)
// - C++Builder 11.1 or compatible C++ compiler
// - Network library for UDP transmission (e.g., IPWorks TipwUDPPort)
//
// PROTOCOL SPECIFICATION:
// -----------------------
// Based on CoAP (RFC 7252) with custom security options
//
//==============================================================================

// Include all Sig-Net modules
#include "sig-net-constants.hpp"
#include "sig-net-types.hpp"
#include "sig-net-crypto.hpp"
#include "sig-net-coap.hpp"
#include "sig-net-security.hpp"
#include "sig-net-tlv.hpp"
#include "sig-net-send.hpp"
#include "sig-net-selftest.hpp"

//==============================================================================
// Version Information
//==============================================================================

namespace SigNet {

static const char* LIBRARY_VERSION = "0.3";
static const char* PROTOCOL_VERSION = "0.15";

// Get library version string
inline const char* GetLibraryVersion() {
    return LIBRARY_VERSION;
}

// Get protocol version string
inline const char* GetProtocolVersion() {
    return PROTOCOL_VERSION;
}


//==============================================================================
// Passphrase Validation Result Codes
// Returned by Crypto::ValidatePassphrase() and Crypto::GetPassphraseValidationReport()
// These mirror the constants in sig-net-constants.hpp for convenient reference.
//==============================================================================

enum PassphraseResult {
    PASSPHRASE_VALID              =  0,  // All requirements met - K0 derivation allowed
    PASSPHRASE_TOO_SHORT          = -10, // Length < 10 characters
    PASSPHRASE_TOO_LONG           = -11, // Length > 64 characters
    PASSPHRASE_INSUFFICIENT_CLASS = -12, // Fewer than 3 of 4 classes (U/L/D/S) present
    PASSPHRASE_CONSECUTIVE_SAME   = -13, // 3+ consecutive identical characters (e.g., "aaa")
    PASSPHRASE_CONSECUTIVE_SEQ    = -14  // 4+ consecutive sequential characters (e.g., "abcd", "1234")
};


} // namespace SigNet

#endif // SIGNET_HPP
