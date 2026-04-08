//==============================================================================
// Sig-Net Protocol Framework - CoAP Packet Building Implementation
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
// Description:  CoAP packet construction implementation with extended delta
//               encoding and URI-Path option building for Sig-Net packets.
//               Implements RFC 7252 CoAP protocol requirements.
//==============================================================================

#include "sig-net-coap.hpp"
#include <stdio.h>
#include <string.h>

// Network byte order functions (htons, htonl)
#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <arpa/inet.h>
#endif

namespace SigNet {
namespace CoAP {

//------------------------------------------------------------------------------
// Build CoAP Header
//------------------------------------------------------------------------------
int32_t BuildCoAPHeader(
    PacketBuffer& buffer,
    uint16_t message_id
) {
    CoAPHeader header;
    
    // Set version (2 bits) = 1
    header.SetVersion(COAP_VERSION);
    
    // Set type (2 bits) = NON (1)
    header.SetType(COAP_TYPE_NON);
    
    // Set token length (4 bits) = 0 (no token)
    header.SetTokenLength(0);
    
    // Set code = POST (0x02)
    header.code = COAP_CODE_POST;
    
    // Set message ID (network byte order)
    header.message_id = htons(message_id);
    
    // Write header to buffer (4 bytes)
    return buffer.WriteBytes(reinterpret_cast<const uint8_t*>(&header), COAP_HEADER_SIZE);
}

//------------------------------------------------------------------------------
// Encode CoAP Option (RFC 7252 Section 3.1)
//
// Option format:
//   0   1   2   3   4   5   6   7
// +---------------+---------------+
// |  Option Delta | Option Length |  1 byte
// +---------------+---------------+
// \    Option Delta (extended)    \  0-2 bytes
// +-------------------------------+
// \    Option Length (extended)   \  0-2 bytes
// +-------------------------------+
// \         Option Value          \  0 or more bytes
// +-------------------------------+
//
// Delta/Length encoding:
//   0-12: Value fits in 4-bit field
//   13:   8-bit extended value follows (actual value = extended + 13)
//   14:   16-bit extended value follows (actual value = extended + 269)
//   15:   Reserved (payload marker or error)
//------------------------------------------------------------------------------
int32_t EncodeCoAPOption(
    PacketBuffer& buffer,
    uint16_t option_number,
    uint16_t prev_option,
    const uint8_t* option_value,
    uint16_t option_length
) {
    if (option_number < prev_option) {
        return SIGNET_ERROR_ENCODE;  // Options must be in ascending order
    }
    
    // Calculate delta from previous option
    uint16_t delta = option_number - prev_option;
    
    // Determine delta encoding format
    uint8_t delta_nibble;
    uint8_t delta_ext_size = GetDeltaExtendedSize(delta);
    uint16_t delta_ext_value = 0;
    
    if (delta <= COAP_OPTION_INLINE_MAX) {
        delta_nibble = static_cast<uint8_t>(delta);
    } else if (delta < COAP_OPTION_EXT16_BASE) {
        delta_nibble = COAP_OPTION_EXT8_NIBBLE;
        delta_ext_value = delta - COAP_OPTION_EXT8_BASE;
    } else {
        delta_nibble = COAP_OPTION_EXT16_NIBBLE;
        delta_ext_value = delta - COAP_OPTION_EXT16_BASE;
    }
    
    // Determine length encoding format
    uint8_t length_nibble;
    uint8_t length_ext_size = GetLengthExtendedSize(option_length);
    uint16_t length_ext_value = 0;
    
    if (option_length <= COAP_OPTION_INLINE_MAX) {
        length_nibble = static_cast<uint8_t>(option_length);
    } else if (option_length < COAP_OPTION_EXT16_BASE) {
        length_nibble = COAP_OPTION_EXT8_NIBBLE;
        length_ext_value = option_length - COAP_OPTION_EXT8_BASE;
    } else {
        length_nibble = COAP_OPTION_EXT16_NIBBLE;
        length_ext_value = option_length - COAP_OPTION_EXT16_BASE;
    }
    
    // Write option header byte (delta nibble | length nibble)
    uint8_t header_byte = (delta_nibble << 4) | length_nibble;
    int32_t result = buffer.WriteByte(header_byte);
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    
    // Write extended delta if needed
    if (delta_ext_size == 1) {
        result = buffer.WriteByte(static_cast<uint8_t>(delta_ext_value));
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    } else if (delta_ext_size == 2) {
        result = buffer.WriteUInt16(delta_ext_value);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }
    
    // Write extended length if needed
    if (length_ext_size == 1) {
        result = buffer.WriteByte(static_cast<uint8_t>(length_ext_value));
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    } else if (length_ext_size == 2) {
        result = buffer.WriteUInt16(length_ext_value);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }
    
    // Write option value
    if (option_length > 0) {
        if (!option_value) {
            return SIGNET_ERROR_INVALID_ARG;
        }
        result = buffer.WriteBytes(option_value, option_length);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Build URI-Path Options for Sig-Net
// 
// Constructs: /sig-net/v1/level/{universe}
// As 4 separate Uri-Path options (Option 11):
//   1. "sig-net"
//   2. "v1"
//   3. "level"
//   4. "{universe}" (as ASCII decimal string)
//------------------------------------------------------------------------------
int32_t BuildURIPathOptions(
    PacketBuffer& buffer,
    uint16_t universe
) {
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    int32_t result;
    uint16_t prev_option = 0;  // No options before Uri-Path
    
    // Option 1: "sig-net"
    result = EncodeCoAPOption(
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
    
    // Option 2: "v1"
    result = EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_VERSION),
        strlen(SIGNET_URI_VERSION)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    // prev_option remains COAP_OPTION_URI_PATH (delta = 0)
    
    // Option 3: "level"
    result = EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(SIGNET_URI_LEVEL),
        strlen(SIGNET_URI_LEVEL)
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    // prev_option remains COAP_OPTION_URI_PATH
    
    // Option 4: universe number as ASCII decimal string
    char universe_str[UNIVERSE_DECIMAL_BUFFER_SIZE];
    snprintf(universe_str, sizeof(universe_str), "%u", universe);
    
    result = EncodeCoAPOption(
        buffer,
        COAP_OPTION_URI_PATH,
        prev_option,
        reinterpret_cast<const uint8_t*>(universe_str),
        strlen(universe_str)
    );
    
    return result;
}

//------------------------------------------------------------------------------
// Build URI String for HMAC Calculation
// 
// Returns: "/sig-net/v1/level/{universe}"
// This is used as part of the HMAC input per Section 8.5
//------------------------------------------------------------------------------
int32_t BuildURIString(
    uint16_t universe,
    char* uri_output,
    uint32_t max_length
) {
    if (!uri_output || max_length < URI_STRING_MIN_BUFFER) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Build URI string: "/sig-net/v1/level/{universe}"
    int written = snprintf(
        uri_output,
        max_length,
        "/%s/%s/%s/%u",
        SIGNET_URI_PREFIX,
        SIGNET_URI_VERSION,
        SIGNET_URI_LEVEL,
        universe
    );
    
    if (written < 0 || static_cast<uint32_t>(written) >= max_length) {
        return SIGNET_ERROR_ENCODE;
    }
    
    return SIGNET_SUCCESS;
}

} // namespace CoAP
} // namespace SigNet
