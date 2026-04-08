//==============================================================================
// Sig-Net Protocol Framework - Security Layer Implementation
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
// Description:  Implementation of Sig-Net custom CoAP options encoding and
//               HMAC-SHA256 signature calculation per Section 8.5 of spec.
//               Handles Security-Mode, Sender-ID, Mfg-Code, Session, Seq, HMAC.
//==============================================================================

#include "sig-net-security.hpp"
#include <string.h>

namespace SigNet {
namespace Security {

//------------------------------------------------------------------------------
// Build SigNet Custom Options (Without HMAC)
//------------------------------------------------------------------------------
int32_t BuildSigNetOptionsWithoutHMAC(
    PacketBuffer& buffer,
    const SigNetOptions& options,
    uint16_t prev_option
) {
    int32_t result;
    
    // Option 1: Security-Mode (2076) - 1 byte
    result = CoAP::EncodeCoAPOption(
        buffer,
        SIGNET_OPTION_SECURITY_MODE,
        prev_option,
        &options.security_mode,
        1
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    prev_option = SIGNET_OPTION_SECURITY_MODE;
    
    // Option 2: Sender-ID (2108) - 8 bytes (TUID + endpoint)
    result = CoAP::EncodeCoAPOption(
        buffer,
        SIGNET_OPTION_SENDER_ID,
        prev_option,
        options.sender_id,
        SENDER_ID_LENGTH
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    prev_option = SIGNET_OPTION_SENDER_ID;
    
    // Option 3: Mfg-Code (2140) - 2 bytes (network byte order)
    uint8_t mfg_code_bytes[2];
    mfg_code_bytes[0] = static_cast<uint8_t>((options.mfg_code >> 8) & 0xFF);
    mfg_code_bytes[1] = static_cast<uint8_t>(options.mfg_code & 0xFF);
    
    result = CoAP::EncodeCoAPOption(
        buffer,
        SIGNET_OPTION_MFG_CODE,
        prev_option,
        mfg_code_bytes,
        2
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    prev_option = SIGNET_OPTION_MFG_CODE;
    
    // Option 4: Session-ID (2172) - 4 bytes (network byte order)
    uint8_t session_id_bytes[4];
    session_id_bytes[0] = static_cast<uint8_t>((options.session_id >> 24) & 0xFF);
    session_id_bytes[1] = static_cast<uint8_t>((options.session_id >> 16) & 0xFF);
    session_id_bytes[2] = static_cast<uint8_t>((options.session_id >> 8) & 0xFF);
    session_id_bytes[3] = static_cast<uint8_t>(options.session_id & 0xFF);
    
    result = CoAP::EncodeCoAPOption(
        buffer,
        SIGNET_OPTION_SESSION_ID,
        prev_option,
        session_id_bytes,
        4
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    prev_option = SIGNET_OPTION_SESSION_ID;
    
    // Option 5: Seq-Num (2204) - 4 bytes (network byte order)
    uint8_t seq_num_bytes[4];
    seq_num_bytes[0] = static_cast<uint8_t>((options.seq_num >> 24) & 0xFF);
    seq_num_bytes[1] = static_cast<uint8_t>((options.seq_num >> 16) & 0xFF);
    seq_num_bytes[2] = static_cast<uint8_t>((options.seq_num >> 8) & 0xFF);
    seq_num_bytes[3] = static_cast<uint8_t>(options.seq_num & 0xFF);
    
    result = CoAP::EncodeCoAPOption(
        buffer,
        SIGNET_OPTION_SEQ_NUM,
        prev_option,
        seq_num_bytes,
        4
    );
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    
    // Note: HMAC option (2236) is added later by CalculateAndEncodeHMAC()
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Build HMAC Input Buffer (Section 8.5)
//------------------------------------------------------------------------------
int32_t BuildHMACInput(
    const char* uri_string,
    const SigNetOptions& options,
    const uint8_t* payload,
    uint16_t payload_len,
    uint8_t* output,
    uint32_t output_size,
    uint32_t* bytes_written
) {
    if (!uri_string || !payload || !output || !bytes_written) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    uint32_t pos = 0;
    
    // 1. URI string (ASCII, including leading '/')
    uint32_t uri_len = strlen(uri_string);
    if (pos + uri_len > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    memcpy(&output[pos], uri_string, uri_len);
    pos += uri_len;
    
    // 2. Security-Mode (1 byte)
    if (pos + 1 > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    output[pos++] = options.security_mode;
    
    // 3. Sender-ID (8 bytes)
    if (pos + SENDER_ID_LENGTH > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    memcpy(&output[pos], options.sender_id, SENDER_ID_LENGTH);
    pos += SENDER_ID_LENGTH;
    
    // 4. Mfg-Code (2 bytes, network byte order)
    if (pos + 2 > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    output[pos++] = static_cast<uint8_t>((options.mfg_code >> 8) & 0xFF);
    output[pos++] = static_cast<uint8_t>(options.mfg_code & 0xFF);
    
    // 5. Session-ID (4 bytes, network byte order)
    if (pos + 4 > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    output[pos++] = static_cast<uint8_t>((options.session_id >> 24) & 0xFF);
    output[pos++] = static_cast<uint8_t>((options.session_id >> 16) & 0xFF);
    output[pos++] = static_cast<uint8_t>((options.session_id >> 8) & 0xFF);
    output[pos++] = static_cast<uint8_t>(options.session_id & 0xFF);
    
    // 6. Seq-Num (4 bytes, network byte order)
    if (pos + 4 > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    output[pos++] = static_cast<uint8_t>((options.seq_num >> 24) & 0xFF);
    output[pos++] = static_cast<uint8_t>((options.seq_num >> 16) & 0xFF);
    output[pos++] = static_cast<uint8_t>((options.seq_num >> 8) & 0xFF);
    output[pos++] = static_cast<uint8_t>(options.seq_num & 0xFF);
    
    // 7. Application Payload (variable length)
    if (pos + payload_len > output_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    memcpy(&output[pos], payload, payload_len);
    pos += payload_len;
    
    *bytes_written = pos;
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Calculate and Encode HMAC Option
//------------------------------------------------------------------------------
int32_t CalculateAndEncodeHMAC(
    PacketBuffer& buffer,
    const char* uri_string,
    SigNetOptions& options,
    const uint8_t* payload,
    uint16_t payload_len,
    const uint8_t* sender_key,
    uint16_t prev_option
) {
    if (!uri_string || !payload || !sender_key) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Build HMAC input buffer
    uint8_t hmac_input[1400];  // Maximum possible size
    uint32_t hmac_input_len = 0;
    
    int32_t result = BuildHMACInput(
        uri_string,
        options,
        payload,
        payload_len,
        hmac_input,
        sizeof(hmac_input),
        &hmac_input_len
    );
    
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    
    // Calculate HMAC-SHA256
    result = Crypto::HMAC_SHA256(
        sender_key,
        DERIVED_KEY_LENGTH,
        hmac_input,
        hmac_input_len,
        options.hmac
    );

    SecureZero(hmac_input, sizeof(hmac_input));

    if (result != SIGNET_SUCCESS) {
        return result;
    }
    
    // Encode HMAC as option 2236
    result = CoAP::EncodeCoAPOption(
        buffer,
        SIGNET_OPTION_HMAC,
        prev_option,
        options.hmac,
        HMAC_SHA256_LENGTH
    );
    
    return result;
}

//------------------------------------------------------------------------------
// Build Sender-ID from TUID and Endpoint
//------------------------------------------------------------------------------
int32_t BuildSenderID(
    const uint8_t* tuid,
    uint16_t endpoint,
    uint8_t* sender_id
) {
    if (!tuid || !sender_id) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    // Copy TUID (6 bytes)
    memcpy(sender_id, tuid, TUID_LENGTH);
    
    // Append endpoint (2 bytes, network byte order)
    sender_id[6] = static_cast<uint8_t>((endpoint >> 8) & 0xFF);
    sender_id[7] = static_cast<uint8_t>(endpoint & 0xFF);
    
    return SIGNET_SUCCESS;
}

} // namespace Security
} // namespace SigNet
