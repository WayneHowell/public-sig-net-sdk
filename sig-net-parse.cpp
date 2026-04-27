//==============================================================================
// Sig-Net Protocol Framework - Packet Parsing Implementation
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
// Prot Version: v0.12
// Description:  Implementation of packet parsing for Sig-Net receivers. CoAP
//               option parsing, custom option extraction, TLV parsing, and
//               HMAC verification wrapper functions.
//==============================================================================

#include "sig-net-parse.hpp"
#include "sig-net-security.hpp"
#include "sig-net-crypto.hpp"
#include "sig-net-coap.hpp"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

namespace SigNet {
namespace Parse {

//------------------------------------------------------------------------------
// PacketReader Implementation
//------------------------------------------------------------------------------

PacketReader::PacketReader(const uint8_t* buffer, uint16_t size)
    : buffer_(buffer), position_(0), size_(size)
{
}

bool PacketReader::ReadByte(uint8_t& value) {
    if (!CanRead(1)) {
        return false;
    }
    value = buffer_[position_++];
    return true;
}

bool PacketReader::ReadUInt16(uint16_t& value) {
    if (!CanRead(2)) {
        return false;
    }
    // Network byte order (big-endian)
    value = ((uint16_t)buffer_[position_] << 8) | buffer_[position_ + 1];
    position_ += 2;
    return true;
}

bool PacketReader::ReadUInt32(uint32_t& value) {
    if (!CanRead(4)) {
        return false;
    }
    // Network byte order (big-endian)
    value = ((uint32_t)buffer_[position_] << 24) |
            ((uint32_t)buffer_[position_ + 1] << 16) |
            ((uint32_t)buffer_[position_ + 2] << 8) |
            ((uint32_t)buffer_[position_ + 3]);
    position_ += 4;
    return true;
}

bool PacketReader::ReadBytes(uint8_t* dest, uint16_t count) {
    if (!CanRead(count)) {
        return false;
    }
    memcpy(dest, buffer_ + position_, count);
    position_ += count;
    return true;
}

bool PacketReader::Skip(uint16_t count) {
    if (!CanRead(count)) {
        return false;
    }
    position_ += count;
    return true;
}

bool PacketReader::Seek(uint16_t new_position) {
    if (new_position > size_) {
        return false;
    }
    position_ = new_position;
    return true;
}

bool PacketReader::PeekByte(uint8_t& value) const {
    if (position_ >= size_) {
        return false;
    }
    value = buffer_[position_];
    return true;
}

//------------------------------------------------------------------------------
// Parse CoAP Header
//------------------------------------------------------------------------------
int32_t ParseCoAPHeader(PacketReader& reader, CoAPHeader& header) {
    uint8_t byte0, byte1;
    
    if (!reader.ReadByte(byte0)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    if (!reader.ReadByte(byte1)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    if (!reader.ReadUInt16(header.message_id)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    
    header.version_type_tkl = byte0;
    header.code = byte1;
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Skip CoAP Token
//------------------------------------------------------------------------------
int32_t SkipToken(PacketReader& reader, uint8_t token_length) {
    if (token_length == 0) {
        return SIGNET_SUCCESS;
    }
    
    if (!reader.Skip(token_length)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Parse CoAP Option
//------------------------------------------------------------------------------
int32_t ParseCoAPOption(
    PacketReader& reader,
    uint16_t prev_option,
    uint16_t& option_num,
    const uint8_t*& option_value,
    uint16_t& option_length
) {
    uint8_t header_byte;
    
    // Peek at next byte to check for payload marker
    if (!reader.PeekByte(header_byte)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    
    if (header_byte == 0xFF) {
        // Payload marker - not an option
        return SIGNET_ERROR_INVALID_PACKET;
    }
    
    // Read option header
    if (!reader.ReadByte(header_byte)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    
    uint16_t delta = (header_byte >> 4) & 0x0F;
    uint16_t length = header_byte & 0x0F;
    
    // Handle extended delta
    if (delta == 13) {
        uint8_t delta_ext;
        if (!reader.ReadByte(delta_ext)) {
            return SIGNET_ERROR_BUFFER_TOO_SMALL;
        }
        delta = 13 + delta_ext;
    }
    else if (delta == 14) {
        uint16_t delta_ext;
        if (!reader.ReadUInt16(delta_ext)) {
            return SIGNET_ERROR_BUFFER_TOO_SMALL;
        }
        delta = 269 + delta_ext;
    }
    else if (delta == 15) {
        // Reserved - payload marker
        return SIGNET_ERROR_INVALID_PACKET;
    }
    
    // Handle extended length
    if (length == 13) {
        uint8_t length_ext;
        if (!reader.ReadByte(length_ext)) {
            return SIGNET_ERROR_BUFFER_TOO_SMALL;
        }
        length = 13 + length_ext;
    }
    else if (length == 14) {
        uint16_t length_ext;
        if (!reader.ReadUInt16(length_ext)) {
            return SIGNET_ERROR_BUFFER_TOO_SMALL;
        }
        // 269 + 0xFFFF wraps uint16_t — widen, bound, then narrow.
        uint32_t full = 269u + length_ext;
        if (full > MAX_UDP_PAYLOAD) {
            return SIGNET_ERROR_INVALID_PACKET;
        }
        length = static_cast<uint16_t>(full);
    }
    else if (length == 15) {
        // Reserved
        return SIGNET_ERROR_INVALID_PACKET;
    }

    // Sig-Net options never exceed MAX_UDP_PAYLOAD; bound regardless of encoding.
    if (length > MAX_UDP_PAYLOAD) {
        return SIGNET_ERROR_INVALID_PACKET;
    }

    // Calculate absolute option number
    option_num = prev_option + delta;
    option_length = length;
    
    // Point to option value (no copy)
    if (length > 0) {
        option_value = reader.GetCurrentPtr();
        if (!reader.Skip(length)) {
            return SIGNET_ERROR_BUFFER_TOO_SMALL;
        }
    }
    else {
        option_value = 0;
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Extract URI String
//------------------------------------------------------------------------------
int32_t ExtractURIString(
    PacketReader& reader,
    char* uri_string,
    uint16_t uri_buffer_size,
    uint16_t& uri_length
) {
    uint16_t current_option = 0;
    uint16_t uri_pos = 0;
    
    // URI must start with '/'
    if (uri_pos + 1 > uri_buffer_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    uri_string[uri_pos++] = '/';
    
    bool first_segment = true;
    
    while (true) {
        // Snapshot so we can rewind a non-Uri-Path option for the next phase.
        uint16_t option_start_pos = reader.GetPosition();

        uint16_t option_num;
        const uint8_t* option_value;
        uint16_t option_length;

        int32_t result = ParseCoAPOption(reader, current_option, option_num, option_value, option_length);

        if (result == SIGNET_ERROR_INVALID_PACKET) {
            // Hit payload marker or end of options
            break;
        }

        if (result != SIGNET_SUCCESS) {
            return result;
        }

        // Check if this is a Uri-Path option (11)
        if (option_num == COAP_OPTION_URI_PATH) {
            // Add separator between segments (but not before first)
            if (!first_segment) {
                if (uri_pos + 1 > uri_buffer_size) {
                    return SIGNET_ERROR_BUFFER_FULL;
                }
                uri_string[uri_pos++] = '/';
            }
            first_segment = false;

            // Copy segment
            if (uri_pos + option_length > uri_buffer_size) {
                return SIGNET_ERROR_BUFFER_FULL;
            }
            memcpy(&uri_string[uri_pos], option_value, option_length);
            uri_pos += option_length;
        }
        else if (option_num > COAP_OPTION_URI_PATH) {
            reader.Seek(option_start_pos);   // hand the option to the next phase
            break;
        }

        current_option = option_num;
    }
    
    // Null-terminate (not transmitted, but useful for C string functions)
    if (uri_pos >= uri_buffer_size) {
        return SIGNET_ERROR_BUFFER_FULL;
    }
    uri_string[uri_pos] = 0;
    uri_length = uri_pos;
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Parse SigNet Options
//------------------------------------------------------------------------------
int32_t ParseSigNetOptions(
    PacketReader& reader,
    SigNetOptions& options,
    uint16_t initial_prev_option
) {
    // 0 if starting fresh; COAP_OPTION_URI_PATH if chained after ExtractURIString.
    uint16_t current_option = initial_prev_option;
    bool found_security_mode = false;
    bool found_sender_id = false;
    bool found_mfg_code = false;
    bool found_session_id = false;
    bool found_seq_num = false;
    bool found_hmac = false;
    
    while (true) {
        uint16_t option_num;
        const uint8_t* option_value;
        uint16_t option_length;
        
        int32_t result = ParseCoAPOption(reader, current_option, option_num, option_value, option_length);
        
        if (result == SIGNET_ERROR_INVALID_PACKET) {
            // Hit payload marker - done with options
            break;
        }
        
        if (result != SIGNET_SUCCESS) {
            return result;
        }
        
        // Process SigNet custom options
        switch (option_num) {
            case SIGNET_OPTION_SECURITY_MODE:
                if (option_length != 1) {
                    return SIGNET_ERROR_INVALID_OPTION;
                }
                options.security_mode = *option_value;
                found_security_mode = true;
                break;
                
            case SIGNET_OPTION_SENDER_ID:
                if (option_length != SENDER_ID_LENGTH) {
                    return SIGNET_ERROR_INVALID_OPTION;
                }
                memcpy(options.sender_id, option_value, SENDER_ID_LENGTH);
                found_sender_id = true;
                break;
                
            case SIGNET_OPTION_MFG_CODE:
                if (option_length != 2) {
                    return SIGNET_ERROR_INVALID_OPTION;
                }
                options.mfg_code = ((uint16_t)option_value[0] << 8) | option_value[1];
                found_mfg_code = true;
                break;
                
            case SIGNET_OPTION_SESSION_ID:
                if (option_length != 4) {
                    return SIGNET_ERROR_INVALID_OPTION;
                }
                options.session_id = ((uint32_t)option_value[0] << 24) |
                                    ((uint32_t)option_value[1] << 16) |
                                    ((uint32_t)option_value[2] << 8) |
                                    ((uint32_t)option_value[3]);
                found_session_id = true;
                break;
                
            case SIGNET_OPTION_SEQ_NUM:
                if (option_length != 4) {
                    return SIGNET_ERROR_INVALID_OPTION;
                }
                options.seq_num = ((uint32_t)option_value[0] << 24) |
                                 ((uint32_t)option_value[1] << 16) |
                                 ((uint32_t)option_value[2] << 8) |
                                 ((uint32_t)option_value[3]);
                found_seq_num = true;
                break;
                
            case SIGNET_OPTION_HMAC:
                if (option_length != HMAC_SHA256_LENGTH) {
                    return SIGNET_ERROR_INVALID_OPTION;
                }
                memcpy(options.hmac, option_value, HMAC_SHA256_LENGTH);
                found_hmac = true;
                break;
        }
        
        current_option = option_num;
    }
    
    // Verify all required options were present
    // (Except for Security-Mode 0xFF beacons which may have missing fields)
    if (!found_security_mode) {
        return SIGNET_ERROR_INVALID_OPTION;
    }
    
    // For normal packets (not beacons), all options are required
    if (options.security_mode != 0xFF) {
        if (!found_sender_id || !found_mfg_code || !found_session_id || 
            !found_seq_num || !found_hmac) {
            return SIGNET_ERROR_INVALID_OPTION;
        }
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Parse TLV Block
//------------------------------------------------------------------------------
int32_t ParseTLVBlock(PacketReader& reader, TLVBlock& tlv) {
    if (!reader.ReadUInt16(tlv.type_id)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    
    if (!reader.ReadUInt16(tlv.length)) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }
    
    if (tlv.length > 0) {
        if (!reader.CanRead(tlv.length)) {
            return SIGNET_ERROR_BUFFER_TOO_SMALL;
        }
        tlv.value = reader.GetCurrentPtr();
        reader.Skip(tlv.length);
    }
    else {
        tlv.value = 0;
    }
    
    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Parse TID_LEVEL Payload
//------------------------------------------------------------------------------
int32_t ParseTID_LEVEL(
    const TLVBlock& tlv,
    uint8_t* dmx_data,
    uint16_t& slot_count
) {
    if (tlv.type_id != TID_LEVEL) {
        return SIGNET_ERROR_INVALID_ARG;
    }
    
    if (tlv.length < 1 || tlv.length > 512) {
        return SIGNET_ERROR_INVALID_PACKET;
    }
    
    slot_count = tlv.length;
    memcpy(dmx_data, tlv.value, slot_count);
    
    return SIGNET_SUCCESS;
}

static bool IsSpaceChar(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

static bool IsHexChar(char ch)
{
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}

static uint8_t HexNibble(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return static_cast<uint8_t>(ch - '0');
    }
    if (ch >= 'a' && ch <= 'f') {
        return static_cast<uint8_t>(10 + (ch - 'a'));
    }
    return static_cast<uint8_t>(10 + (ch - 'A'));
}

static int32_t NormalizeToken(const char* text,
                              char* out_token,
                              uint16_t out_size,
                              bool strip_0x_prefix)
{
    if (!text || !out_token || out_size < 2) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    const char* begin = text;
    while (*begin && IsSpaceChar(*begin)) {
        begin++;
    }

    const char* end = begin + strlen(begin);
    while (end > begin && IsSpaceChar(*(end - 1))) {
        end--;
    }

    if (end <= begin) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    if (strip_0x_prefix && (end - begin) >= 2 && begin[0] == '0' && (begin[1] == 'x' || begin[1] == 'X')) {
        begin += 2;
    }

    size_t len = static_cast<size_t>(end - begin);
    if (len == 0 || len >= out_size) {
        return SIGNET_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(out_token, begin, len);
    out_token[len] = '\0';
    return SIGNET_SUCCESS;
}

int32_t ParseHexBytes(const char* text, uint8_t* out_bytes, uint16_t byte_count)
{
    if (!text || !out_bytes || byte_count == 0) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    char token[256];
    int32_t norm = NormalizeToken(text, token, sizeof(token), true);
    if (norm != SIGNET_SUCCESS) {
        return norm;
    }

    size_t hex_len = strlen(token);
    if (hex_len != (static_cast<size_t>(byte_count) * 2U)) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    for (uint16_t i = 0; i < byte_count; i++) {
        char hi = token[i * 2U];
        char lo = token[i * 2U + 1U];
        if (!IsHexChar(hi) || !IsHexChar(lo)) {
            return SIGNET_ERROR_INVALID_ARG;
        }
        out_bytes[i] = static_cast<uint8_t>((HexNibble(hi) << 4) | HexNibble(lo));
    }

    return SIGNET_SUCCESS;
}

int32_t ParseK0Hex(const char* text, uint8_t out_k0[32])
{
    return ParseHexBytes(text, out_k0, 32);
}

int32_t ParseTUIDHex(const char* text, uint8_t out_tuid[6])
{
    return ParseHexBytes(text, out_tuid, 6);
}

int32_t ParseEndpointValue(const char* text, uint16_t& endpoint_out)
{
    char token[64];
    int32_t norm = NormalizeToken(text, token, sizeof(token), false);
    if (norm != SIGNET_SUCCESS) {
        return norm;
    }

    char* end_ptr = 0;
    long parsed = 0;
    if (token[0] == '$') {
        parsed = strtol(token + 1, &end_ptr, 16);
    } else {
        parsed = strtol(token, &end_ptr, 0);
    }

    if (!end_ptr || *end_ptr != '\0') {
        return SIGNET_ERROR_INVALID_ARG;
    }
    if (parsed < 0 || parsed > 65535L) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    endpoint_out = static_cast<uint16_t>(parsed);
    return SIGNET_SUCCESS;
}

int32_t ParseHexWord(const char* text, uint16_t& value_out)
{
    char token[64];
    int32_t norm = NormalizeToken(text, token, sizeof(token), false);
    if (norm != SIGNET_SUCCESS) {
        return norm;
    }

    char prefixed[68];
    const char* parse_ptr = token;
    if (!(token[0] == '0' && (token[1] == 'x' || token[1] == 'X'))) {
        strcpy(prefixed, "0x");
        strncat(prefixed, token, sizeof(prefixed) - 3);
        prefixed[sizeof(prefixed) - 1] = '\0';
        parse_ptr = prefixed;
    }

    char* end_ptr = 0;
    long parsed = strtol(parse_ptr, &end_ptr, 0);
    if (!end_ptr || *end_ptr != '\0') {
        return SIGNET_ERROR_INVALID_ARG;
    }
    if (parsed < 0 || parsed > 65535L) {
        return SIGNET_ERROR_INVALID_ARG;
    }

    value_out = static_cast<uint16_t>(parsed);
    return SIGNET_SUCCESS;
}

int32_t ValidateSigNetURI(const char* uri_string)
{
    if (!uri_string || uri_string[0] != '/') {
        return SIGNET_ERROR_INVALID_PACKET;
    }

    const char* p = uri_string + 1;
    const char* seg_end = strchr(p, '/');
    if (!seg_end) {
        return SIGNET_ERROR_INVALID_PACKET;
    }
    if ((size_t)(seg_end - p) != strlen(SIGNET_URI_PREFIX) ||
        strncmp(p, SIGNET_URI_PREFIX, (size_t)(seg_end - p)) != 0) {
        return SIGNET_ERROR_INVALID_PACKET;
    }

    p = seg_end + 1;
    seg_end = strchr(p, '/');
    if (!seg_end) {
        return SIGNET_ERROR_INVALID_PACKET;
    }
    if ((size_t)(seg_end - p) != strlen(SIGNET_URI_VERSION) ||
        strncmp(p, SIGNET_URI_VERSION, (size_t)(seg_end - p)) != 0) {
        return SIGNET_ERROR_INVALID_PACKET;
    }

    p = seg_end + 1;
    seg_end = strchr(p, '/');
    if (!seg_end) {
        return SIGNET_ERROR_INVALID_PACKET;
    }

    const size_t scope_len = (size_t)(seg_end - p);
    const char* configured_scope = CoAP::GetURIScope();
    const size_t configured_len = strlen(configured_scope);
    if (scope_len != configured_len || strncmp(p, configured_scope, scope_len) != 0) {
        return SIGNET_ERROR_INVALID_PACKET;
    }

    return SIGNET_SUCCESS;
}

//------------------------------------------------------------------------------
// Verify Packet HMAC
//------------------------------------------------------------------------------
int32_t VerifyPacketHMAC(
    const char* uri_string,
    const SigNetOptions& options,
    const uint8_t* payload,
    uint16_t payload_len,
    const uint8_t* role_key
) {
    // Build HMAC input buffer
    uint8_t hmac_input[1400];
    uint32_t hmac_input_len = 0;
    
    int32_t result = Security::BuildHMACInput(
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
    
    // Calculate expected HMAC
    uint8_t computed_hmac[HMAC_SHA256_LENGTH];
    result = Crypto::HMAC_SHA256(
        role_key,
        DERIVED_KEY_LENGTH,
        hmac_input,
        hmac_input_len,
        computed_hmac
    );
    
    if (result != SIGNET_SUCCESS) {
        return result;
    }
    
    // Constant-time comparison to prevent timing attacks
    uint8_t diff = 0;
    for (int i = 0; i < HMAC_SHA256_LENGTH; i++) {
        diff |= (computed_hmac[i] ^ options.hmac[i]);
    }
    
    if (diff != 0) {
        return SIGNET_ERROR_HMAC_FAILED;
    }
    
    return SIGNET_SUCCESS;
}

} // namespace Parse
} // namespace SigNet
