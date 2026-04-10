//==============================================================================
// Sig-Net Protocol Framework - Node Data Library Implementation
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

#include "sig-net-node-data.hpp"
#include "sig-net-tid-strings.hpp"
#include "sig-net-tlv.hpp"
#include "sig-net-constants.hpp"
#include <string.h>

namespace SigNet {
namespace Node {

//------------------------------------------------------------------------------
// AppendNodeTLVRaw
//------------------------------------------------------------------------------

int32_t AppendNodeTLVRaw(PacketBuffer& payload,
                         uint16_t tid,
                         const uint8_t* value,
                         uint16_t len)
{
    int32_t result = payload.WriteUInt16(tid);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    result = payload.WriteUInt16(len);
    if (result != SIGNET_SUCCESS) {
        return result;
    }

    if (len > 0 && value) {
        result = payload.WriteBytes(value, len);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    return SIGNET_SUCCESS;
}

bool StoreNodeBlobFromBytesIfChanged(TidDataBlob& blob,
                                     uint16_t tid,
                                     const uint8_t* value,
                                     uint16_t length,
                                     uint8_t value_type,
                                     bool& changed_out)
{
    changed_out = false;

    if (length > SigNet::TID_BLOB_MAX_BYTES) {
        return false;
    }
    if (length > 0 && !value) {
        return false;
    }

    bool same_meta = (blob.tid == tid) &&
                     (blob.length == length) &&
                     (blob.value_type == value_type);
    bool same_data = true;

    if (same_meta && length > 0) {
        same_data = (memcmp(blob.data.bytes, value, length) == 0);
    }

    if (same_meta && same_data) {
        return true;
    }

    blob.tid = tid;
    blob.length = length;
    blob.value_type = value_type;

    if (length > 0) {
        memcpy(blob.data.bytes, value, length);
    }
    if (length < SigNet::TID_BLOB_MAX_BYTES) {
        blob.data.bytes[length] = 0;
        blob.data.text[length] = 0;
    }

    changed_out = true;
    return true;
}

//------------------------------------------------------------------------------
// Internal helpers
//------------------------------------------------------------------------------

// Append a blob's value as a TLV, or a default if the blob is empty.
static int32_t AppendBlobOrDefault(PacketBuffer& payload,
                                   uint16_t tid,
                                   const TidDataBlob& blob,
                                   const uint8_t* default_value,
                                   uint16_t default_len)
{
    if (blob.length > 0) {
        return AppendNodeTLVRaw(payload, tid, blob.data.bytes, blob.length);
    }
    return AppendNodeTLVRaw(payload, tid, default_value, default_len);
}

//------------------------------------------------------------------------------
// BuildNodeQueryPayload
//
// All data comes from NodeUserData and NodeConfig.
// No GUI objects are accessed.
//------------------------------------------------------------------------------

int32_t BuildNodeQueryPayload(uint8_t query_level,
                              uint16_t reply_endpoint,
                              const NodeUserData& data,
                              const NodeConfig& config,
                              PacketBuffer& payload_out)
{
    payload_out.Reset();
    int32_t result;
    bool is_root_ep = (reply_endpoint == 0);
    bool is_data_ep = !is_root_ep;

    // ==========================================================================
    // QUERY_HEARTBEAT tier: POLL_REPLY, RT_ENDPOINT_COUNT, RT_MULT
    // ==========================================================================

    if (IsTidAllowedForEndpoint(TID_POLL_REPLY, is_root_ep, is_data_ep)) {
        result = TLV::EncodeTID_POLL_REPLY(payload_out,
                                           config.tuid,
                                           config.mfg_code,
                                           config.product_variant_id,
                                           config.change_count);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_ENDPOINT_COUNT, is_root_ep, is_data_ep)) {
        uint8_t default_ep_count[2] = { 0x00, 0x01 };
        result = AppendBlobOrDefault(payload_out, TID_RT_ENDPOINT_COUNT,
                                     data.root.tid_rt_endpoint_count,
                                     default_ep_count, 2);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_MULT, is_root_ep, is_data_ep)) {
        uint8_t default_mult[1] = { 0x00 };
        result = AppendBlobOrDefault(payload_out, TID_RT_MULT,
                                     data.root.tid_rt_mult,
                                     default_mult, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (query_level < QUERY_CONFIG) {
        return SIGNET_SUCCESS;
    }

    // ==========================================================================
    // QUERY_CONFIG tier (cumulative): DEVICE_LABEL, IDENTIFY, STATUS,
    //   RDM_TOD_BACKGROUND, EP_UNIVERSE, EP_LABEL, EP_MULT_OVERRIDE,
    //   EP_DIRECTION, EP_INPUT_PRIORITY, EP_STATUS, EP_FAILOVER
    // ==========================================================================

    if (IsTidAllowedForEndpoint(TID_RT_DEVICE_LABEL, is_root_ep, is_data_ep)) {
        // Device label (text): emit zero-length TLV if not set
        result = AppendNodeTLVRaw(payload_out, TID_RT_DEVICE_LABEL,
                                  data.root.tid_rt_device_label.data.bytes,
                                  data.root.tid_rt_device_label.length);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_IDENTIFY, is_root_ep, is_data_ep)) {
        uint8_t default_identify[1] = { 0x00 };
        result = AppendBlobOrDefault(payload_out, TID_RT_IDENTIFY,
                                     data.root.tid_rt_identify,
                                     default_identify, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_STATUS, is_root_ep, is_data_ep)) {
        uint8_t default_status[4] = { 0, 0, 0, 0 };
        result = AppendBlobOrDefault(payload_out, TID_RT_STATUS,
                                     data.root.tid_rt_status,
                                     default_status, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RDM_TOD_BACKGROUND, is_root_ep, is_data_ep)) {
        uint8_t default_rdm_bg[1] = { 0x01 };  // Background RDM discovery on by default
        result = AppendBlobOrDefault(payload_out, TID_RDM_TOD_BACKGROUND,
                                     data.ep1.tid_rdm_tod_background,
                                     default_rdm_bg, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_UNIVERSE, is_root_ep, is_data_ep)) {
        uint8_t default_universe[2] = { 0x00, 0x01 };  // Universe 1
        result = AppendBlobOrDefault(payload_out, TID_EP_UNIVERSE,
                                     data.ep1.tid_ep_universe,
                                     default_universe, 2);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_LABEL, is_root_ep, is_data_ep)) {
        // EP label (text): emit zero-length TLV if not set
        result = AppendNodeTLVRaw(payload_out, TID_EP_LABEL,
                                  data.ep1.tid_ep_label.data.bytes,
                                  data.ep1.tid_ep_label.length);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_MULT_OVERRIDE, is_root_ep, is_data_ep)) {
        uint8_t default_mult_override[4] = { 0, 0, 0, 0 };  // 0.0.0.0 = clear
        result = AppendBlobOrDefault(payload_out, TID_EP_MULT_OVERRIDE,
                                     data.ep1.tid_ep_mult_override,
                                     default_mult_override, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_DIRECTION, is_root_ep, is_data_ep)) {
        uint8_t default_dir[1] = { 0x01 };  // Consumer by default
        result = AppendBlobOrDefault(payload_out, TID_EP_DIRECTION,
                                     data.ep1.tid_ep_direction,
                                     default_dir, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_INPUT_PRIORITY, is_root_ep, is_data_ep)) {
        uint8_t default_prio[1] = { 100 };  // E1.31 default priority
        result = AppendBlobOrDefault(payload_out, TID_EP_INPUT_PRIORITY,
                                     data.ep1.tid_ep_input_priority,
                                     default_prio, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_STATUS, is_root_ep, is_data_ep)) {
        uint8_t default_ep_status[4] = { 0, 0, 0, 0 };
        result = AppendBlobOrDefault(payload_out, TID_EP_STATUS,
                                     data.ep1.tid_ep_status,
                                     default_ep_status, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_FAILOVER, is_root_ep, is_data_ep)) {
        uint8_t default_failover[3] = { 0x00, 0x00, 0x00 };  // Hold last state
        result = AppendBlobOrDefault(payload_out, TID_EP_FAILOVER,
                                     data.ep1.tid_ep_failover,
                                     default_failover, 3);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (query_level < QUERY_FULL) {
        return SIGNET_SUCCESS;
    }

    // ==========================================================================
    // QUERY_FULL tier (cumulative): SUPPORTED_TIDS, PROTOCOL_VERSION,
    //   FIRMWARE_VERSION, ROLE_CAPABILITY, MODEL_NAME, all NW_* TIDs,
    //   EP_CAPABILITY, EP_REFRESH_CAPABILITY
    // ==========================================================================

    if (IsTidAllowedForEndpoint(TID_RT_SUPPORTED_TIDS, is_root_ep, is_data_ep)) {
        // SUPPORTED_TIDS: blob holds the already-encoded 2-byte-per-TID array
        if (data.root.tid_rt_supported_tids.length > 0) {
            result = AppendNodeTLVRaw(payload_out, TID_RT_SUPPORTED_TIDS,
                                      data.root.tid_rt_supported_tids.data.bytes,
                                      data.root.tid_rt_supported_tids.length);
            if (result != SIGNET_SUCCESS) {
                return result;
            }
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_PROTOCOL_VERSION, is_root_ep, is_data_ep)) {
        uint8_t prot_ver = (data.root.tid_rt_protocol_version.length > 0)
                           ? data.root.tid_rt_protocol_version.data.bytes[0]
                           : 0x01;
        result = TLV::EncodeTID_RT_PROTOCOL_VERSION(payload_out, prot_ver);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_FIRMWARE_VERSION, is_root_ep, is_data_ep)) {
        // Firmware blob layout: bytes[0..1] = big-endian uint16 machine version ID,
        //                       bytes[2..N] = UTF-8 version string (no null terminator)
        if (data.root.tid_rt_firmware_version.length >= 2) {
            uint16_t fw_id = ((uint16_t)data.root.tid_rt_firmware_version.data.bytes[0] << 8) |
                              data.root.tid_rt_firmware_version.data.bytes[1];
            const char* fw_str = (const char*)data.root.tid_rt_firmware_version.data.bytes + 2;
            result = TLV::EncodeTID_RT_FIRMWARE_VERSION(payload_out, fw_id, fw_str);
        } else {
            result = TLV::EncodeTID_RT_FIRMWARE_VERSION(payload_out, 0x0001, "");
        }
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_ROLE_CAPABILITY, is_root_ep, is_data_ep)) {
        uint8_t role = (data.root.tid_rt_role_capability.length > 0)
                       ? data.root.tid_rt_role_capability.data.bytes[0]
                       : ROLE_CAP_NODE;
        result = TLV::EncodeTID_RT_ROLE_CAPABILITY(payload_out, role);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_MODEL_NAME, is_root_ep, is_data_ep)) {
        result = AppendNodeTLVRaw(payload_out, TID_RT_MODEL_NAME,
                                  data.root.tid_rt_model_name.data.bytes,
                                  data.root.tid_rt_model_name.length);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    // --- Network configuration TIDs ---

    if (IsTidAllowedForEndpoint(TID_NW_MAC_ADDRESS, is_root_ep, is_data_ep)) {
        uint8_t default_mac[6] = { 0, 0, 0, 0, 0, 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_MAC_ADDRESS,
                                     data.root.tid_nw_mac_address,
                                     default_mac, 6);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV4_MODE, is_root_ep, is_data_ep)) {
        uint8_t default_ipv4_mode[1] = { 0x00 };  // Static
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV4_MODE,
                                     data.root.tid_nw_ipv4_mode,
                                     default_ipv4_mode, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV4_ADDRESS, is_root_ep, is_data_ep)) {
        uint8_t default_addr[4] = { 0, 0, 0, 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV4_ADDRESS,
                                     data.root.tid_nw_ipv4_address,
                                     default_addr, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV4_NETMASK, is_root_ep, is_data_ep)) {
        uint8_t default_mask[4] = { 0, 0, 0, 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV4_NETMASK,
                                     data.root.tid_nw_ipv4_netmask,
                                     default_mask, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV4_GATEWAY, is_root_ep, is_data_ep)) {
        uint8_t default_gw[4] = { 0, 0, 0, 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV4_GATEWAY,
                                     data.root.tid_nw_ipv4_gateway,
                                     default_gw, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV4_CURRENT, is_root_ep, is_data_ep)) {
        uint8_t default_current[12] = { 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV4_CURRENT,
                                     data.root.tid_nw_ipv4_current,
                                     default_current, 12);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV6_MODE, is_root_ep, is_data_ep)) {
        uint8_t default_ipv6_mode[1] = { 0x01 };  // SLAAC
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV6_MODE,
                                     data.root.tid_nw_ipv6_mode,
                                     default_ipv6_mode, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV6_ADDRESS, is_root_ep, is_data_ep)) {
        uint8_t default_ipv6_zero[16] = { 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV6_ADDRESS,
                                     data.root.tid_nw_ipv6_address,
                                     default_ipv6_zero, 16);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV6_PREFIX, is_root_ep, is_data_ep)) {
        uint8_t default_prefix[1] = { 64 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV6_PREFIX,
                                     data.root.tid_nw_ipv6_prefix,
                                     default_prefix, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV6_GATEWAY, is_root_ep, is_data_ep)) {
        uint8_t default_ipv6_zero[16] = { 0 };
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV6_GATEWAY,
                                     data.root.tid_nw_ipv6_gateway,
                                     default_ipv6_zero, 16);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_NW_IPV6_CURRENT, is_root_ep, is_data_ep)) {
        uint8_t default_ipv6_current[33] = { 0 };
        default_ipv6_current[16] = 64;  // default prefix length byte
        result = AppendBlobOrDefault(payload_out, TID_NW_IPV6_CURRENT,
                                     data.root.tid_nw_ipv6_current,
                                     default_ipv6_current, 33);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    // --- Endpoint capability and refresh ---

    if (IsTidAllowedForEndpoint(TID_EP_CAPABILITY, is_root_ep, is_data_ep)) {
        uint8_t default_cap[1] = { EP_CAP_CONSUME_LEVEL | EP_CAP_VIRTUAL };
        result = AppendBlobOrDefault(payload_out, TID_EP_CAPABILITY,
                                     data.ep1.tid_ep_capability,
                                     default_cap, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_REFRESH_CAPABILITY, is_root_ep, is_data_ep)) {
        uint8_t default_refresh[1] = { 44 };  // 44 Hz maximum
        result = AppendBlobOrDefault(payload_out, TID_EP_REFRESH_CAPABILITY,
                                     data.ep1.tid_ep_refresh_capability,
                                     default_refresh, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    // QUERY_EXTENDED: security TIDs (treated same as FULL until spec is finalised)

    return SIGNET_SUCCESS;
}

} // namespace Node
} // namespace SigNet
