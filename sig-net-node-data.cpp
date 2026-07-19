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
#include "sig-net-node-profile.hpp"
#include "sig-net-tid-strings.hpp"
#include "sig-net-tlv.hpp"
#include "sig-net-constants.hpp"
#include "sig-net-coap.hpp"
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

int GetSupportedRootBlobCount()
{
    return 25;
}

int GetSupportedDataBlobCount()
{
    return 17;
}

TidDataBlob* GetSupportedRootBlobByIndex(NodeUserData& data, int index)
{
    switch (index) {
        case 0: return &data.root.tid_rt_supported_tids;
        case 1: return &data.root.tid_rt_endpoint_count;
        case 2: return &data.root.tid_rt_protocol_version;
        case 3: return &data.root.tid_rt_firmware_version;
        case 4: return &data.root.tid_rt_device_label;
        case 5: return &data.root.tid_rt_mult;
        case 6: return &data.root.tid_rt_identify;
        case 7: return &data.root.tid_rt_status;
        case 8: return &data.root.tid_rt_role_capability;
        case 9: return &data.root.tid_rt_reboot;
        case 10: return &data.root.tid_rt_model_name;
        case 11: return &data.root.tid_rt_scope;
        case 12: return &data.root.tid_rt_unprovision;
        case 13: return &data.root.tid_nw_mac_address;
        case 14: return &data.root.tid_nw_ipv4_mode;
        case 15: return &data.root.tid_nw_ipv4_address;
        case 16: return &data.root.tid_nw_ipv4_netmask;
        case 17: return &data.root.tid_nw_ipv4_gateway;
        case 18: return &data.root.tid_nw_ipv4_current;
        case 19: return &data.root.tid_nw_ipv6_mode;
        case 20: return &data.root.tid_nw_ipv6_address;
        case 21: return &data.root.tid_nw_ipv6_prefix;
        case 22: return &data.root.tid_nw_ipv6_gateway;
        case 23: return &data.root.tid_nw_ipv6_current;
        case 24: return &data.root.tid_dg_security_event;
        case 25: return &data.root.tid_dg_message;
        default: return 0;
    }
}

TidDataBlob* GetSupportedDataBlobByIndex(NodeUserData& data, int index)
{
    switch (index) {
        case 0: return &data.ep1.tid_ep_universe;
        case 1: return &data.ep1.tid_ep_label;
        case 2: return &data.ep1.tid_ep_mult_override;
        case 3: return &data.ep1.tid_ep_capability;
        case 4: return &data.ep1.tid_ep_direction;
        case 5: return &data.ep1.tid_ep_input_priority;
        case 6: return &data.ep1.tid_ep_status;
        case 7: return &data.ep1.tid_ep_failover;
        case 8: return &data.ep1.tid_ep_dmx_timing;
        case 9: return &data.ep1.tid_ep_refresh_capability;
        case 10: return &data.ep1.tid_ep_protocol;
        case 11: return &data.ep1.tid_rdm_port_config;
        case 12: return &data.ep1.tid_rdm_tod_data;
        case 13: return &data.ep1.tid_rdm_flow_control;
        case 14: return &data.ep1.tid_dg_level_foldback;
        case 15: return &data.ep1.tid_level;
        case 16: return &data.ep1.tid_priority;
        case 17: return &data.ep1.tid_sync;
        default: return 0;
    }
}

const TidDataBlob* GetSupportedRootBlobByIndex(const NodeUserData& data, int index)
{
    return GetSupportedRootBlobByIndex(const_cast<NodeUserData&>(data), index);
}

const TidDataBlob* GetSupportedDataBlobByIndex(const NodeUserData& data, int index)
{
    return GetSupportedDataBlobByIndex(const_cast<NodeUserData&>(data), index);
}

TidDataBlob* FindSupportedTidBlob(NodeUserData& data, uint16_t tid)
{
    int i;
    for (i = 0; i < GetSupportedRootBlobCount(); ++i) {
        TidDataBlob* blob = GetSupportedRootBlobByIndex(data, i);
        if (blob && blob->tid == tid) {
            return blob;
        }
    }
    for (i = 0; i < GetSupportedDataBlobCount(); ++i) {
        TidDataBlob* blob = GetSupportedDataBlobByIndex(data, i);
        if (blob && blob->tid == tid) {
            return blob;
        }
    }
    return 0;
}

const TidDataBlob* FindSupportedTidBlob(const NodeUserData& data, uint16_t tid)
{
    return FindSupportedTidBlob(const_cast<NodeUserData&>(data), tid);
}

void ClearAllManagerStaleFlags(NodeUserData& data)
{
    int i;
    for (i = 0; i < GetSupportedRootBlobCount(); ++i) {
        TidDataBlob* blob = GetSupportedRootBlobByIndex(data, i);
        if (blob) {
            blob->manager_is_stale = false;
        }
    }
    for (i = 0; i < GetSupportedDataBlobCount(); ++i) {
        TidDataBlob* blob = GetSupportedDataBlobByIndex(data, i);
        if (blob) {
            blob->manager_is_stale = false;
        }
    }
}

void ClearAllUIStaleFlags(NodeUserData& data)
{
    int i;
    for (i = 0; i < GetSupportedRootBlobCount(); ++i) {
        TidDataBlob* blob = GetSupportedRootBlobByIndex(data, i);
        if (blob) {
            blob->ui_is_stale = false;
        }
    }
    for (i = 0; i < GetSupportedDataBlobCount(); ++i) {
        TidDataBlob* blob = GetSupportedDataBlobByIndex(data, i);
        if (blob) {
            blob->ui_is_stale = false;
        }
    }
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
        result = AppendBlobOrDefault(payload_out, TID_RT_ENDPOINT_COUNT,
                                     data.root.tid_rt_endpoint_count,
                                     DEFAULT_ROOT_ENDPOINT_COUNT, 2);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_MULT, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RT_MULT,
                                     data.root.tid_rt_mult,
                                     DEFAULT_ROOT_MULT, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (query_level < QUERY_CONFIG) {
        return SIGNET_SUCCESS;
    }

    // ==========================================================================
    // QUERY_CONFIG tier (cumulative): root identity/state and the single EP1
    // configuration surface retained by the simplified node profile.
    // ==========================================================================

    if (IsTidAllowedForEndpoint(TID_RT_DEVICE_LABEL, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RT_DEVICE_LABEL,
                                     data.root.tid_rt_device_label,
                                     reinterpret_cast<const uint8_t*>(DEFAULT_ROOT_DEVICE_LABEL),
                                     static_cast<uint16_t>(strlen(DEFAULT_ROOT_DEVICE_LABEL)));
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_IDENTIFY, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RT_IDENTIFY,
                                     data.root.tid_rt_identify,
                                     DEFAULT_ROOT_IDENTIFY, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_STATUS, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RT_STATUS,
                                     data.root.tid_rt_status,
                                     DEFAULT_ROOT_STATUS, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RDM_PORT_CONFIG, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RDM_PORT_CONFIG,
                                     data.ep1.tid_rdm_port_config,
                                     DEFAULT_RDM_PORT_CONFIG, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RDM_FLOW_CONTROL, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RDM_FLOW_CONTROL,
                                     data.ep1.tid_rdm_flow_control,
                                     DEFAULT_RDM_FLOW_CONTROL, 2);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_UNIVERSE, is_root_ep, is_data_ep)) {
        uint8_t default_universe[2] = {
            static_cast<uint8_t>(DEFAULT_EP1_UNIVERSE >> 8),
            static_cast<uint8_t>(DEFAULT_EP1_UNIVERSE & 0xFF)
        };
        result = AppendBlobOrDefault(payload_out, TID_EP_UNIVERSE,
                                     data.ep1.tid_ep_universe,
                                     default_universe, 2);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_LABEL, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_LABEL,
                                     data.ep1.tid_ep_label,
                                     reinterpret_cast<const uint8_t*>(DEFAULT_EP1_LABEL),
                                     static_cast<uint16_t>(strlen(DEFAULT_EP1_LABEL)));
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_MULT_OVERRIDE, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_MULT_OVERRIDE,
                                     data.ep1.tid_ep_mult_override,
                                     DEFAULT_EP1_MULT_OVERRIDE, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_DIRECTION, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_DIRECTION,
                                     data.ep1.tid_ep_direction,
                                     DEFAULT_EP1_DIRECTION, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_INPUT_PRIORITY, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_INPUT_PRIORITY,
                                     data.ep1.tid_ep_input_priority,
                                     DEFAULT_EP1_INPUT_PRIORITY, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_STATUS, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_STATUS,
                                     data.ep1.tid_ep_status,
                                     DEFAULT_EP1_STATUS, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_FAILOVER, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_FAILOVER,
                                     data.ep1.tid_ep_failover,
                                     DEFAULT_EP1_FAILOVER, 3);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_DMX_TIMING, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_DMX_TIMING,
                                     data.ep1.tid_ep_dmx_timing,
                                     DEFAULT_EP1_DMX_TIMING, 2);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_REFRESH_CAPABILITY, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_REFRESH_CAPABILITY,
                                     data.ep1.tid_ep_refresh_capability,
                                     DEFAULT_EP1_REFRESH_CAPABILITY, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_PROTOCOL, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_PROTOCOL,
                                     data.ep1.tid_ep_protocol,
                                     DEFAULT_EP1_PROTOCOL, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    // SNAC 578: TID_EP_CAPABILITY (0x0904) must appear in the EP CONFIG poll
    // reply, so it is advertised at CONFIG tier (cumulative into FULL/EXTENDED).
    if (IsTidAllowedForEndpoint(TID_EP_CAPABILITY, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_CAPABILITY,
                                     data.ep1.tid_ep_capability,
                                     DEFAULT_EP1_CAPABILITY, 1);
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
                           : DEFAULT_ROOT_PROTOCOL_VERSION[0];
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
            result = TLV::EncodeTID_RT_FIRMWARE_VERSION(payload_out, 0x0001, DEFAULT_ROOT_FIRMWARE_STRING);
        }
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_ROLE_CAPABILITY, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RT_ROLE_CAPABILITY,
                                     data.root.tid_rt_role_capability,
                                     DEFAULT_ROOT_ROLE_CAPABILITY, 4);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_RT_MODEL_NAME, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_RT_MODEL_NAME,
                                     data.root.tid_rt_model_name,
                                     reinterpret_cast<const uint8_t*>(DEFAULT_ROOT_MODEL_NAME),
                                     static_cast<uint16_t>(strlen(DEFAULT_ROOT_MODEL_NAME)));
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (IsTidAllowedForEndpoint(TID_EP_CAPABILITY, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_EP_CAPABILITY,
                                     data.ep1.tid_ep_capability,
                                     DEFAULT_EP1_CAPABILITY, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    if (query_level < QUERY_EXTENDED) {
        return SIGNET_SUCCESS;
    }

    // ==========================================================================
    // QUERY_EXTENDED tier (cumulative): diagnostic TIDs. SNAC 875 requires the
    // root endpoint's EXTENDED poll reply to advertise TID_DG_SECURITY_EVENT.
    // ==========================================================================

    if (IsTidAllowedForEndpoint(TID_DG_SECURITY_EVENT, is_root_ep, is_data_ep)) {
        result = AppendBlobOrDefault(payload_out, TID_DG_SECURITY_EVENT,
                                     data.root.tid_dg_security_event,
                                     DEFAULT_ROOT_SECURITY_EVENT, 1);
        if (result != SIGNET_SUCCESS) {
            return result;
        }
    }

    return SIGNET_SUCCESS;
}

} // namespace Node
} // namespace SigNet
