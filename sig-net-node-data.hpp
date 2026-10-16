//==============================================================================
// Sig-Net Protocol Framework - Node Data Library
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
// Date:         April 2026
// Description:  Library-side data model helpers for a Sig-Net node.
//               No VCL or Winsock dependency.
//
//               NodeConfig  – identity fields that are NOT TID blobs
//                             (TUID, manufacturer code, product variant, etc.).
//
//               BuildNodeQueryPayload – builds the TLV payload for a
//               QUERY_HEARTBEAT / CONFIG / FULL poll reply entirely from
//               NodeUserData + NodeConfig, with no UI access.
//
//   Data flow:
//     UI change  → update blob + set blob.manager_is_stale
//     Sig-Net SET → update blob + set blob.ui_is_stale
//     Timer tick → SyncUIFromStaleBlobs()  (if any ui_is_stale)
//                  SendStaleTIDsToManager() (if any manager_is_stale)
//==============================================================================

#ifndef SIGNET_NODE_DATA_HPP
#define SIGNET_NODE_DATA_HPP

#include "sig-net-types.hpp"
#include "sig-net-tlv.hpp"
#include "sig-net-node-profile.hpp"
#include <stdint.h>
#include <string.h>

namespace SigNet {
namespace Node {

//------------------------------------------------------------------------------
// NodeConfig
//
// Identity and session-management fields that are not carried directly in a
// TID blob but are needed to build packets (TUID, manufacturer code, etc.).
//------------------------------------------------------------------------------

struct NodeConfig {
    uint8_t  tuid[6];               // 48-bit TUID
    uint16_t mfg_code;              // ESTA manufacturer code
    uint16_t product_variant_id;    // Product variant (high byte of firmware ID)
    uint16_t endpoint;              // Endpoint number for this node (usually 1)
    uint16_t change_count;          // Incremented when persistent config changes

    NodeConfig() : mfg_code(0), product_variant_id(0), endpoint(1), change_count(0)
    {
        memset(tuid, 0, sizeof(tuid));
    }
};

//------------------------------------------------------------------------------
// AppendNodeTLVRaw
//
// Writes a raw TLV (type + length + value) into a PacketBuffer.
// Returns SIGNET_SUCCESS or SIGNET_ERROR_BUFFER_FULL.
//------------------------------------------------------------------------------

int32_t AppendNodeTLVRaw(PacketBuffer& payload,
                         uint16_t tid,
                         const uint8_t* value,
                         uint16_t len);

//------------------------------------------------------------------------------
// StoreNodeBlobFromBytesIfChanged
//
// Writes raw value bytes into a TidDataBlob only when content/metadata changed.
// changed_out is set to true only when blob state is updated.
//------------------------------------------------------------------------------

bool StoreNodeBlobFromBytesIfChanged(TidDataBlob& blob,
                                     uint16_t tid,
                                     const uint8_t* value,
                                     uint16_t length,
                                     uint8_t value_type,
                                     bool& changed_out);

//------------------------------------------------------------------------------
// Supported TID blob access helpers
//
// These helpers expose the simplified supported root/data blob sets via indexed
// access and tid lookup, so UI/executable code does not need local switch maps.
//------------------------------------------------------------------------------

int GetSupportedRootBlobCount();
int GetSupportedDataBlobCount();

TidDataBlob* GetSupportedRootBlobByIndex(NodeUserData& data, int index);
TidDataBlob* GetSupportedDataBlobByIndex(NodeUserData& data, int index);
const TidDataBlob* GetSupportedRootBlobByIndex(const NodeUserData& data, int index);
const TidDataBlob* GetSupportedDataBlobByIndex(const NodeUserData& data, int index);

TidDataBlob* FindSupportedTidBlob(NodeUserData& data, uint16_t tid);
const TidDataBlob* FindSupportedTidBlob(const NodeUserData& data, uint16_t tid);

void ClearAllManagerStaleFlags(NodeUserData& data);
void ClearAllUIStaleFlags(NodeUserData& data);

//------------------------------------------------------------------------------
// BuildNodeQueryPayload
//
// Builds the TLV payload for a poll reply at the given query level, reading
// all values from NodeUserData and NodeConfig.
//
// query_level  – QUERY_HEARTBEAT (0x00), QUERY_CONFIG (0x01), QUERY_FULL (0x02), QUERY_EXTENDED (0x03)
// data         – all per-TID blob values (populated from UI / Sig-Net traffic)
// config       – identity fields (TUID, mfg code, etc.)
// payload_out  – reset and filled by this function
//
// Returns SIGNET_SUCCESS or a negative error code on failure.
//------------------------------------------------------------------------------

int32_t BuildNodeQueryPayload(uint8_t query_level,
                              uint16_t reply_endpoint,
                              const NodeUserData& data,
                              const NodeConfig& config,
                              PacketBuffer& payload_out);

//------------------------------------------------------------------------------
// Level merge (constrained node fallback, spec 10.x Merge)
//
// One slot per simultaneous TID_LEVEL sender on the endpoint's universe. Each
// source carries a single universe-wide priority (the first byte of its latest
// TID_PRIORITY). The merged output takes, per slot, the HTP value among the
// sources of the highest priority.
//------------------------------------------------------------------------------

struct LevelSource {
    bool     active;
    uint8_t  sender_id[SENDER_ID_LENGTH];
    uint32_t last_rx_tick;
    uint8_t  priority;
    uint16_t slot_count;
    uint8_t  levels[MAX_DMX_SLOTS];
};

struct LevelMergeState {
    LevelSource sources[EP1_MAX_MERGE_SOURCES];
};

void ResetLevelMerge(LevelMergeState& state);

// Returns the slot for sender_id, allocating one if new (reusing an expired slot,
// else evicting the least recently heard). Never returns 0.
LevelSource* FindOrAllocLevelSource(LevelMergeState& state, const uint8_t* sender_id, uint32_t now_ms);

// Writes the merged levels into out (MAX_DMX_SLOTS bytes) and returns the slot
// count. Returns 0 when no source is active (caller keeps the previous output).
uint16_t MergeLevelSources(LevelMergeState& state, uint32_t now_ms, uint8_t* out);

} // namespace Node
} // namespace SigNet

#endif // SIGNET_NODE_DATA_HPP
