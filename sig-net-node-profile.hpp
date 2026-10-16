#ifndef SIGNET_NODE_PROFILE_HPP
#define SIGNET_NODE_PROFILE_HPP

#include "sig-net-constants.hpp"

namespace SigNet {
namespace Node {

struct SupportedTidEntry {
    uint16_t    tid;
    const char* label;
    bool        mandated;
    bool        allowed_root_ep;
    bool        allowed_data_ep;
    bool        write_only;
    bool        supports_get;
    bool        persistent;     // Spec 11: a change to a Persistent TID increments CHANGE_COUNT
};

static const int PROFILE_SUPPORTED_TID_COUNT = 22;

// Core protocol TIDs handled by the protocol engine (not the per-TID profile
// table). SNAC 1007 requires them to be advertised in the SUPPORTED_TIDS array.
static const int PROFILE_CORE_TID_COUNT = 4;
static const int PROFILE_ADVERTISED_TID_COUNT = PROFILE_SUPPORTED_TID_COUNT + PROFILE_CORE_TID_COUNT;

inline const SupportedTidEntry* GetProfileSupportedTidTable()
{
    static const SupportedTidEntry k_table[PROFILE_SUPPORTED_TID_COUNT] = {
        { TID_RT_ENDPOINT_COUNT,     "TID_RT_ENDPOINT_COUNT (0x0602) - root",     true,  true,  false, false, true,  false },
        { TID_RT_PROTOCOL_VERSION,   "TID_RT_PROTOCOL_VERSION (0x0603) - root",   true,  true,  false, false, true,  false },
        { TID_RT_FIRMWARE_VERSION,   "TID_RT_FIRMWARE_VERSION (0x0604) - root",   true,  true,  false, false, true,  false },
        { TID_RT_DEVICE_LABEL,       "TID_RT_DEVICE_LABEL (0x0605) - root",       true,  true,  false, false, true,  true  },
        { TID_RT_MULT,               "TID_RT_MULT_OVERRIDE (0x0606) - root",      true,  true,  false, false, true,  true  },
        { TID_RT_IDENTIFY,           "TID_RT_IDENTIFY (0x0607) - root",           true,  true,  false, false, true,  false },
        { TID_RT_STATUS,             "TID_RT_STATUS (0x0608) - root",             true,  true,  false, false, true,  false },
        { TID_RT_ROLE_CAPABILITY,    "TID_RT_ROLE_CAPABILITY (0x0609) - root",    true,  true,  false, false, true,  false },
        { TID_RT_MODEL_NAME,         "TID_RT_MODEL_NAME (0x060B) - root",         true,  true,  false, false, true,  false },
        { TID_DG_SECURITY_EVENT,     "TID_DG_SECURITY_EVENT (0xFF01) - root",     true,  true,  false, false, true,  false },

        { TID_EP_UNIVERSE,           "TID_EP_UNIVERSE (0x0901) - data",           true,  false, true,  false, true,  true  },
        { TID_EP_LABEL,              "TID_EP_LABEL (0x0902) - data",              true,  false, true,  false, true,  true  },
        { TID_EP_MULT_OVERRIDE,      "TID_EP_MULT_OVERRIDE (0x0903) - data",      true,  false, true,  false, true,  true  },
        { TID_EP_CAPABILITY,         "TID_EP_CAPABILITY (0x0904) - data",         true,  false, true,  false, true,  false },
        { TID_EP_DIRECTION,          "TID_EP_DIRECTION (0x0905) - data",          true,  false, true,  false, true,  true  },
        { TID_EP_INPUT_PRIORITY,     "TID_EP_INPUT_PRIORITY (0x0906) - data",     false, false, true,  false, true,  true  },
        { TID_EP_STATUS,             "TID_EP_STATUS (0x0907) - data",             true,  false, true,  false, true,  false },
        { TID_EP_FAILOVER,           "TID_EP_FAILOVER (0x0908) - data",           false, false, true,  false, true,  true  },
        { TID_EP_DMX_TIMING,         "TID_EP_DMX_TIMING (0x0909) - data",         true,  false, true,  false, true,  true  },
        { TID_EP_REFRESH_CAPABILITY, "TID_EP_REFRESH_CAPABILITY (0x090A) - data", true,  false, true,  false, true,  false },
        { TID_EP_PROTOCOL,           "TID_EP_PROTOCOL (0x090B) - data",           false, false, true,  false, true,  true  },
        { TID_DG_LEVEL_FOLDBACK,     "TID_DG_LEVEL_FOLDBACK (0xFF03) - data",     true,  false, true,  false, true,  false }
    };

    return k_table;
}

inline uint16_t BuildSupportedTidBytes(uint8_t* out, uint16_t capacity)
{
    uint16_t byte_count = 0;
    int i;


    static const uint16_t k_core_tids[PROFILE_CORE_TID_COUNT] = {
        TID_POLL,               // 0x0001
        TID_POLL_REPLY,         // 0x0002
        TID_SET_REPLY,          // 0x0003
        TID_RT_SUPPORTED_TIDS   // 0x0601
    };
    for (i = 0; i < PROFILE_CORE_TID_COUNT; ++i) {
        if (byte_count + 2 > capacity) {
            return byte_count;
        }
        out[byte_count++] = static_cast<uint8_t>(k_core_tids[i] >> 8);
        out[byte_count++] = static_cast<uint8_t>(k_core_tids[i] & 0xFF);
    }

    const SupportedTidEntry* table = GetProfileSupportedTidTable();
    for (i = 0; i < PROFILE_SUPPORTED_TID_COUNT; ++i) {
        if (byte_count + 2 > capacity) {
            break;
        }
        out[byte_count++] = static_cast<uint8_t>(table[i].tid >> 8);
        out[byte_count++] = static_cast<uint8_t>(table[i].tid & 0xFF);
    }

    return byte_count;
}

// Value limits used by IsValidSetPayload (spec 11.6.5, 11.7.2, 11.7.3, 11.7.6, 11.7.11).
static const uint8_t TEXT_ENCODING_MAX            = 0x01;  // First out-of-range text encoding byte (only 0x00 = ASCII is defined, spec 11.6.5)
static const uint8_t EP_PROTOCOL_MAX              = 0x03;  // First out-of-range TID_EP_PROTOCOL value (valid 0x00..0x02)
static const uint8_t EP_DIRECTION_MAX             = 0x08;  // First out-of-range TID_EP_DIRECTION value (bits 0..2 used)
static const uint8_t INPUT_PRIORITY_MAX_VALUE     = 200;   // Highest valid per-slot input priority
static const uint16_t INPUT_PRIORITY_MAX_SLOTS    = 512;   // Longest TID_EP_INPUT_PRIORITY payload
static const uint8_t MULT_OVERRIDE_OCTET_MIN      = 0xE0;  // Lowest valid multicast first octet
static const uint8_t MULT_OVERRIDE_OCTET_MAX      = 0xEF;  // Highest valid multicast first octet
static const uint16_t MULT_OVERRIDE_LENGTH        = 4;     // IPv4 address
static const uint16_t TEXT_TID_MAX_LENGTH         = 65;    // 1 encoding byte + 64 text bytes

// Strict SET payload validation (spec 10.4 / SNAC 1251,1261,1451,1461,3651,3751,
// 4151,4451,4551): a SET carrying an out-of-range value or a wrong/oversized
// length must be silently ignored. Returns true only when the payload is a
// well-formed, in-range value for the given TID. TIDs not listed here fall
// through to the caller's blob-capacity / read-only handling.
inline bool IsValidSetPayload(uint16_t tid, const uint8_t* value, uint16_t length)
{
    if (length == 0 || value == 0) {
        return false;  // a zero-length TLV is a GET, never a SET
    }

    uint16_t i;

    switch (tid) {
        // Text TIDs: [1 encoding byte][0..64 text] => length 1..65
        case TID_RT_DEVICE_LABEL:
        case TID_RT_MODEL_NAME:
        case TID_EP_LABEL:
            return (length <= TEXT_TID_MAX_LENGTH && value[0] < TEXT_ENCODING_MAX);

        // Single-byte enum TIDs with a defined valid range
        case TID_RT_MULT:
            return (length == 1 && value[0] < MULT_STATE_MAX);        // 0x00..0x01
        case TID_RT_IDENTIFY:
            return (length == 1 && value[0] < IDENTIFY_MAX);          // 0x00..0x04
        case TID_EP_DIRECTION:
            return (length == 1 && value[0] < EP_DIRECTION_MAX);      // bits0-1 dir + bit2 rdm
        case TID_EP_PROTOCOL:
            return (length == 1 && value[0] < EP_PROTOCOL_MAX);
        case TID_EP_FAILOVER:
            return (length == 3 && value[0] <= FAILOVER_STOP_DMX);
        case TID_EP_DMX_TIMING:
            return (length == 2 &&
                    value[0] <= DMX_TIMING_DELTA &&
                    value[1] <= DMX_OUTPUT_MINIMUM);

        // Fixed-length numeric TIDs
        case TID_EP_UNIVERSE:
        {
            if (length != 2) {
                return false;
            }
            uint16_t u = (static_cast<uint16_t>(value[0]) << 8) | value[1];
            return (u >= MIN_UNIVERSE && u <= MAX_UNIVERSE);
        }
        case TID_EP_INPUT_PRIORITY:
            if (length > INPUT_PRIORITY_MAX_SLOTS) {
                return false;
            }
            for (i = 0; i < length; ++i) {
                if (value[i] > INPUT_PRIORITY_MAX_VALUE) {
                    return false;
                }
            }
            return true;
        case TID_EP_MULT_OVERRIDE:
            if (length != MULT_OVERRIDE_LENGTH) {
                return false;
            }
            if (value[0] >= MULT_OVERRIDE_OCTET_MIN && value[0] <= MULT_OVERRIDE_OCTET_MAX) {
                return true;
            }
            // 0.0.0.0 = revert to the default folded address
            return (value[0] == 0 && value[1] == 0 && value[2] == 0 && value[3] == 0);

        default:
            return true;
    }
}

static const char* FIXED_SCOPE = SIGNET_URI_SCOPE_DEFAULT;

static const uint16_t DEFAULT_EP1_UNIVERSE = 1;

static const uint8_t DEFAULT_ROOT_ENDPOINT_COUNT[2] = { 0x00, 0x01 };
static const uint8_t DEFAULT_ROOT_MULT[1] = { 0x00 };
static const uint8_t DEFAULT_ROOT_IDENTIFY[1] = { 0x00 };
static const uint8_t DEFAULT_ROOT_STATUS[4] = { 0x00, 0x00, 0x00, 0x00 };
static const uint8_t DEFAULT_ROOT_ROLE_CAPABILITY[4] = { 0x00, 0x00, 0x00, ROLE_CAP_NODE };
static const uint8_t DEFAULT_ROOT_PROTOCOL_VERSION[1] = { 0x01 };

static const char* DEFAULT_ROOT_DEVICE_LABEL = "Sig-Net Node";
static const char* DEFAULT_ROOT_MODEL_NAME = "Fogmaster 5000";
static const char* DEFAULT_ROOT_FIRMWARE_STRING = "v1.08 Spec";

static const char* DEFAULT_EP1_LABEL = "EP1";
static const uint8_t DEFAULT_EP1_MULT_OVERRIDE[4] = { 0x00, 0x00, 0x00, 0x00 };
static const uint8_t DEFAULT_EP1_DIRECTION[1] = { static_cast<uint8_t>(EP_DIR_CONSUMER) };
static const uint8_t DEFAULT_EP1_INPUT_PRIORITY[1] = { 100 };
static const uint8_t DEFAULT_EP1_STATUS[4] = { 0x00, 0x00, 0x00, 0x00 };
static const uint8_t DEFAULT_EP1_FAILOVER[3] = { 0x00, 0x00, 0x00 };
// Maximum simultaneous TID_LEVEL sources merged per universe (spec 10.x: minimum 4).
static const int      EP1_MAX_MERGE_SOURCES = 4;
static const uint32_t LEVEL_SOURCE_TIMEOUT_MS = 2500;  // A source silent this long stops contributing (E1.31 style)
static const uint8_t  LEVEL_DEFAULT_PRIORITY  = 100;   // Priority of a source that has not sent TID_PRIORITY
static const uint16_t EP1_MAX_MERGE_SOURCES_WIRE = 4;  // same value as the TID_EP_CAPABILITY [4-5] field

// TID_EP_CAPABILITY (spec 11.7.4): [0-3] 32-bit big-endian bitfield, [4-5] Maximum
// Merge Sources. Bit 5 (per-slot priority) is clear: this node uses the Constrained
// Node Fallback (first TID_PRIORITY byte = universe priority).
static const uint8_t DEFAULT_EP1_CAPABILITY[6] = { 0x00, 0x00, 0x00, static_cast<uint8_t>(EP_CAP_CONSUME_LEVEL),
                                                   static_cast<uint8_t>(EP1_MAX_MERGE_SOURCES_WIRE >> 8),
                                                   static_cast<uint8_t>(EP1_MAX_MERGE_SOURCES_WIRE & 0xFF) };
static const uint16_t DEFAULT_EP1_CAPABILITY_LEN = 6;
static const uint8_t DEFAULT_EP1_REFRESH_CAPABILITY[1] = { 44 };
static const uint8_t DEFAULT_EP1_DMX_TIMING[2] = { DMX_TIMING_CONTINUOUS, DMX_OUTPUT_MAXIMUM };
static const uint8_t DEFAULT_EP1_PROTOCOL[1] = { 0x00 };

// SECURITY_EVENT poll-reply placeholder: a well-formed 7-byte TLV (spec 11.8.1:
// event code 0x0000, counter 0, address type 0x00 = None) meaning "no events".
// Live event history is reported via the dedicated GET path (BuildSecurityEventPayload).
static const uint8_t DEFAULT_ROOT_SECURITY_EVENT[7] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
static const uint16_t DEFAULT_ROOT_SECURITY_EVENT_LEN = 7;

} // namespace Node
} // namespace SigNet

#endif // SIGNET_NODE_PROFILE_HPP