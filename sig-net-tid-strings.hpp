//==============================================================================
// Sig-Net Protocol Framework - Node UI String Helpers
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
// Description:  Display-string helpers for all Sig-Net node enum types.
//               No VCL, no Winsock dependencies - pure portable C++.
//
//               Usage pattern:
//                 // Populate a TComboBox:
//                 for (int i = 0; i < SigNet::Node::IDENTIFY_STATE_COUNT; ++i)
//                     ComboRootIdentify->Items->Add(SigNet::Node::GetIdentifyStateLabel(static_cast<SigNet::IdentifyState>(i)));
//
//                 // Recover from combo index:
//                 uint8_t identify = SigNet::Node::GetIdentifyStateValue(ComboRootIdentify->ItemIndex);
//==============================================================================

#ifndef SIGNET_NODE_STRINGS_HPP
#define SIGNET_NODE_STRINGS_HPP

#include "sig-net-constants.hpp"

namespace SigNet {
namespace Node {

//------------------------------------------------------------------------------
// IdentifyState  (TID_RT_IDENTIFY  0x0607)
//------------------------------------------------------------------------------

static const int IDENTIFY_STATE_COUNT = 4;

inline const char* GetIdentifyStateLabel(IdentifyState state)
{
    switch (state) {
        case IDENTIFY_OFF:    return "0x00 - Off";
        case IDENTIFY_SUBTLE: return "0x01 - Subtle";
        case IDENTIFY_FULL:   return "0x02 - Full";
        case IDENTIFY_MUTE:   return "0x03 - Mute (dark-sky)";
        default:              return "";
    }
}

// Returns the protocol byte value for a given combo index.
inline uint8_t GetIdentifyStateValue(int index)
{
    return static_cast<uint8_t>(index & 0x03);
}

//------------------------------------------------------------------------------
// FailoverMode  (TID_EP_FAILOVER  0x0908)
//------------------------------------------------------------------------------

static const int FAILOVER_MODE_COUNT = 5;

inline const char* GetFailoverModeLabel(FailoverMode mode)
{
    switch (mode) {
        case FAILOVER_HOLD_LAST:  return "0x00 - Hold Last State";
        case FAILOVER_BLACKOUT:   return "0x01 - Blackout (all slots 0)";
        case FAILOVER_FULL:       return "0x02 - Full (all slots 255)";
        case FAILOVER_PLAY_SCENE: return "0x03 - Play Scene";
        case FAILOVER_STOP_DMX:   return "0x04 - Stop generating DMX";
        default:                  return "";
    }
}

inline uint8_t GetFailoverModeValue(int index)
{
    return static_cast<uint8_t>(index & 0x07);
}

//------------------------------------------------------------------------------
// EpDirection  (TID_EP_DIRECTION  0x0905)
//------------------------------------------------------------------------------

static const int EP_DIRECTION_COUNT = 4;

inline const char* GetEpDirectionLabel(EpDirection direction)
{
    switch (direction) {
        case EP_DIR_DISABLED: return "0x00 - Disabled";
        case EP_DIR_CONSUMER: return "0x01 - Consumer (receives Sig-Net, consumes internally)";
        case EP_DIR_SUPPLIER: return "0x02 - Supplier (generates Sig-Net)";
        case EP_DIR_FALLBACK: return "0x03 - Fallback (monitor input, auto-consume on signal loss)";
        default:              return "";
    }
}

inline uint8_t GetEpDirectionValue(int index)
{
    return static_cast<uint8_t>(index & 0x03);
}

//------------------------------------------------------------------------------
// Ipv4Mode  (TID_NW_IPV4_MODE  0x0502)
//------------------------------------------------------------------------------

static const int IPV4_MODE_COUNT = 2;

inline const char* GetIpv4ModeLabel(Ipv4Mode mode)
{
    switch (mode) {
        case IPV4_MODE_STATIC: return "0x00 - Static";
        case IPV4_MODE_DHCP:   return "0x01 - DHCP";
        default:               return "";
    }
}

inline uint8_t GetIpv4ModeValue(int index)
{
    return static_cast<uint8_t>(index & 0x01);
}

//------------------------------------------------------------------------------
// Ipv6Mode  (TID_NW_IPV6_MODE  0x0581)
//------------------------------------------------------------------------------

static const int IPV6_MODE_COUNT = 3;

inline const char* GetIpv6ModeLabel(Ipv6Mode mode)
{
    switch (mode) {
        case IPV6_MODE_STATIC: return "0x00 - Static";
        case IPV6_MODE_SLAAC:  return "0x01 - SLAAC";
        case IPV6_MODE_DHCPV6: return "0x02 - DHCPv6";
        default:               return "";
    }
}

inline uint8_t GetIpv6ModeValue(int index)
{
    return static_cast<uint8_t>(index & 0x03);
}

//------------------------------------------------------------------------------
// RebootType  (TID_RT_REBOOT  0x060A)
// Combo index 0 = Warm (0xFE), index 1 = Hardware reset (0xFF)
//------------------------------------------------------------------------------

static const int REBOOT_TYPE_COUNT = 2;

inline const char* GetRebootTypeLabel(RebootType reboot_type)
{
    switch (reboot_type) {
        case REBOOT_WARM:     return "0xfe - Warm reboot";
        case REBOOT_HARDWARE: return "0xff - Hardware reset";
        default:              return "";
    }
}

// Returns the protocol byte value: index 0 → 0xFE (warm), index 1 → 0xFF (hardware).
inline uint8_t GetRebootTypeValue(int index)
{
    return (index == 0) ? static_cast<uint8_t>(REBOOT_WARM)
                        : static_cast<uint8_t>(REBOOT_HARDWARE);
}

// Returns the combo index for a given reboot type byte value.
inline int GetRebootTypeIndex(uint8_t value)
{
    return (value == static_cast<uint8_t>(REBOOT_WARM)) ? 0 : 1;
}

//------------------------------------------------------------------------------
// MultRoutingState  (TID_RT_MULT  0x0606)
//------------------------------------------------------------------------------

static const int MULT_ROUTING_STATE_COUNT = 2;

inline const char* GetMultRoutingStateLabel(MultRoutingState state)
{
    switch (state) {
        case MULT_STATE_DEFAULT: return "0x00 - Default";
        case MULT_STATE_CUSTOM:  return "0x01 - Custom";
        default:                 return "";
    }
}

inline uint8_t GetMultRoutingStateValue(int index)
{
    return static_cast<uint8_t>(index & 0x01);
}

//------------------------------------------------------------------------------
// DmxTransmitMode  (TID_EP_DMX_TIMING byte 0  0x0909)
//------------------------------------------------------------------------------

static const int DMX_TRANSMIT_MODE_COUNT = 2;

inline const char* GetDmxTransmitModeLabel(DmxTransmitMode mode)
{
    switch (mode) {
        case DMX_TIMING_CONTINUOUS: return "0x00 - Continuous";
        case DMX_TIMING_DELTA:      return "0x01 - Delta (change-only)";
        default:                    return "";
    }
}

inline uint8_t GetDmxTransmitModeValue(int index)
{
    return static_cast<uint8_t>(index & 0x01);
}

//------------------------------------------------------------------------------
// DmxOutputTiming  (TID_EP_DMX_TIMING byte 1  0x0909)
//------------------------------------------------------------------------------

static const int DMX_OUTPUT_TIMING_COUNT = 3;

inline const char* GetDmxOutputTimingLabel(DmxOutputTiming timing)
{
    switch (timing) {
        case DMX_OUTPUT_MAXIMUM: return "0x00 - Maximum rate";
        case DMX_OUTPUT_MEDIUM:  return "0x01 - Medium rate";
        case DMX_OUTPUT_MINIMUM: return "0x02 - Minimum rate";
        default:                 return "";
    }
}

inline uint8_t GetDmxOutputTimingValue(int index)
{
    return static_cast<uint8_t>(index & 0x03);
}

//------------------------------------------------------------------------------
// Supported TIDs CheckListBox table
//
// Each entry maps a combo/checklist row index to a TID value and display label.
// Entries marked mandated=true are checked by default.
//------------------------------------------------------------------------------

struct SupportedTidEntry {
    uint16_t    tid;
    const char* label;
    bool        mandated;
    bool        allowed_root_ep;
    bool        allowed_data_ep;
    bool        write_only;
    bool        supports_get;
};

static const int SUPPORTED_TID_COUNT = 46;

inline const SupportedTidEntry* GetSupportedTidTable()
{
    static const SupportedTidEntry k_table[SUPPORTED_TID_COUNT] = {
        { TID_RT_ENDPOINT_COUNT,   "TID_RT_ENDPOINT_COUNT (0x0602) - mandated",  true,  true,  false, false, true  },
        { TID_RT_PROTOCOL_VERSION, "TID_RT_PROTOCOL_VERSION (0x0603) - mandated",true,  true,  false, false, true  },
        { TID_RT_FIRMWARE_VERSION, "TID_RT_FIRMWARE_VERSION (0x0604) - mandated",true,  true,  false, false, true  },
        { TID_RT_DEVICE_LABEL,     "TID_RT_DEVICE_LABEL (0x0605) - mandated",    true,  true,  false, false, true  },
        { TID_RT_MULT,             "TID_RT_MULT_OVERRIDE (0x0606) - mandated",    true,  true,  false, false, true  },
        { TID_RT_IDENTIFY,         "TID_RT_IDENTIFY (0x0607) - mandated",        true,  true,  false, false, true  },
        { TID_RT_STATUS,           "TID_RT_STATUS (0x0608) - mandated",          true,  true,  false, false, true  },
        { TID_RT_ROLE_CAPABILITY,  "TID_RT_ROLE_CAPABILITY (0x0609) - mandated", true,  true,  false, false, true  },
        { TID_RT_MODEL_NAME,       "TID_RT_MODEL_NAME (0x060B) - mandated",      true,  true,  false, false, true  },
        { TID_RT_SCOPE,            "TID_RT_SCOPE (0x060C) - mandated",           true,  true,  false, false, true  },
        { TID_RT_REBOOT,           "TID_RT_REBOOT (0x060A) - optional",          false, true,  false, true,  false },
        { TID_RT_UNPROVISION,      "TID_RT_UNPROVISION (0x0401) - optional",     false, true,  false, true,  false },
        { TID_NW_MAC_ADDRESS,      "TID_NW_MAC_ADDRESS (0x0501) - optional",     false, true,  false, false, true  },
        { TID_NW_IPV4_MODE,        "TID_NW_IPV4_MODE (0x0502) - optional",       false, true,  false, false, true  },
        { TID_NW_IPV4_ADDRESS,     "TID_NW_IPV4_ADDRESS (0x0503) - optional",    false, true,  false, false, true  },
        { TID_NW_IPV4_NETMASK,     "TID_NW_IPV4_NETMASK (0x0504) - optional",    false, true,  false, false, true  },
        { TID_NW_IPV4_GATEWAY,     "TID_NW_IPV4_GATEWAY (0x0505) - optional",    false, true,  false, false, true  },
        { TID_NW_IPV4_CURRENT,     "TID_NW_IPV4_CURRENT (0x0506) - optional",    false, true,  false, false, true  },
        { TID_NW_IPV6_MODE,        "TID_NW_IPV6_MODE (0x0581) - optional",       false, true,  false, false, true  },
        { TID_NW_IPV6_ADDRESS,     "TID_NW_IPV6_ADDRESS (0x0582) - optional",    false, true,  false, false, true  },
        { TID_NW_IPV6_PREFIX,      "TID_NW_IPV6_PREFIX (0x0583) - optional",     false, true,  false, false, true  },
        { TID_NW_IPV6_GATEWAY,     "TID_NW_IPV6_GATEWAY (0x0584) - optional",    false, true,  false, false, true  },
        { TID_NW_IPV6_CURRENT,     "TID_NW_IPV6_CURRENT (0x0585) - optional",    false, true,  false, false, true  },
        { TID_DG_SECURITY_EVENT,   "TID_DG_SECURITY_EVENT (0xFF01) - diagnostics",true,true, false,false, true  },
        { TID_DG_MESSAGE,          "TID_DG_MESSAGE (0xFF02) - diagnostics",      false, true,  false, false, true  },

        { TID_EP_UNIVERSE,         "TID_EP_UNIVERSE (0x0901) - data endpoint",   true,  false, true,  false, true  },
        { TID_EP_LABEL,            "TID_EP_LABEL (0x0902) - data endpoint",      true,  false, true,  false, true  },
        { TID_EP_MULT_OVERRIDE,    "TID_EP_MULT_OVERRIDE (0x0903) - data endpoint",true,false,true,  false, true  },
        { TID_EP_CAPABILITY,       "TID_EP_CAPABILITY (0x0904) - data endpoint", true,  false, true,  false, true  },
        { TID_EP_DIRECTION,        "TID_EP_DIRECTION (0x0905) - data endpoint",  true,  false, true,  false, true  },
        { TID_EP_INPUT_PRIORITY,   "TID_EP_INPUT_PRIORITY (0x0906) - data endpoint",false,false,true,false, true  },
        { TID_EP_STATUS,           "TID_EP_STATUS (0x0907) - data endpoint",     true,  false, true,  false, true  },
        { TID_EP_FAILOVER,         "TID_EP_FAILOVER (0x0908) - data endpoint",   true,  false, true,  false, true  },
        { TID_EP_DMX_TIMING,       "TID_EP_DMX_TIMING (0x0909) - data endpoint", false, false, true,  false, true  },
        { TID_EP_REFRESH_CAPABILITY,"TID_EP_REFRESH_CAPABILITY (0x090A) - data endpoint",false,false,true,false, true  },
        { TID_RDM_TOD_BACKGROUND,  "TID_RDM_TOD_BACKGROUND (0x0305) - data endpoint",false,false,true,false, true  },
        { TID_RDM_FLOW_CONTROL,    "TID_RDM_FLOW_CONTROL (0x0306) - data endpoint",false,false,true,false, true  },
        { TID_RDM_TOD_DATA,        "TID_RDM_TOD_DATA (0x0304) - query only",     false, false, true,  false, true  },
        { TID_RDM_COMMAND,         "TID_RDM_COMMAND (0x0301) - RDM command",      false, true,  true,  true,  false },
        { TID_RDM_RESPONSE,        "TID_RDM_RESPONSE (0x0302) - RDM response",    false, true,  true,  false, false },
        { TID_RDM_TOD_CONTROL,     "TID_RDM_TOD_CONTROL (0x0303) - TOD control",  false, false, true,  true,  false },
        { TID_DG_LEVEL_FOLDBACK,   "TID_DG_LEVEL_FOLDBACK (0xFF03) - query only",false,false,true,false, true  },

        { TID_LEVEL,               "TID_LEVEL (0x0101) - data stream",           false, false, true,  false, false },
        { TID_PRIORITY,            "TID_PRIORITY (0x0102) - data stream",        false, false, true,  false, false },
        { TID_SYNC,                "TID_SYNC (0x0201) - data stream",            false, false, true,  false, false },
        { TID_TIMECODE,            "TID_TIMECODE (0x0202) - data stream",        false, false, true,  false, false }
    };
    return k_table;
}

// Shared lookup. Linear scan; k_table is ordered for UI/wire iteration so
// can't be re-sorted for bsearch. One touch point if that ever changes.
inline const SupportedTidEntry* FindTidEntry(uint16_t tid)
{
    const SupportedTidEntry* table = GetSupportedTidTable();
    for (int i = 0; i < SUPPORTED_TID_COUNT; ++i) {
        if (table[i].tid == tid) {
            return &table[i];
        }
    }
    return 0;
}

inline bool IsTidWriteOnly(uint16_t tid)
{
    const SupportedTidEntry* e = FindTidEntry(tid);
    return e ? e->write_only : false;
}

inline bool IsTidGetSupported(uint16_t tid)
{
    if (tid == TID_RT_SUPPORTED_TIDS) {
        return true;
    }
    const SupportedTidEntry* e = FindTidEntry(tid);
    return e ? e->supports_get : false;
}

inline bool IsTidAllowedForEndpoint(uint16_t tid, bool is_root_ep, bool is_data_ep)
{
    if (tid == TID_POLL_REPLY) {
        return is_root_ep || is_data_ep;
    }

    if (tid == TID_RT_SUPPORTED_TIDS) {
        return is_root_ep;
    }

    const SupportedTidEntry* e = FindTidEntry(tid);
    if (e) {
        return (is_root_ep && e->allowed_root_ep) ||
               (is_data_ep && e->allowed_data_ep);
    }

    switch (tid) {
        case TID_EP_UNIVERSE:
        case TID_EP_LABEL:
        case TID_EP_MULT_OVERRIDE:
        case TID_EP_CAPABILITY:
        case TID_EP_DIRECTION:
        case TID_EP_INPUT_PRIORITY:
        case TID_EP_STATUS:
        case TID_EP_FAILOVER:
        case TID_EP_DMX_TIMING:
        case TID_EP_REFRESH_CAPABILITY:
        case TID_RDM_TOD_BACKGROUND:
        case TID_RDM_FLOW_CONTROL:
        case TID_RDM_TOD_DATA:
        case TID_DG_LEVEL_FOLDBACK:
        case TID_LEVEL:
        case TID_PRIORITY:
        case TID_SYNC:
        case TID_TIMECODE:
            return is_data_ep;
        default:
            return false;
    }
}

} // namespace Node
} // namespace SigNet

#endif // SIGNET_NODE_STRINGS_HPP
