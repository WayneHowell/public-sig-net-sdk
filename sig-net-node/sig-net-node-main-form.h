//==============================================================================
// Sig-Net Protocol Framework - Node Application Main Form
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
// Description:  Main form header for Sig-Net Node application.
//               VCL form with Root Endpoint (EP0) and one Virtual Data
//               Endpoint (EP1) configuration UI. Phase 1: UI only.
//               Sig-Net network wiring deferred to Phase 2.
//==============================================================================

//---------------------------------------------------------------------------

#ifndef SigNetNodeMainFormH
#define SigNetNodeMainFormH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.ComCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.ExtCtrls.hpp>
#include <Vcl.Graphics.hpp>
#include <Vcl.Samples.Spin.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>

// Sig-Net library
#include "sig-net.hpp"

// Node data model + string helpers
#include "..\sig-net-tid-strings.hpp"
#include "..\sig-net-node-data.hpp"
#include "..\sig-net-node-udp-listen.hpp"
#include "..\sig-net-node-udp-socket.hpp"

// K0 Entry Dialog
#include "..\sig-net-passcode\K0EntryDialog.h"

// Self-Test Results Dialog
#include "..\sig-net-self-test-dialog\SelfTestResultsForm.h"

// NIC Selection Dialog
#include "..\sig-net-nic\NicSelectDialog.h"

//---------------------------------------------------------------------------
class TFormSigNetNode : public TForm
{
__published:    // IDE-managed Components

    // -------------------------------------------------------------------------
    // Main panel (fills client area)
    // -------------------------------------------------------------------------
    TPanel *PanelMain;

    // -------------------------------------------------------------------------
    // FroupBoxConfig - K0, NIC, self-test
    // -------------------------------------------------------------------------
    TGroupBox *FroupBoxConfig;
    TButton *ButtonSelectK0;
    TButton *ButtonDeprovision;
    TLabel *LabelNicIP;
    TEdit *EditNicIP;
    TButton *ButtonSelectNic;
    TButton *ButtonSelfTest;
    TButton *ButtonGoLive;

    // -------------------------------------------------------------------------
    // GroupBoxDevice - Device / TUID parameters
    // -------------------------------------------------------------------------
    TGroupBox *GroupBoxDevice;
    TLabel *LabelTUID;
    TEdit *EditTUID;
    TLabel *LabelUniverse;
    TSpinEdit *SpinUniverse;

    // -------------------------------------------------------------------------
    // Status log (docked to bottom of form)
    // -------------------------------------------------------------------------
    TGroupBox *GroupBoxStatus;
    TMemo *MemoStatus;
	TLabel *LabelRootDeviceLabel;
	TEdit *EditRootDeviceLabel;
	TButton *ButtonSetDeviceLabel;

    // -------------------------------------------------------------------------
    // GroupBoxLevelMimic - mimic of received TID_LEVEL for EP1 slots 1-3
    // -------------------------------------------------------------------------
    TGroupBox *GroupBoxLevelMimic;
    TLabel *LabelLevelCh1;
    TTrackBar *TrackLevelCh1;
    TLabel *LabelLevelCh1Val;
    TLabel *LabelLevelCh2;
    TTrackBar *TrackLevelCh2;
    TLabel *LabelLevelCh2Val;
    TLabel *LabelLevelCh3;
    TTrackBar *TrackLevelCh3;
    TLabel *LabelLevelCh3Val;

    // -------------------------------------------------------------------------
    // Event handlers
    // -------------------------------------------------------------------------
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall FormDestroy(TObject *Sender);
    void __fastcall ButtonSelectK0Click(TObject *Sender);
    void __fastcall ButtonSelfTestClick(TObject *Sender);
    void __fastcall ButtonSelectNicClick(TObject *Sender);
    void __fastcall ButtonDeprovisionClick(TObject *Sender);
    void __fastcall ButtonGoLiveClick(TObject *Sender);
    void __fastcall ButtonSetDeviceLabelClick(TObject *Sender);
    void __fastcall EditRootDeviceLabelExit(TObject *Sender);
    void __fastcall EditRootDeviceLabelKeyPress(TObject *Sender, wchar_t &Key);
    void __fastcall GenericEditExit(TObject *Sender);
    void __fastcall GenericEditKeyPress(TObject *Sender, wchar_t &Key);
    void __fastcall GenericComboChange(TObject *Sender);
    void __fastcall GenericCheckBoxClick(TObject *Sender);
    void __fastcall GenericSpinChange(TObject *Sender);

private:    // User declarations
    // Cryptographic keys
    uint8_t k0_key[32];
    uint8_t sender_key[32];
    uint8_t citizen_key[32];
    uint8_t manager_global_key[32];
    uint8_t manager_local_key[32];
    bool keys_valid;
    bool k0_set;

    // Device parameters
    uint8_t tuid[6];
    uint16_t endpoint;
    uint32_t session_id;
    uint32_t sequence_num;
    uint16_t message_id;

    // Statistics
    uint32_t send_count;
    uint32_t error_count;
    uint32_t last_packet_size;

    // Network socket
    SOCKET udp_socket;
    bool winsock_started;
    bool socket_initialized;
    AnsiString selected_nic_ip;
    SigNet::Node::UdpGroupState udp_groups;
    TTimer* receive_timer;
    uint32_t rx_packet_counter;
    uint32_t rx_accept_counter;
    uint32_t rx_reject_counter;
    uint32_t rx_idle_ticks;
    uint8_t last_poll_query_level;
    bool last_poll_reply_root;
    bool last_poll_reply_data;
    bool suppress_ui_change_events;

    // Security event tracking (spec 11.8.1 / TID_DG_SECURITY_EVENT).
    // Index i holds the RAM counter + last source IPv4 for Event Code (i + 1),
    // i.e. codes 0x0001..0x0008.
    static const int SECURITY_EVENT_CODE_COUNT = 8;
    uint32_t security_event_counts[SECURITY_EVENT_CODE_COUNT];
    uint8_t  security_event_src_ip[SECURITY_EVENT_CODE_COUNT][4];
    uint32_t security_event_last_tx_tick[SECURITY_EVENT_CODE_COUNT];  // per-code rate limit

    // Lifecycle / Lost-Mode state machine (spec 10.2.5). Armed by the Go Live
    // button once NIC + scope + K0 are set (none of which are persisted).
    bool node_is_live;
    bool node_in_lost_mode;
    uint32_t last_valid_poll_tick;   // GetTickCount() at last authenticated poll RX
    uint32_t last_lost_tx_tick;      // GetTickCount() at last node_lost announce
    SigNet::Node::FreshnessTracker node_freshness_tracker;

    // Phase 2 shared user data model
    SigNet::NodeUserData node_user_data;

    // Identity/session config (non-TID fields used by BuildNodeQueryPayload)
    SigNet::Node::NodeConfig node_config;

    // Private methods
    void UpdateStatusDisplay();
    void LogMessage(const String& msg);
    void LogError(const String& msg);
    bool ApplyScopeFromUI();
    bool ParseK0FromHex(const String& hex_string);
    bool ParseTUIDFromHex(const String& hex_string);
    bool ParseHexTUIDField(const String& hex_string, uint8_t out_tuid[6]);
    static void UdpLogThunk(const char* message, bool is_error, void* user_context);
    bool EnsureSocketInitialized();
    void ShutdownSocket();
    bool SendRawPacket(const uint8_t* packet, uint16_t packet_len, const char* destination_ip, const String& context_label);
    void RefreshReceiverGroups();
    void WarnIfLoopbackSelected();
    void __fastcall ReceiveTimerTick(TObject *Sender);
    static void UdpPacketThunk(const uint8_t* packet, uint16_t packet_len, const sockaddr_in& source_addr, void* user_context);
    void PollReceiveSocket();
    void ProcessIncomingPacket(const uint8_t* packet, uint16_t packet_len, const sockaddr_in& source_addr);
    bool StoreBlobFromBytes(SigNet::TidDataBlob& blob, uint16_t tid, const uint8_t* value, uint16_t length, uint8_t value_type);
    bool StoreTextBlobWire(SigNet::TidDataBlob& blob, uint16_t tid, const uint8_t* text, uint16_t text_len);
    void MarkBlobStale(SigNet::TidDataBlob& blob);
    void InitializeNodeUserDataFromUI();
    bool HandlePollTLV(const SigNet::TLVBlock& tlv);
    void HandleGetRequest(uint16_t tid, uint16_t reply_endpoint);
    bool SendGetResponse(uint16_t tid, uint16_t reply_endpoint);
    int  HandleSetRequest(uint16_t tid, const uint8_t* value, uint16_t length, bool from_manager);
    bool SendSetReply(const uint16_t* tids, int count, uint16_t reply_endpoint);
    bool SendAnnounce(bool lost_mode, const String& reason);
    void UpdateLevelMimic();
    void RecordSecurityEvent(uint16_t code, uint32_t src_ipv4_net);
    int32_t BuildSecurityEventPayload(SigNet::PacketBuffer& payload);
    bool SendSecurityEvent(uint16_t code);
    bool SendProactiveResponse(const String& reason);
    bool SendPollReplyWithQueryLevel(uint8_t query_level, uint16_t reply_endpoint, const String& reason);
    bool SendStaleResponseForEndpoint(uint16_t reply_endpoint, const String& reason);
    int32_t AppendTLVRaw(SigNet::PacketBuffer& payload, uint16_t tid, const uint8_t* value, uint16_t len);
    int32_t BuildQueryLevelPayload(uint8_t query_level, uint16_t reply_endpoint, SigNet::PacketBuffer& payload);
    void SyncUIFromStaleBlobs();
    void SendStaleTIDsToManager();
    void UpdateK0DependentControls();
    void CommitControlFromUI(TObject* sender, const String& trigger_source);
    void CommitRootDeviceLabelFromUI(const String& trigger_source);

public:     // User declarations
    __fastcall TFormSigNetNode(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TFormSigNetNode *FormSigNetNode;
//---------------------------------------------------------------------------
#endif
