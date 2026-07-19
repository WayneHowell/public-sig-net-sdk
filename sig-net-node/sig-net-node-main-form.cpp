//==============================================================================
// Sig-Net Protocol Framework - Node Application Main Form Implementation
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
// Description:  Node application main form. 
//==============================================================================

//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "sig-net-node-main-form.h"
#include "..\sig-net-crypto.hpp"
#include "..\sig-net-node-profile.hpp"
#include "sig-net-parse.hpp"
#include "..\sig-net-node-data.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TFormSigNetNode *FormSigNetNode;

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 6
#define APP_VERSION_ID ((APP_VERSION_MAJOR << 8) | APP_VERSION_MINOR)

// SET application results (spec 10.4.x transaction paths).
static const int SET_RESULT_REJECTED  = 0;  // Invalid/unsupported → voids the whole transaction
static const int SET_RESULT_UNCHANGED = 1;  // Valid SET, value identical → no CHANGE_COUNT bump
static const int SET_RESULT_CHANGED   = 2;  // Valid SET with a real state change

// Lifecycle timing (spec Appendix defaults): poll_time = 3s, node_lost_timeout = 3.
// A live Node enters Lost Mode after this many ms without an authenticated poll.
static const uint32_t POLL_TIME_MS           = 3000;
static const int      NODE_LOST_TIMEOUT_POLLS = 3;
static const uint32_t NODE_LOST_THRESHOLD_MS  = POLL_TIME_MS * NODE_LOST_TIMEOUT_POLLS;

// Spec 11.8.1: proactive TID_DG_SECURITY_EVENT multicasts are rate-limited to a
// maximum of one packet per second per Event Code.
static const uint32_t SECURITY_EVENT_MIN_INTERVAL_MS = 1000;

static void SecureZeroBuffer(void* ptr, size_t len)
{
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len > 0) {
        *p++ = 0;
        --len;
    }
}

//---------------------------------------------------------------------------
__fastcall TFormSigNetNode::TFormSigNetNode(TComponent* Owner)
    : TForm(Owner)
{
    keys_valid = false;
    k0_set = false;
    endpoint = 1;
    session_id = 1;
    sequence_num = 1;
    message_id = 1;
    send_count = 0;
    error_count = 0;
    last_packet_size = 0;
    udp_socket = INVALID_SOCKET;
    winsock_started = false;
    socket_initialized = false;
    SigNet::Node::ResetUdpGroupState(udp_groups);
    receive_timer = 0;
    rx_packet_counter = 0;
    rx_accept_counter = 0;
    rx_reject_counter = 0;
    rx_idle_ticks = 0;
    last_poll_query_level = SigNet::QUERY_HEARTBEAT;
    last_poll_reply_root = false;
    last_poll_reply_data = true;
    suppress_ui_change_events = false;
    SigNet::Node::ResetFreshnessTracker(node_freshness_tracker);

    memset(security_event_counts, 0, sizeof(security_event_counts));
    memset(security_event_src_ip, 0, sizeof(security_event_src_ip));
    memset(security_event_last_tx_tick, 0, sizeof(security_event_last_tx_tick));

    node_is_live = false;
    node_in_lost_mode = false;
    last_valid_poll_tick = 0;
    last_lost_tx_tick = 0;

    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));
    memset(manager_global_key, 0, sizeof(manager_global_key));
    memset(manager_local_key, 0, sizeof(manager_local_key));
    memset(tuid, 0, sizeof(tuid));
}

bool TFormSigNetNode::EnsureSocketInitialized()
{
    // Bind the receive socket to the selected NIC's unicast IP so that unicast
    // traffic to this node lands on THIS socket even when another Sig-Net app on
    // the same host shares UDP/5683 (SO_REUSEADDR). Empty/unresolved -> INADDR_ANY.
    char nic_ip[16];
    nic_ip[0] = 0;
    SigNet::Node::ExtractValidIPv4FromText(selected_nic_ip.c_str(), nic_ip, sizeof(nic_ip));
    return SigNet::Node::EnsureSocketInitialized(udp_socket,
                                                 winsock_started,
                                                 socket_initialized,
                                                 nic_ip,
                                                 TFormSigNetNode::UdpLogThunk,
                                                 this);
}

void TFormSigNetNode::ShutdownSocket()
{
    SigNet::Node::ShutdownSocket(udp_socket,
                                 winsock_started,
                                 socket_initialized,
                                 udp_groups);
}

void __fastcall TFormSigNetNode::FormCreate(TObject *Sender)
{
    Caption = String().sprintf(L"SDK Node Device. v%d.%d", APP_VERSION_MAJOR, APP_VERSION_MINOR);

    ApplyScopeFromUI();

    EditRootDeviceLabel->MaxLength = 64;

    // Device parameters - ephemeral TUID (fallback if generation fails)
    {
        const uint16_t mfg_code = static_cast<uint16_t>((SigNet::SoemCodeSdkNode >> 16) & 0xFFFF);
        int32_t tuid_result = SigNet::Crypto::TUID_GenerateEphemeral(mfg_code, tuid);
        if (tuid_result != SigNet::SIGNET_SUCCESS) {
            tuid[0] = static_cast<uint8_t>((mfg_code >> 8) & 0xFF);
            tuid[1] = static_cast<uint8_t>(mfg_code & 0xFF);
            tuid[2] = 0x80;
            tuid[3] = 0x00;
            tuid[4] = 0x00;
            tuid[5] = 0x00;
        }
        String tuid_text;
        tuid_text.sprintf(L"0x%02x%02x%02x%02x%02x%02x",
                          tuid[0], tuid[1], tuid[2], tuid[3], tuid[4], tuid[5]);
        EditTUID->Text = tuid_text;
        if (tuid_result != SigNet::SIGNET_SUCCESS) {
            LogError("Ephemeral TUID generation failed; using fallback TUID.");
        }
    }
    SpinUniverse->MinValue = SigNet::MIN_UNIVERSE;
    SpinUniverse->MaxValue = SigNet::MAX_UNIVERSE;
    SpinUniverse->Value = SigNet::Node::DEFAULT_EP1_UNIVERSE;


    EditRootDeviceLabel->Text = SigNet::Node::DEFAULT_ROOT_DEVICE_LABEL;
    EditRootDeviceLabel->OnExit = EditRootDeviceLabelExit;
    EditRootDeviceLabel->OnKeyPress = EditRootDeviceLabelKeyPress;
    ButtonSetDeviceLabel->Visible = false;
    ButtonSetDeviceLabel->Enabled = false;


    // ---------------------------------------------------------------------------
    UpdateK0DependentControls();
    InitializeNodeUserDataFromUI();

    if (EnsureSocketInitialized()) {
        RefreshReceiverGroups();
    } else {
        LogError("Startup socket initialization failed; timer will retry.");
    }
    WarnIfLoopbackSelected();

    receive_timer = new TTimer(this);
    receive_timer->Interval = 20;
    receive_timer->Enabled = true;
    receive_timer->OnTimer = ReceiveTimerTick;

    LogMessage("Sig-Net Node initialized (Phase 2 RX active). BUILD=RXDBG_20260404A");
    LogMessage("Receiver listens for /poll, /node and /level traffic and handles TID switch processing.");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::FormDestroy(TObject *Sender)
{
    if (receive_timer) {
        receive_timer->Enabled = false;
    }

    SigNet::Node::LeaveAllReceiverGroups(udp_socket,
                                         socket_initialized,
                                         udp_groups,
                                         TFormSigNetNode::UdpLogThunk,
                                         this);

    ShutdownSocket();
    LogMessage("UDP socket closed.");

    SecureZeroBuffer(k0_key, sizeof(k0_key));
    SecureZeroBuffer(sender_key, sizeof(sender_key));
    SecureZeroBuffer(citizen_key, sizeof(citizen_key));
    SecureZeroBuffer(manager_global_key, sizeof(manager_global_key));
    SecureZeroBuffer(manager_local_key, sizeof(manager_local_key));
    SecureZeroBuffer(tuid, sizeof(tuid));

    keys_valid = false;
    k0_set = false;
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSelectK0Click(TObject *Sender)
{
    if (!this->ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Invalid TUID - cannot open K0 dialog");
        return;
    }

    TK0EntryDialog *dialog = new TK0EntryDialog(this);
    dialog->SetTUID(tuid);

    try {
        if (dialog->ShowModal() == mrOk) {
            dialog->GetK0(k0_key);

            int32_t result = SigNet::Crypto::DeriveSenderKey(k0_key, sender_key);
            if (result != SigNet::SIGNET_SUCCESS) {
                LogError(String().sprintf(L"Failed to derive sender key: error %d", result));
                keys_valid = false;
                k0_set = false;
                UpdateK0DependentControls();
                return;
            }

            result = SigNet::Crypto::DeriveCitizenKey(k0_key, citizen_key);
            if (result != SigNet::SIGNET_SUCCESS) {
                LogError(String().sprintf(L"Failed to derive citizen key: error %d", result));
                keys_valid = false;
                k0_set = false;
                UpdateK0DependentControls();
                return;
            }

            result = SigNet::Crypto::DeriveManagerGlobalKey(k0_key, manager_global_key);
            if (result != SigNet::SIGNET_SUCCESS) {
                LogError(String().sprintf(L"Failed to derive manager global key: error %d", result));
                keys_valid = false;
                k0_set = false;
                UpdateK0DependentControls();
                return;
            }

            result = SigNet::Crypto::DeriveManagerLocalKey(k0_key, tuid, manager_local_key);
            if (result != SigNet::SIGNET_SUCCESS) {
                LogError(String().sprintf(L"Failed to derive manager local key: error %d", result));
                keys_valid = false;
                k0_set = false;
                UpdateK0DependentControls();
                return;
            }

            keys_valid = true;
            k0_set = true;
            UpdateK0DependentControls();
            LogMessage("K0 selected. Ks, Kc, Km_global and Km_local derived successfully.");
            LogMessage("Node is ready to transmit On-Boot Announce.");
        } else {
            LogMessage("K0 selection cancelled.");
        }
    }
    __finally {
        delete dialog;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSelfTestClick(TObject *Sender)
{
    TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
    form->ShowModal();
    delete form;
}
//---------------------------------------------------------------------------

// Go Live: transmit the On-Boot Announce (spec 10.2.5) and arm the lifecycle
// state machine. NIC + scope + K0 must already be set (none are persisted).
void __fastcall TFormSigNetNode::ButtonGoLiveClick(TObject *Sender)
{
    if (!keys_valid) {
        LogError("Cannot go live: provision the node (select K0) first.");
        return;
    }

    if (!EnsureSocketInitialized()) {
        LogError("Cannot go live: network socket is not ready.");
        return;
    }

    if (!SendAnnounce(false, "On-Boot Announce (Go Live)")) {
        return;
    }

    node_is_live = true;
    node_in_lost_mode = false;
    last_valid_poll_tick = static_cast<uint32_t>(GetTickCount());
    LogMessage("Node is LIVE. Lifecycle state machine armed; watching for manager polls.");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSelectNicClick(TObject *Sender)
{
    TNicSelectDialog* dlg = new TNicSelectDialog(Application);
    dlg->SetCurrentIP(selected_nic_ip);
    try {
        if (dlg->ShowModal() == mrOk) {
            selected_nic_ip = dlg->GetSelectedIP();
            EditNicIP->Text = String(selected_nic_ip.c_str());
            LogMessage("Node interface set to: " + String(selected_nic_ip.c_str()));

            // Rebind the receive socket to the new NIC. Because the socket now
            // binds to a specific NIC IP (not INADDR_ANY), changing NIC requires a
            // close + re-open so unicast to the new address is delivered here.
            SigNet::Node::LeaveAllReceiverGroups(udp_socket,
                                                 socket_initialized,
                                                 udp_groups,
                                                 TFormSigNetNode::UdpLogThunk,
                                                 this);
            ShutdownSocket();
            if (!EnsureSocketInitialized()) {
                LogError("Failed to re-open socket on the newly selected NIC.");
            }
            RefreshReceiverGroups();
            WarnIfLoopbackSelected();
        }
    }
    __finally {
        delete dlg;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonDeprovisionClick(TObject *Sender)
{
    SecureZeroBuffer(k0_key, sizeof(k0_key));
    SecureZeroBuffer(sender_key, sizeof(sender_key));
    SecureZeroBuffer(citizen_key, sizeof(citizen_key));
    SecureZeroBuffer(manager_global_key, sizeof(manager_global_key));
    SecureZeroBuffer(manager_local_key, sizeof(manager_local_key));

    keys_valid = false;
    k0_set = false;
    UpdateK0DependentControls();
    LogMessage("Device de-provisioned. Keys cleared; select K0 to re-provision.");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSetDeviceLabelClick(TObject *Sender)
{
    CommitRootDeviceLabelFromUI("button");
}
//---------------------------------------------------------------------------

void TFormSigNetNode::CommitRootDeviceLabelFromUI(const String& trigger_source)
{
    if (suppress_ui_change_events) {
        return;
    }

    String lbl = EditRootDeviceLabel->Text.Trim();
    if (lbl.IsEmpty()) {
        return;
    }

    AnsiString ansi_lbl = AnsiString(lbl);
    uint16_t text_len = (uint16_t)ansi_lbl.Length();
    if (text_len > 64) {
        text_len = 64;
    }
    uint8_t wire[65];
    wire[0] = 0x00;  // Encoding: UTF-8/ASCII (spec 11.6.5)
    memcpy(&wire[1], ansi_lbl.c_str(), text_len);
    bool changed = false;
    if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_device_label,
                                                      SigNet::TID_RT_DEVICE_LABEL,
                                                      wire,
                                                      (uint16_t)(text_len + 1),
                                                      SigNet::TID_BLOB_TEXT,
                                                      changed) && changed) {
        MarkBlobStale(node_user_data.root.tid_rt_device_label);
        LogMessage("Device label committed (" + trigger_source + ") and marked stale.");
        if (!keys_valid) {
            LogMessage("K0/keys not set yet; proactive TX is deferred.");
        }
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditRootDeviceLabelExit(TObject *Sender)
{
    CommitRootDeviceLabelFromUI("focus-exit");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditRootDeviceLabelKeyPress(TObject *Sender, wchar_t &Key)
{
    if (Key == L'\r') {
        CommitRootDeviceLabelFromUI("enter");
        Key = 0;
    }
}
//---------------------------------------------------------------------------

void TFormSigNetNode::CommitControlFromUI(TObject* sender, const String& trigger_source)
{
    if (suppress_ui_change_events || !sender) {
        return;
    }

    bool changed = false;

    if (sender == SpinUniverse) {
        uint16_t ep1_universe = static_cast<uint16_t>(SpinUniverse->Value);
        uint8_t universe_payload[2] = {(uint8_t)(ep1_universe >> 8), (uint8_t)(ep1_universe & 0xFF)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_universe,
                                                          SigNet::TID_EP_UNIVERSE,
                                                          universe_payload,
                                                          2,
                                                          SigNet::TID_BLOB_U16,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.ep1.tid_ep_universe);
            RefreshReceiverGroups();
            LogMessage("EP1 universe committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::GenericEditExit(TObject *Sender)
{
    CommitControlFromUI(Sender, "focus-exit");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::GenericEditKeyPress(TObject *Sender, wchar_t &Key)
{
    if (Key == L'\r') {
        CommitControlFromUI(Sender, "enter");
        Key = 0;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::GenericComboChange(TObject *Sender)
{
    CommitControlFromUI(Sender, "change");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::GenericCheckBoxClick(TObject *Sender)
{
    CommitControlFromUI(Sender, "change");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::GenericSpinChange(TObject *Sender)
{
    CommitControlFromUI(Sender, "change");
}
//---------------------------------------------------------------------------

bool TFormSigNetNode::SendRawPacket(const uint8_t* packet, uint16_t packet_len, const char* destination_ip, const String& context_label)
{
    if (!packet || packet_len == 0 || !destination_ip) {
        LogError(context_label + ": invalid packet arguments");
        error_count++;
        return false;
    }

    if (!EnsureSocketInitialized()) {
        error_count++;
        return false;
    }

    if (!(socket_initialized && udp_socket != INVALID_SOCKET)) {
        LogError(context_label + ": socket not initialized");
        error_count++;
        return false;
    }

    char nic_ip[16];
    nic_ip[0] = '\0';
    SigNet::ExtractIPv4Token(selected_nic_ip.c_str(), nic_ip, sizeof(nic_ip));
    bool loopback = (strncmp(nic_ip, "127.", 4) == 0);
    if (!loopback && nic_ip[0] != '\0') {
        struct in_addr iface_addr;
        iface_addr.s_addr = inet_addr(nic_ip);
        if (iface_addr.s_addr == INADDR_NONE) {
            LogError(context_label + ": invalid selected NIC IP; using OS default multicast interface.");
        } else {
            if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                           (char*)&iface_addr, sizeof(iface_addr)) == SOCKET_ERROR) {
                LogError(context_label + String().sprintf(L": IP_MULTICAST_IF failed: WSA %d", WSAGetLastError()));
            }
        }
    }

    sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);
    dest_addr.sin_addr.s_addr = inet_addr(destination_ip);

    int bytes_sent = sendto(
        udp_socket,
        (const char*)packet,
        packet_len,
        0,
        (sockaddr*)&dest_addr,
        sizeof(dest_addr)
    );

    if (bytes_sent == SOCKET_ERROR && !loopback) {
        struct in_addr any_addr;
        any_addr.s_addr = INADDR_ANY;
        setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF, (char*)&any_addr, sizeof(any_addr));
        bytes_sent = sendto(udp_socket, (const char*)packet, packet_len, 0,
                            (sockaddr*)&dest_addr, sizeof(dest_addr));
        if (bytes_sent != SOCKET_ERROR) {
            LogMessage(context_label + ": retry succeeded using default multicast interface.");
        }
    }

    if (bytes_sent == SOCKET_ERROR) {
        LogError(context_label + String().sprintf(L": sendto() failed: WSA error %d", WSAGetLastError()));
        error_count++;
        return false;
    }

    if (bytes_sent != packet_len) {
        LogError(context_label + String().sprintf(L": partial send: %d of %d bytes", bytes_sent, packet_len));
        error_count++;
        return false;
    }

    return true;
}

void TFormSigNetNode::RefreshReceiverGroups()
{
    char nic_ip[16];
    nic_ip[0] = 0;

    // Resolve a valid NIC IP in priority order:
    // selected_nic_ip -> EditNicIP -> startup auto-select -> loopback fallback.
    if (!SigNet::Node::ExtractValidIPv4FromText(selected_nic_ip.c_str(), nic_ip, sizeof(nic_ip))) {
        SigNet::Node::ExtractValidIPv4FromText(AnsiString(EditNicIP->Text).c_str(), nic_ip, sizeof(nic_ip));
    }

    if (nic_ip[0] == 0) {
        AnsiString auto_nic = SigNet::SelectDefaultStartupNicIP();
        if (!SigNet::Node::ExtractValidIPv4FromText(auto_nic.c_str(), nic_ip, sizeof(nic_ip))) {
            strncpy(nic_ip, "127.0.0.1", sizeof(nic_ip) - 1);
            nic_ip[sizeof(nic_ip) - 1] = 0;
        }
    }

    if (selected_nic_ip != nic_ip) {
        selected_nic_ip = nic_ip;
        EditNicIP->Text = String(nic_ip);
    }

    uint16_t ep1_universe = static_cast<uint16_t>(SpinUniverse->Value);
    SigNet::Node::RefreshReceiverGroups(udp_socket,
                                        socket_initialized,
                                        nic_ip,
                                        ep1_universe,
                                        udp_groups,
                                        TFormSigNetNode::UdpLogThunk,
                                        this);
}

void __fastcall TFormSigNetNode::ReceiveTimerTick(TObject *Sender)
{
    static int tick_count = 0;
    tick_count++;

    if (!socket_initialized || udp_socket == INVALID_SOCKET) {
        if (tick_count % 10 == 0) {  // Log every 10 ticks to avoid spam
            LogMessage(String().sprintf(L"[Timer tick %d] Socket not initialized (socket_initialized=%d, udp_socket=%X), attempting init...", 
                tick_count, socket_initialized ? 1 : 0, (unsigned)udp_socket));
        }
        if (EnsureSocketInitialized()) {
            LogMessage("RX timer recovered socket initialization.");
        } else {
            if (tick_count % 20 == 0) {  // Log failures every 20 ticks
                LogMessage(String().sprintf(L"[Timer tick %d] Socket init attempt FAILED, will retry", tick_count));
            }
            return;
        }
    }

    RefreshReceiverGroups();
    PollReceiveSocket();

    SyncUIFromStaleBlobs();
    SendStaleTIDsToManager();

    // Lifecycle / Lost-Mode state machine (spec 10.2.5). Only runs once the node
    // has been taken live via the Go Live button.
    if (node_is_live && keys_valid) {
        uint32_t now = static_cast<uint32_t>(GetTickCount());
        if (!node_in_lost_mode) {
            if ((now - last_valid_poll_tick) > NODE_LOST_THRESHOLD_MS) {
                node_in_lost_mode = true;
                last_lost_tx_tick = now - POLL_TIME_MS;  // transmit immediately on this tick
                LogMessage("No manager poll within node_lost_timeout; entering Lost Mode.");
            }
        }
        if (node_in_lost_mode) {
            if ((now - last_lost_tx_tick) >= POLL_TIME_MS) {
                SendAnnounce(true, "Lost Mode heartbeat");
                last_lost_tx_tick = now;
            }
        }
    }
}

void TFormSigNetNode::UdpLogThunk(const char* message, bool is_error, void* user_context)
{
    TFormSigNetNode* form = static_cast<TFormSigNetNode*>(user_context);
    if (!form || !message) {
        return;
    }

    if (is_error) {
        form->LogError(String(message));
    } else {
        form->LogMessage(String(message));
    }
}

void TFormSigNetNode::UdpPacketThunk(const uint8_t* packet,
                                     uint16_t packet_len,
                                     const sockaddr_in& source_addr,
                                     void* user_context)
{
    TFormSigNetNode* form = static_cast<TFormSigNetNode*>(user_context);
    if (!form) {
        return;
    }
    form->ProcessIncomingPacket(packet, packet_len, source_addr);
}

void TFormSigNetNode::PollReceiveSocket()
{
    if (!socket_initialized || udp_socket == INVALID_SOCKET) {
        return;
    }

    bool saw_packet = false;
    int last_error = 0;
    int32_t result = SigNet::Node::PollUdpSocket(udp_socket,
                                                  SigNet::MAX_UDP_PAYLOAD,
                                                  50,
                                                  TFormSigNetNode::UdpPacketThunk,
                                                  this,
                                                  saw_packet,
                                                  last_error);
    if (result != SigNet::SIGNET_SUCCESS && last_error != WSAEWOULDBLOCK) {
        LogError(String().sprintf(L"recvfrom failed: WSA %d", last_error));
        return;
    }

    if (saw_packet) {
        rx_idle_ticks = 0;
    }

    if (!saw_packet) {
        rx_idle_ticks++;
        if ((rx_idle_ticks % 250) == 0) {
            LogMessage(String().sprintf(L"RX idle: no packets for %u ticks (groups: poll=%s mgr=%s ep1=%s)",
                                        rx_idle_ticks,
                                        udp_groups.joined_manager_poll_group ? L"Y" : L"N",
                                        udp_groups.joined_manager_send_group ? L"Y" : L"N",
                                        udp_groups.joined_ep1_universe_group ? L"Y" : L"N"));
        }
    }
}

bool TFormSigNetNode::StoreBlobFromBytes(SigNet::TidDataBlob& blob,
                                         uint16_t tid,
                                         const uint8_t* value,
                                         uint16_t length,
                                         uint8_t value_type)
{
    if (length > SigNet::TID_BLOB_MAX_BYTES) {
        return false;
    }

    blob.tid = tid;
    blob.length = length;
    blob.value_type = value_type;

    if (length > 0 && value) {
        memcpy(blob.data.bytes, value, length);
    }
    if (length < SigNet::TID_BLOB_MAX_BYTES) {
        blob.data.bytes[length] = 0;
        blob.data.text[length] = 0;
    }
    return true;
}

// Stores a text TID in Sig-Net wire format: [0] encoding byte (0x00 = UTF-8/ASCII)
// followed by the raw text (spec 11.6.5 / 11.6.11 / 11.7.2). Every send path emits
// blob.data.bytes verbatim, so keeping the encoding byte in the blob makes all
// GET/poll/announce/stale responses correct without per-path special casing.
bool TFormSigNetNode::StoreTextBlobWire(SigNet::TidDataBlob& blob,
                                        uint16_t tid,
                                        const uint8_t* text,
                                        uint16_t text_len)
{
    if (text_len > SigNet::TID_BLOB_MAX_BYTES - 1) {
        text_len = SigNet::TID_BLOB_MAX_BYTES - 1;
    }
    uint8_t buf[SigNet::TID_BLOB_MAX_BYTES];
    buf[0] = 0x00;  // Encoding: UTF-8/ASCII
    if (text_len > 0 && text) {
        memcpy(&buf[1], text, text_len);
    }
    return StoreBlobFromBytes(blob, tid, buf, static_cast<uint16_t>(text_len + 1), SigNet::TID_BLOB_TEXT);
}

void TFormSigNetNode::MarkBlobStale(SigNet::TidDataBlob& blob)
{
    if (SigNet::Node::IsTidWriteOnly(blob.tid)) {
        blob.manager_is_stale = false;
        return;
    }
    blob.manager_is_stale = true;
}

void TFormSigNetNode::InitializeNodeUserDataFromUI()
{
    // --- node_config: identity fields (not TID blobs) ---
    ParseTUIDFromHex(EditTUID->Text.Trim());  // updates this->tuid
    memcpy(node_config.tuid, tuid, 6);

    node_config.mfg_code = static_cast<uint16_t>((SigNet::SoemCodeSdkNode >> 16) & 0xFFFF);
    node_config.product_variant_id = static_cast<uint16_t>(SigNet::SoemCodeSdkNode & 0xFFFF);
    node_config.endpoint = 1;
    // NOTE: change_count is a persistent transaction counter (spec 10.4.4). It is
    // NOT a UI field and must NOT be reset here; it only starts at 0 (NodeConfig
    // ctor / offboard) and increments on persistent SETs.


    if (node_user_data.root.tid_rt_endpoint_count.length != 0) {
        return;
    }

    // --- Root EP: ENDPOINT_COUNT ---
    {
        StoreBlobFromBytes(node_user_data.root.tid_rt_endpoint_count,
                           SigNet::TID_RT_ENDPOINT_COUNT,
                           SigNet::Node::DEFAULT_ROOT_ENDPOINT_COUNT,
                           2,
                           SigNet::TID_BLOB_U16);
    }

    // --- Root EP: PROTOCOL_VERSION ---
    {
        StoreBlobFromBytes(node_user_data.root.tid_rt_protocol_version,
                           SigNet::TID_RT_PROTOCOL_VERSION,
                           SigNet::Node::DEFAULT_ROOT_PROTOCOL_VERSION,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- Root EP: FIRMWARE_VERSION (2-byte big-endian ID + string bytes) ---
    {
        uint16_t fw_id = APP_VERSION_ID;
        AnsiString fw_str = AnsiString(SigNet::Node::DEFAULT_ROOT_FIRMWARE_STRING);
        uint16_t str_len = (uint16_t)fw_str.Length();
        if (str_len > 64) { str_len = 64; }
        uint8_t fw_blob[2 + 64];
        fw_blob[0] = (uint8_t)(fw_id >> 8);
        fw_blob[1] = (uint8_t)(fw_id & 0xFF);
        if (str_len > 0) { memcpy(fw_blob + 2, fw_str.c_str(), str_len); }
        StoreBlobFromBytes(node_user_data.root.tid_rt_firmware_version,
                           SigNet::TID_RT_FIRMWARE_VERSION, fw_blob, 2 + str_len, SigNet::TID_BLOB_BYTES);
    }

    // --- Root EP: DEVICE_LABEL ---
    {
        AnsiString device_label = AnsiString(EditRootDeviceLabel->Text);
        StoreTextBlobWire(node_user_data.root.tid_rt_device_label,
                          SigNet::TID_RT_DEVICE_LABEL,
                          (const uint8_t*)device_label.c_str(),
                          (uint16_t)device_label.Length());
    }

    // --- Root EP: RT_MULT ---
    {
        StoreBlobFromBytes(node_user_data.root.tid_rt_mult,
                           SigNet::TID_RT_MULT,
                           SigNet::Node::DEFAULT_ROOT_MULT,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- Root EP: IDENTIFY ---
    {
        StoreBlobFromBytes(node_user_data.root.tid_rt_identify,
                           SigNet::TID_RT_IDENTIFY,
                           SigNet::Node::DEFAULT_ROOT_IDENTIFY,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- Root EP: STATUS ---
    {
        StoreBlobFromBytes(node_user_data.root.tid_rt_status,
                           SigNet::TID_RT_STATUS,
                           SigNet::Node::DEFAULT_ROOT_STATUS,
                           4,
                           SigNet::TID_BLOB_U32);
    }

    // --- Root EP: ROLE_CAPABILITY (spec 11.6.9: 32-bit BE bitfield, length 4) ---
    {
        StoreBlobFromBytes(node_user_data.root.tid_rt_role_capability,
                           SigNet::TID_RT_ROLE_CAPABILITY,
                           SigNet::Node::DEFAULT_ROOT_ROLE_CAPABILITY,
                           4,
                           SigNet::TID_BLOB_U32);
    }

    // --- Root EP: MODEL_NAME (SoemCode prefix stripped here - store just the name) ---
    {
        AnsiString model_name = AnsiString(SigNet::Node::DEFAULT_ROOT_MODEL_NAME);
        if (model_name.Length() > 64) {
            model_name = model_name.SubString(1, 64);
        }
        StoreTextBlobWire(node_user_data.root.tid_rt_model_name,
                          SigNet::TID_RT_MODEL_NAME,
                          (const uint8_t*)model_name.c_str(),
                          (uint16_t)model_name.Length());
    }

    // --- Root EP: SCOPE ---
    {
        AnsiString scope_text = AnsiString(SigNet::Node::FIXED_SCOPE);
        StoreBlobFromBytes(node_user_data.root.tid_rt_scope,
                           SigNet::TID_RT_SCOPE,
                           (const uint8_t*)scope_text.c_str(),
                           (uint16_t)scope_text.Length(),
                           SigNet::TID_BLOB_TEXT);
    }

    // --- Root EP: SUPPORTED_TIDS (2 bytes per checked entry) ---
    {
        uint8_t tid_bytes[SigNet::Node::PROFILE_ADVERTISED_TID_COUNT * 2];
        uint16_t tid_byte_count = SigNet::Node::BuildSupportedTidBytes(tid_bytes, sizeof(tid_bytes));
        StoreBlobFromBytes(node_user_data.root.tid_rt_supported_tids,
                           SigNet::TID_RT_SUPPORTED_TIDS, tid_bytes, tid_byte_count, SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: UNIVERSE ---
    {
        uint16_t ep1_universe = static_cast<uint16_t>(SpinUniverse->Value);
        uint8_t universe_payload[2] = {(uint8_t)(ep1_universe >> 8), (uint8_t)(ep1_universe & 0xFF)};
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_universe,
                           SigNet::TID_EP_UNIVERSE, universe_payload, 2, SigNet::TID_BLOB_U16);
    }

    // --- EP1: LABEL ---
    {
        AnsiString ep1_label = AnsiString(SigNet::Node::DEFAULT_EP1_LABEL);
        StoreTextBlobWire(node_user_data.ep1.tid_ep_label,
                          SigNet::TID_EP_LABEL,
                          (const uint8_t*)ep1_label.c_str(),
                          (uint16_t)ep1_label.Length());
    }

    // --- EP1: MULT_OVERRIDE (IPv4, network byte order) ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_mult_override,
                           SigNet::TID_EP_MULT_OVERRIDE,
                           SigNet::Node::DEFAULT_EP1_MULT_OVERRIDE,
                           4,
                           SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: DIRECTION (bits 0..1 = direction, bit 2 = RDM enable) ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_direction,
                           SigNet::TID_EP_DIRECTION,
                           SigNet::Node::DEFAULT_EP1_DIRECTION,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- EP1: INPUT_PRIORITY (keep existing if already set by Sig-Net; seed from 100) ---
    if (node_user_data.ep1.tid_ep_input_priority.length == 0) {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_input_priority,
                           SigNet::TID_EP_INPUT_PRIORITY,
                           SigNet::Node::DEFAULT_EP1_INPUT_PRIORITY,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- EP1: STATUS ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_status,
                           SigNet::TID_EP_STATUS,
                           SigNet::Node::DEFAULT_EP1_STATUS,
                           4,
                           SigNet::TID_BLOB_U32);
    }

    // --- EP1: FAILOVER (mode + scene high + scene low = 3 bytes) ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_failover,
                           SigNet::TID_EP_FAILOVER,
                           SigNet::Node::DEFAULT_EP1_FAILOVER,
                           3,
                           SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: CAPABILITY (bitfield) ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_capability,
                           SigNet::TID_EP_CAPABILITY,
                           SigNet::Node::DEFAULT_EP1_CAPABILITY,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- EP1: REFRESH_CAPABILITY ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_refresh_capability,
                           SigNet::TID_EP_REFRESH_CAPABILITY,
                           SigNet::Node::DEFAULT_EP1_REFRESH_CAPABILITY,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- EP1: DMX_TIMING (transmit mode byte + output timing byte) ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_dmx_timing,
                           SigNet::TID_EP_DMX_TIMING,
                           SigNet::Node::DEFAULT_EP1_DMX_TIMING,
                           2,
                           SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: PROTOCOL ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_protocol,
                           SigNet::TID_EP_PROTOCOL,
                           SigNet::Node::DEFAULT_EP1_PROTOCOL,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- EP1: RDM_TOD_BACKGROUND ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_rdm_port_config,
                           SigNet::TID_RDM_PORT_CONFIG,
                           SigNet::Node::DEFAULT_RDM_PORT_CONFIG,
                           1,
                           SigNet::TID_BLOB_U8);
    }

    // --- EP1: RDM_FLOW_CONTROL ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_rdm_flow_control,
                           SigNet::TID_RDM_FLOW_CONTROL,
                           SigNet::Node::DEFAULT_RDM_FLOW_CONTROL,
                           2,
                           SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: RDM_TOD_DATA ---
    {
        StoreBlobFromBytes(node_user_data.ep1.tid_rdm_tod_data,
                           SigNet::TID_RDM_TOD_DATA, 0, 0, SigNet::TID_BLOB_BYTES);
    }

    SigNet::Node::ClearAllManagerStaleFlags(node_user_data);
    SigNet::Node::ClearAllUIStaleFlags(node_user_data);
}

bool TFormSigNetNode::HandlePollTLV(const SigNet::TLVBlock& tlv)
{
    if (tlv.length != 25 || !tlv.value) {
        LogError("Invalid TID_POLL length (expected 25)");
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Cannot evaluate TID_POLL: local TUID is invalid.");
        return false;
    }

    const uint8_t* value = tlv.value;
    const uint8_t* tuid_lo = value + 10;
    const uint8_t* tuid_hi = value + 16;
    uint16_t target_endpoint = ((uint16_t)value[22] << 8) | value[23];
    uint8_t query_level = value[24];

    LogMessage(String().sprintf(L"TID_POLL parsed: endpoint=0x%04X query=%u", target_endpoint, query_level));

    if (query_level > SigNet::QUERY_EXTENDED) {
        LogError("TID_POLL ignored: invalid QUERY_LEVEL");
        return false;
    }

    if (memcmp(tuid, tuid_lo, 6) < 0 || memcmp(tuid, tuid_hi, 6) > 0) {
        LogMessage("TID_POLL not for this node: local TUID outside requested range.");
        return false;
    }

    uint16_t ui_endpoint = 1;
    bool endpoint_match = (target_endpoint == 0xFFFF) ||
                          (target_endpoint == 0x0000) ||
                          (target_endpoint == ui_endpoint);

    if (!endpoint_match) {
        LogMessage(String().sprintf(L"TID_POLL endpoint mismatch: ui=%u target=0x%04X", ui_endpoint, target_endpoint));
        return false;
    }

    if (target_endpoint == 0xFFFF) {
        last_poll_reply_root = true;
        last_poll_reply_data = true;
    } else if (target_endpoint == 0x0000) {
        last_poll_reply_root = true;
        last_poll_reply_data = false;
    } else {
        last_poll_reply_root = false;
        last_poll_reply_data = true;
    }

    LogMessage(String().sprintf(L"Matched TID_POLL (QUERY_LEVEL=%u, endpoint=0x%04X, send_root=%u, send_data=%u)",
                                query_level,
                                target_endpoint,
                                last_poll_reply_root ? 1 : 0,
                                last_poll_reply_data ? 1 : 0));
    return true;
}

void TFormSigNetNode::HandleGetRequest(uint16_t tid, uint16_t reply_endpoint)
{
    LogMessage(String().sprintf(L"GET request received for TID 0x%04X (endpoint %u)", tid, reply_endpoint));
    SendGetResponse(tid, reply_endpoint);
}

// Records a security event occurrence for the given Event Code (spec 11.8.1),
// bumping the RAM counter and remembering the triggering packet's IPv4 source.
void TFormSigNetNode::RecordSecurityEvent(uint16_t code, uint32_t src_ipv4_net)
{
    if (code < 1 || code > SECURITY_EVENT_CODE_COUNT) {
        return;
    }
    int idx = code - 1;
    security_event_counts[idx]++;
    memcpy(security_event_src_ip[idx], &src_ipv4_net, 4);
}

// Builds the TID_DG_SECURITY_EVENT GET response payload: one 11-byte TLV per
// Event Code that has fired at least once (spec 11.8.1 / query with Length 0).
// Value: [0-1] code, [2-5] counter, [6] addr type (0x01 IPv4), [7-10] source IPv4.
int32_t TFormSigNetNode::BuildSecurityEventPayload(SigNet::PacketBuffer& payload)
{
    int i;
    for (i = 0; i < SECURITY_EVENT_CODE_COUNT; ++i) {
        if (security_event_counts[i] == 0) {
            continue;
        }
        uint16_t code = static_cast<uint16_t>(i + 1);
        uint32_t cnt = security_event_counts[i];
        uint8_t value[11];
        value[0] = static_cast<uint8_t>((code >> 8) & 0xFF);
        value[1] = static_cast<uint8_t>(code & 0xFF);
        value[2] = static_cast<uint8_t>((cnt >> 24) & 0xFF);
        value[3] = static_cast<uint8_t>((cnt >> 16) & 0xFF);
        value[4] = static_cast<uint8_t>((cnt >> 8) & 0xFF);
        value[5] = static_cast<uint8_t>(cnt & 0xFF);
        value[6] = 0x01;  // Address Type: IPv4
        memcpy(&value[7], security_event_src_ip[i], 4);
        int32_t result = AppendTLVRaw(payload, SigNet::TID_DG_SECURITY_EVENT, value, 11);
        if (result != SigNet::SIGNET_SUCCESS) {
            return result;
        }
    }
    return SigNet::SIGNET_SUCCESS;
}

// Spec 11.8.1: on detecting a qualifying security event, the Node unilaterally
// multicasts a TID_DG_SECURITY_EVENT for that Event Code to its Reply URI
// /node/{tuid}/0 (signed Kc). Rate-limited to one packet per second per code.
bool TFormSigNetNode::SendSecurityEvent(uint16_t code)
{
    if (!keys_valid) {
        return false;
    }
    if (code < 1 || code > SECURITY_EVENT_CODE_COUNT) {
        return false;
    }

    int idx = code - 1;
    uint32_t now = static_cast<uint32_t>(GetTickCount());
    if (security_event_last_tx_tick[idx] != 0 &&
        (now - security_event_last_tx_tick[idx]) < SECURITY_EVENT_MIN_INTERVAL_MS) {
        return false;  // rate-limited (spec 11.8.1)
    }

    if (!ApplyScopeFromUI()) {
        return false;
    }
    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        return false;
    }

    uint32_t cnt = security_event_counts[idx];
    uint8_t value[11];
    value[0] = static_cast<uint8_t>((code >> 8) & 0xFF);
    value[1] = static_cast<uint8_t>(code & 0xFF);
    value[2] = static_cast<uint8_t>((cnt >> 24) & 0xFF);
    value[3] = static_cast<uint8_t>((cnt >> 16) & 0xFF);
    value[4] = static_cast<uint8_t>((cnt >> 8) & 0xFF);
    value[5] = static_cast<uint8_t>(cnt & 0xFF);
    value[6] = 0x01;  // Address Type: IPv4
    memcpy(&value[7], security_event_src_ip[idx], 4);

    SigNet::PacketBuffer payload;
    int32_t result = AppendTLVRaw(payload, SigNet::TID_DG_SECURITY_EVENT, value, 11);
    if (result != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    SigNet::PacketBuffer packet;
    char uri_string[96];

    result = SigNet::CoAP::BuildCoAPHeader(packet, message_id);
    if (result != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    result = SigNet::BuildNodeURIPathOptions(packet, tuid, 0, uri_string, sizeof(uri_string));
    if (result != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    SigNet::SigNetOptions options;
    result = SigNet::BuildCommonSigNetOptions(packet,
                                              tuid,
                                              0,
                                              0x0000,
                                              session_id,
                                              sequence_num,
                                              &options);
    if (result != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    result = SigNet::FinalizePacketWithHMACAndPayload(packet,
                                                      uri_string,
                                                      options,
                                                      payload.GetBuffer(),
                                                      payload.GetSize(),
                                                      citizen_key);
    if (result != SigNet::SIGNET_SUCCESS) {
        return false;
    }

    if (packet.GetSize() > SigNet::MAX_UDP_PAYLOAD) {
        return false;
    }

    if (!SendRawPacket(packet.GetBuffer(), packet.GetSize(), SigNet::MULTICAST_NODE_SEND_IP, "SecurityEvent")) {
        return false;
    }

    security_event_last_tx_tick[idx] = now;
    send_count++;
    last_packet_size = packet.GetSize();
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
    }

    LogMessage(String().sprintf(L"TID_DG_SECURITY_EVENT multicast (code 0x%04X, count=%u)", code, cnt));
    return true;
}

// Spec 10.4.3 (Parameter Queries): a GET is a TLV with Length 0x0000 on the
// Command URI. The Node replies on its Reply URI (/node/{tuid}/{endpoint}),
// authenticated with the citizen key (Kc), packing the requested TID's current
// value. A Get-Response shall never carry Length 0x0000, so an empty parameter
// is silently ignored (matching the spec's "silently ignore" error handling).
bool TFormSigNetNode::SendGetResponse(uint16_t tid, uint16_t reply_endpoint)
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send GET response: keys not available");
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Cannot send GET response: invalid local TUID");
        return false;
    }

    // Refresh blob values from the current UI state before reading them.
    InitializeNodeUserDataFromUI();

    SigNet::PacketBuffer payload;
    int32_t result;

    if (tid == SigNet::TID_RT_SUPPORTED_TIDS) {
        // The supported-TID list is generated from the profile table, not stored
        // as a blob, so build it on demand.
        uint8_t tid_bytes[SigNet::Node::PROFILE_ADVERTISED_TID_COUNT * 2];
        uint16_t len = SigNet::Node::BuildSupportedTidBytes(tid_bytes, sizeof(tid_bytes));
        result = AppendTLVRaw(payload, tid, tid_bytes, len);
    } else if (tid == SigNet::TID_DG_SECURITY_EVENT) {
        // Pack one TLV per tracked Event Code (spec 11.8.1). If none have fired,
        // there is nothing to report and no reply is sent.
        result = BuildSecurityEventPayload(payload);
        if (result == SigNet::SIGNET_SUCCESS && payload.GetSize() == 0) {
            LogMessage("GET TID_DG_SECURITY_EVENT: no security events tracked; no reply sent.");
            return false;
        }
    } else if (tid == SigNet::TID_DG_LEVEL_FOLDBACK) {
        // Spec 11.9.3 note: if the level buffer is empty/uninitialised, reply with
        // length 1 and data 0 - never a zero-length Get-Response.
        const SigNet::TidDataBlob* blob = SigNet::Node::FindSupportedTidBlob(node_user_data, tid);
        if (blob && blob->length > 0) {
            result = AppendTLVRaw(payload, tid, blob->data.bytes, blob->length);
        } else {
            uint8_t empty_level = 0x00;
            result = AppendTLVRaw(payload, tid, &empty_level, 1);
        }
    } else {
        const SigNet::TidDataBlob* blob = SigNet::Node::FindSupportedTidBlob(node_user_data, tid);
        if (!blob || blob->length == 0) {
            LogMessage(String().sprintf(L"GET ignored: no value held for TID 0x%04X", tid));
            return false;
        }
        result = AppendTLVRaw(payload, tid, blob->data.bytes, blob->length);
    }

    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"GET response payload build failed for TID 0x%04X: %d", tid, result));
        return false;
    }

    SigNet::PacketBuffer packet;
    char uri_string[96];

    result = SigNet::CoAP::BuildCoAPHeader(packet, message_id);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"GET response CoAP header build failed: %d", result));
        return false;
    }

    result = SigNet::BuildNodeURIPathOptions(packet, tuid, reply_endpoint, uri_string, sizeof(uri_string));
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"GET response URI build failed: %d", result));
        return false;
    }

    SigNet::SigNetOptions options;
    result = SigNet::BuildCommonSigNetOptions(packet,
                                              tuid,
                                              reply_endpoint,
                                              0x0000,
                                              session_id,
                                              sequence_num,
                                              &options);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"GET response options build failed: %d", result));
        return false;
    }

    result = SigNet::FinalizePacketWithHMACAndPayload(packet,
                                                      uri_string,
                                                      options,
                                                      payload.GetBuffer(),
                                                      payload.GetSize(),
                                                      citizen_key);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"GET response finalize failed: %d", result));
        return false;
    }

    if (packet.GetSize() > SigNet::MAX_UDP_PAYLOAD) {
        LogError(String().sprintf(L"GET response dropped: packet size %u exceeds %u-byte limit",
                                  packet.GetSize(),
                                  SigNet::MAX_UDP_PAYLOAD));
        return false;
    }

    if (!SendRawPacket(packet.GetBuffer(), packet.GetSize(), SigNet::MULTICAST_NODE_SEND_IP, "GetResponse")) {
        return false;
    }

    send_count++;
    last_packet_size = packet.GetSize();
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
    }

    LogMessage(String().sprintf(L"GET response sent for TID 0x%04X (endpoint=%u, payload=%u bytes)",
                                tid,
                                reply_endpoint,
                                payload.GetSize()));
    return true;
}

int TFormSigNetNode::HandleSetRequest(uint16_t tid, const uint8_t* value, uint16_t length, bool from_manager)
{
    SigNet::TidDataBlob* blob = SigNet::Node::FindSupportedTidBlob(node_user_data, tid);
    if (!blob) {
        LogMessage(String().sprintf(L"SET received for unsupported TID 0x%04X (stored ignored)", tid));
        return SET_RESULT_REJECTED;
    }

    if ((tid == SigNet::TID_RT_DEVICE_LABEL || tid == SigNet::TID_EP_LABEL || tid == SigNet::TID_RT_MODEL_NAME) &&
        length > 65) {
        LogError(String().sprintf(L"SET rejected for TID 0x%04X: length %u exceeds 65 (1 encoding byte + 64 text)", tid, length));
        return SET_RESULT_REJECTED;
    }

    if (tid == SigNet::TID_RT_SCOPE) {
        LogError("SET rejected for TID_RT_SCOPE: node scope is fixed to local");
        return SET_RESULT_REJECTED;
    }

    // Strict input validation (spec 10.4): a SET carrying a wrong/oversized length
    // or an out-of-range value must be silently ignored, not applied. Rejecting
    // here voids the whole transaction (no reply, CHANGE_COUNT untouched).
    if (!SigNet::Node::IsValidSetPayload(tid, value, length)) {
        LogError(String().sprintf(L"SET rejected for TID 0x%04X: invalid SET length/value (len=%u)", tid, length));
        return SET_RESULT_REJECTED;
    }

    // Detect whether this SET actually changes the held value. Only a real state
    // change on a persistent TID may bump CHANGE_COUNT (spec 10.4.4).
    bool value_changed = (blob->length != length) ||
                         (length > 0 && memcmp(blob->data.bytes, value, length) != 0);

    uint8_t blob_type = SigNet::TID_BLOB_BYTES;
    if (tid == SigNet::TID_RT_DEVICE_LABEL ||
        tid == SigNet::TID_EP_LABEL ||
        tid == SigNet::TID_RT_MODEL_NAME ||
        tid == SigNet::TID_RT_SCOPE ||
        tid == SigNet::TID_DG_MESSAGE) {
        blob_type = SigNet::TID_BLOB_TEXT;
    }

    if (!StoreBlobFromBytes(*blob, tid, value, length, blob_type)) {
        LogError(String().sprintf(L"SET for TID 0x%04X exceeds blob capacity", tid));
        return SET_RESULT_REJECTED;
    }

    if (from_manager) {
        blob->manager_is_stale = false;
        blob->ui_is_stale = true;  // SyncUIFromStaleBlobs() will apply the change on the next timer tick
    } else {
        MarkBlobStale(*blob);
    }

    LogMessage(String().sprintf(L"SET applied for TID 0x%04X (len=%u, %s)", tid, length,
                                value_changed ? L"changed" : L"unchanged"));
    return value_changed ? SET_RESULT_CHANGED : SET_RESULT_UNCHANGED;
}

// Spec 10.4.4 (Consistency Tracking) / 11.1.3 (TID_SET_REPLY): after applying one
// or more SETs from a manager packet, the Node replies on its Reply URI with the
// altered parameter TLV(s) followed by a trailing TID_SET_REPLY carrying the
// current CHANGE_COUNT. The caller increments CHANGE_COUNT once per transaction
// (before this call) if at least one persistent parameter changed.
bool TFormSigNetNode::SendSetReply(const uint16_t* tids, int count, uint16_t reply_endpoint)
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send SET reply: keys not available");
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Cannot send SET reply: invalid local TUID");
        return false;
    }

    SigNet::PacketBuffer payload;
    int32_t result;
    int i;

    // Altered parameter TLV(s), read straight from the freshly-applied blobs.
    for (i = 0; i < count; ++i) {
        const SigNet::TidDataBlob* blob = SigNet::Node::FindSupportedTidBlob(node_user_data, tids[i]);
        if (!blob || blob->length == 0) {
            continue;
        }
        result = AppendTLVRaw(payload, tids[i], blob->data.bytes, blob->length);
        if (result != SigNet::SIGNET_SUCCESS) {
            LogError(String().sprintf(L"SET reply payload build failed for TID 0x%04X: %d", tids[i], result));
            return false;
        }
    }

    // Trailing TID_SET_REPLY carrying the current CHANGE_COUNT.
    result = SigNet::TLV::EncodeTID_SET_REPLY(payload, node_config.change_count);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"SET reply TID_SET_REPLY encode failed: %d", result));
        return false;
    }

    SigNet::PacketBuffer packet;
    char uri_string[96];

    result = SigNet::CoAP::BuildCoAPHeader(packet, message_id);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"SET reply CoAP header build failed: %d", result));
        return false;
    }

    result = SigNet::BuildNodeURIPathOptions(packet, tuid, reply_endpoint, uri_string, sizeof(uri_string));
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"SET reply URI build failed: %d", result));
        return false;
    }

    SigNet::SigNetOptions options;
    result = SigNet::BuildCommonSigNetOptions(packet,
                                              tuid,
                                              reply_endpoint,
                                              0x0000,
                                              session_id,
                                              sequence_num,
                                              &options);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"SET reply options build failed: %d", result));
        return false;
    }

    result = SigNet::FinalizePacketWithHMACAndPayload(packet,
                                                      uri_string,
                                                      options,
                                                      payload.GetBuffer(),
                                                      payload.GetSize(),
                                                      citizen_key);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"SET reply finalize failed: %d", result));
        return false;
    }

    if (packet.GetSize() > SigNet::MAX_UDP_PAYLOAD) {
        LogError(String().sprintf(L"SET reply dropped: packet size %u exceeds %u-byte limit",
                                  packet.GetSize(),
                                  SigNet::MAX_UDP_PAYLOAD));
        return false;
    }

    if (!SendRawPacket(packet.GetBuffer(), packet.GetSize(), SigNet::MULTICAST_NODE_SEND_IP, "SetReply")) {
        return false;
    }

    send_count++;
    last_packet_size = packet.GetSize();
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
    }

    LogMessage(String().sprintf(L"SET reply sent (endpoint=%u, tids=%d, change_count=%u, payload=%u bytes)",
                                reply_endpoint,
                                count,
                                node_config.change_count,
                                payload.GetSize()));
    return true;
}

// Spec 10.2.5 (On-Boot Notification) and Lost Mode: transmit the mandated
// announce TLV set (POLL_REPLY, PROTOCOL_VERSION, ROLE_CAPABILITY,
// ENDPOINT_COUNT, MULT_OVERRIDE) to the Reply URI /node/{tuid}/0 (Kc), or, when
// lost_mode is true, to /node_lost/{tuid} on the Lost-Mode multicast group.
bool TFormSigNetNode::SendAnnounce(bool lost_mode, const String& reason)
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send announce: keys not available");
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Cannot send announce: invalid local TUID");
        return false;
    }

    // Refresh blob values (and node_config) from the current UI state.
    InitializeNodeUserDataFromUI();

    SigNet::PacketBuffer payload;
    int32_t result = SigNet::TLV::EncodeTID_POLL_REPLY(payload,
                                                       node_config.tuid,
                                                       node_config.mfg_code,
                                                       node_config.product_variant_id,
                                                       node_config.change_count);
    if (result == SigNet::SIGNET_SUCCESS) {
        result = AppendTLVRaw(payload, SigNet::TID_RT_PROTOCOL_VERSION,
                              node_user_data.root.tid_rt_protocol_version.data.bytes,
                              node_user_data.root.tid_rt_protocol_version.length);
    }
    if (result == SigNet::SIGNET_SUCCESS) {
        result = AppendTLVRaw(payload, SigNet::TID_RT_ROLE_CAPABILITY,
                              node_user_data.root.tid_rt_role_capability.data.bytes,
                              node_user_data.root.tid_rt_role_capability.length);
    }
    if (result == SigNet::SIGNET_SUCCESS) {
        result = AppendTLVRaw(payload, SigNet::TID_RT_ENDPOINT_COUNT,
                              node_user_data.root.tid_rt_endpoint_count.data.bytes,
                              node_user_data.root.tid_rt_endpoint_count.length);
    }
    if (result == SigNet::SIGNET_SUCCESS) {
        result = AppendTLVRaw(payload, SigNet::TID_RT_MULT,
                              node_user_data.root.tid_rt_mult.data.bytes,
                              node_user_data.root.tid_rt_mult.length);
    }
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Announce payload build failed: %d", result));
        return false;
    }

    SigNet::PacketBuffer packet;
    char uri_string[96];

    result = SigNet::CoAP::BuildCoAPHeader(packet, message_id);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Announce CoAP header build failed: %d", result));
        return false;
    }

    if (lost_mode) {
        result = SigNet::BuildNodeLostURIPathOptions(packet, tuid, uri_string, sizeof(uri_string));
    } else {
        result = SigNet::BuildNodeURIPathOptions(packet, tuid, 0, uri_string, sizeof(uri_string));
    }
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Announce URI build failed: %d", result));
        return false;
    }

    SigNet::SigNetOptions options;
    result = SigNet::BuildCommonSigNetOptions(packet,
                                              tuid,
                                              0,
                                              0x0000,
                                              session_id,
                                              sequence_num,
                                              &options);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Announce options build failed: %d", result));
        return false;
    }

    result = SigNet::FinalizePacketWithHMACAndPayload(packet,
                                                      uri_string,
                                                      options,
                                                      payload.GetBuffer(),
                                                      payload.GetSize(),
                                                      citizen_key);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Announce finalize failed: %d", result));
        return false;
    }

    if (packet.GetSize() > SigNet::MAX_UDP_PAYLOAD) {
        LogError(String().sprintf(L"Announce dropped: packet size %u exceeds %u-byte limit",
                                  packet.GetSize(),
                                  SigNet::MAX_UDP_PAYLOAD));
        return false;
    }

    const char* dest_ip = lost_mode ? SigNet::MULTICAST_NODE_LOST_IP : SigNet::MULTICAST_NODE_SEND_IP;
    const char* context = lost_mode ? "NodeLostAnnounce" : "BootAnnounce";
    if (!SendRawPacket(packet.GetBuffer(), packet.GetSize(), dest_ip, context)) {
        return false;
    }

    send_count++;
    last_packet_size = packet.GetSize();
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
    }

    LogMessage(String().sprintf(L"%s sent (payload=%u bytes) reason=",
                                lost_mode ? L"node_lost announce" : L"On-Boot announce",
                                payload.GetSize()) + reason);
    return true;
}

bool TFormSigNetNode::SendProactiveResponse(const String& reason)
{
    bool send_root = last_poll_reply_root;
    bool send_data = last_poll_reply_data;
    uint16_t ui_endpoint = 1;

    if (!send_root && !send_data) {
        send_data = true;
    }

    if (send_root && !SendPollReplyWithQueryLevel(last_poll_query_level, 0, reason + " [EP0]")) {
        LogError("Proactive response send failed (EP0): " + reason);
        return false;
    }

    String data_ep_reason = reason + String().sprintf(L" [EP%u]", ui_endpoint);
    if (send_data && !SendPollReplyWithQueryLevel(last_poll_query_level, ui_endpoint, data_ep_reason)) {
        LogError("Proactive response send failed (Data EP): " + reason);
        return false;
    }

    SigNet::Node::ClearAllManagerStaleFlags(node_user_data);
    LogMessage("Proactive response sent; manager_is_stale flags cleared.");
    return true;
}

int32_t TFormSigNetNode::AppendTLVRaw(SigNet::PacketBuffer& payload, uint16_t tid, const uint8_t* value, uint16_t len)
{
    int32_t result = payload.WriteUInt16(tid);
    if (result != SigNet::SIGNET_SUCCESS) {
        return result;
    }

    result = payload.WriteUInt16(len);
    if (result != SigNet::SIGNET_SUCCESS) {
        return result;
    }

    if (len > 0 && value) {
        result = payload.WriteBytes(value, len);
        if (result != SigNet::SIGNET_SUCCESS) {
            return result;
        }
    }

    return SigNet::SIGNET_SUCCESS;
}

int32_t TFormSigNetNode::BuildQueryLevelPayload(uint8_t query_level, uint16_t reply_endpoint, SigNet::PacketBuffer& payload)
{
    // Refresh all blobs and node_config from the current UI state, then
    // delegate packet construction to the library function (no GUI access there).
    InitializeNodeUserDataFromUI();

    return SigNet::Node::BuildNodeQueryPayload(query_level,
                                               reply_endpoint,
                                               node_user_data,
                                               node_config,
                                               payload);
}

bool TFormSigNetNode::SendPollReplyWithQueryLevel(uint8_t query_level, uint16_t reply_endpoint, const String& reason)
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send poll reply: keys not available");
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Cannot send poll reply: invalid local TUID");
        return false;
    }

    uint8_t effective_query = query_level;
    SigNet::PacketBuffer payload;
    SigNet::PacketBuffer packet;
    char uri_string[96];
    int32_t result = SigNet::SIGNET_SUCCESS;

    while (true) {
        payload.Reset();
        result = BuildQueryLevelPayload(effective_query, reply_endpoint, payload);
        if (result != SigNet::SIGNET_SUCCESS) {
            if (result == SigNet::SIGNET_ERROR_BUFFER_FULL && effective_query > SigNet::QUERY_HEARTBEAT) {
                effective_query--;
                continue;
            }
            LogError(String().sprintf(L"BuildNodeQueryPayload failed: error %d", result));
            return false;
        }

        packet.Reset();
        result = SigNet::CoAP::BuildCoAPHeader(packet, message_id);
        if (result != SigNet::SIGNET_SUCCESS) {
            LogError(String().sprintf(L"Poll reply CoAP header build failed: %d", result));
            return false;
        }

        result = SigNet::BuildNodeURIPathOptions(packet, tuid, reply_endpoint, uri_string, sizeof(uri_string));
        if (result != SigNet::SIGNET_SUCCESS) {
            LogError(String().sprintf(L"Poll reply URI build failed: %d", result));
            return false;
        }

        SigNet::SigNetOptions options;
        result = SigNet::BuildCommonSigNetOptions(packet,
                                                  tuid,
                                                  reply_endpoint,
                                                  0x0000,
                                                  session_id,
                                                  sequence_num,
                                                  &options);
        if (result != SigNet::SIGNET_SUCCESS) {
            LogError(String().sprintf(L"Poll reply options build failed: %d", result));
            return false;
        }

        result = SigNet::FinalizePacketWithHMACAndPayload(packet,
                                                          uri_string,
                                                          options,
                                                          payload.GetBuffer(),
                                                          payload.GetSize(),
                                                          citizen_key);
        if (result == SigNet::SIGNET_SUCCESS) {
            break;
        }

        if (result == SigNet::SIGNET_ERROR_BUFFER_FULL && effective_query > SigNet::QUERY_HEARTBEAT) {
            effective_query--;
            continue;
        }

        LogError(String().sprintf(L"Poll reply finalize failed: %d", result));
        return false;
    }

    if (packet.GetSize() > SigNet::MAX_UDP_PAYLOAD) {
        LogError(String().sprintf(L"Poll reply dropped: packet size %u exceeds %u-byte limit",
                                  packet.GetSize(),
                                  SigNet::MAX_UDP_PAYLOAD));
        return false;
    }

    if (!SendRawPacket(packet.GetBuffer(), packet.GetSize(), SigNet::MULTICAST_NODE_SEND_IP, "PollReply")) {
        return false;
    }

    send_count++;
    last_packet_size = packet.GetSize();
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
    }

    LogMessage(String().sprintf(L"Poll reply sent (query=%u, endpoint=%u, payload=%u bytes)",
                                effective_query,
                                reply_endpoint,
                                payload.GetSize()) +
               " reason=" + reason);
    return true;
}

bool TFormSigNetNode::SendStaleResponseForEndpoint(uint16_t reply_endpoint, const String& reason)
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send stale response: keys not available");
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Cannot send stale response: invalid local TUID");
        return false;
    }

    bool is_root_ep = (reply_endpoint == 0);
    bool is_data_ep = !is_root_ep;

    SigNet::PacketBuffer payload;
    SigNet::PacketBuffer packet;
    char uri_string[96];
    int32_t result = SigNet::SIGNET_SUCCESS;

    int send_blob_count = is_root_ep ? SigNet::Node::GetSupportedRootBlobCount()
                                     : SigNet::Node::GetSupportedDataBlobCount();

    int i;
    for (i = 0; i < send_blob_count; ++i) {
        SigNet::TidDataBlob* blob = is_root_ep ? SigNet::Node::GetSupportedRootBlobByIndex(node_user_data, i)
                                               : SigNet::Node::GetSupportedDataBlobByIndex(node_user_data, i);
        if (!blob || !blob->manager_is_stale) {
            continue;
        }
        if (SigNet::Node::IsTidWriteOnly(blob->tid)) {
            continue;
        }
        if (!SigNet::Node::IsTidAllowedForEndpoint(blob->tid, is_root_ep, is_data_ep)) {
            continue;
        }
        result = AppendTLVRaw(payload, blob->tid, blob->data.bytes, blob->length);
        if (result != SigNet::SIGNET_SUCCESS) {
            LogError(String().sprintf(L"Stale response payload append failed for TID 0x%04X: %d", blob->tid, result));
            return false;
        }
    }

    if (payload.GetSize() == 0) {
        return true;
    }

    result = SigNet::CoAP::BuildCoAPHeader(packet, message_id);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Stale response CoAP header build failed: %d", result));
        return false;
    }

    result = SigNet::BuildNodeURIPathOptions(packet, tuid, reply_endpoint, uri_string, sizeof(uri_string));
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Stale response URI build failed: %d", result));
        return false;
    }

    SigNet::SigNetOptions options;
    result = SigNet::BuildCommonSigNetOptions(packet,
                                              tuid,
                                              reply_endpoint,
                                              0x0000,
                                              session_id,
                                              sequence_num,
                                              &options);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Stale response options build failed: %d", result));
        return false;
    }

    result = SigNet::FinalizePacketWithHMACAndPayload(packet,
                                                      uri_string,
                                                      options,
                                                      payload.GetBuffer(),
                                                      payload.GetSize(),
                                                      citizen_key);
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Stale response finalize failed: %d", result));
        return false;
    }

    if (packet.GetSize() > SigNet::MAX_UDP_PAYLOAD) {
        LogError(String().sprintf(L"Stale response dropped: packet size %u exceeds %u-byte limit",
                                  packet.GetSize(),
                                  SigNet::MAX_UDP_PAYLOAD));
        return false;
    }

    if (!SendRawPacket(packet.GetBuffer(), packet.GetSize(), SigNet::MULTICAST_NODE_SEND_IP, "StaleResponse")) {
        return false;
    }

    send_count++;
    last_packet_size = packet.GetSize();
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
    }

    LogMessage(String().sprintf(L"Stale-only reply sent (endpoint=%u, payload=%u bytes)",
                                reply_endpoint,
                                payload.GetSize()) +
               " reason=" + reason);
    return true;
}

void TFormSigNetNode::ProcessIncomingPacket(const uint8_t* packet, uint16_t packet_len, const sockaddr_in& source_addr)
{
    rx_packet_counter++;

    if (!ApplyScopeFromUI()) {
        rx_reject_counter++;
        return;
    }

    char src_ip[32];
    src_ip[0] = 0;
    strncpy(src_ip, inet_ntoa(source_addr.sin_addr), sizeof(src_ip) - 1);
    src_ip[sizeof(src_ip) - 1] = 0;

    if (!packet || packet_len < 4) {
        rx_reject_counter++;
        LogError("RX reject: packet too short");
        return;
    }

    SigNet::Parse::PacketReader header_reader(packet, packet_len);
    SigNet::CoAPHeader coap_header;
    if (SigNet::Parse::ParseCoAPHeader(header_reader, coap_header) != SigNet::SIGNET_SUCCESS) {
        rx_reject_counter++;
        LogError("RX reject: CoAP header parse failed");
        return;
    }

    if (coap_header.GetVersion() != SigNet::COAP_VERSION) {
        rx_reject_counter++;
        LogError(String().sprintf(L"RX reject: CoAP version %u != 1", coap_header.GetVersion()));
        return;
    }

    if (coap_header.GetTokenLength() > 8) {
        rx_reject_counter++;
        LogError(String().sprintf(L"RX reject: CoAP token length %u invalid", coap_header.GetTokenLength()));
        return;
    }

    if (coap_header.GetType() != SigNet::COAP_TYPE_NON) {
        rx_reject_counter++;
        LogError(String().sprintf(L"RX reject: CoAP type %u != NON", coap_header.GetType()));
        return;
    }

    if (coap_header.code != SigNet::COAP_CODE_POST) {
        rx_reject_counter++;
        LogError(String().sprintf(L"RX reject: CoAP code 0x%02X != POST", coap_header.code));
        return;
    }

    SigNet::SigNetOptions options;
    char uri[128];
    uri[0] = 0;
    const uint8_t* payload = 0;
    uint16_t payload_len = 0;
    if (!SigNet::Node::ExtractPayload(packet, packet_len, coap_header, options, uri, sizeof(uri), payload, payload_len)) {
        rx_reject_counter++;
        LogError("RX reject: parse failure extracting URI/options/payload");
        return;
    }

    uint16_t uri_endpoint = 0;
    if (SigNet::Node::TryParseTargetUriEndpoint(uri, uri_endpoint)) {
        uint16_t ui_endpoint = 1;
        if (uri_endpoint != 0 && uri_endpoint != ui_endpoint &&
            uri_endpoint != SigNet::BROADCAST_ENDPOINT) {
            rx_reject_counter++;
            LogMessage(String().sprintf(L"RX ignored: URI endpoint %u not local endpoint %u", uri_endpoint, ui_endpoint));
            return;
        }
    } else {
        uri_endpoint = 1;
    }

    bool is_data_ep_packet = (uri_endpoint != 0);
    if (!is_data_ep_packet) {
        LogMessage(String().sprintf(L"RX #%u from %S:%u (%u bytes)",
                                    rx_packet_counter,
                                    src_ip,
                                    ntohs(source_addr.sin_port),
                                    packet_len));
    }

    // Diagnostic: manager->node control traffic (polls, GET/SET) is otherwise not
    // logged when treated as a data-endpoint packet. Surface it before validation
    // so it is visible whether or not it passes HMAC/freshness.
    if (strstr(uri, "/poll") != 0 || strstr(uri, "/manager/") != 0) {
        LogMessage(String().sprintf(L"RX #%u ctrl from %S URI=%S (%u bytes)",
                                    rx_packet_counter,
                                    src_ip,
                                    uri,
                                    packet_len));
    }

    if (!keys_valid) {
        rx_reject_counter++;
        return;
    }

    if (strstr(uri, "/manager/") != 0) {
        const char* tuid_ptr = strstr(uri, "/manager/");
        if (tuid_ptr != 0) {
            tuid_ptr += 9;
            char uri_tuid[13];
            int i;
            for (i = 0; i < 12; ++i) {
                if (tuid_ptr[i] == 0 || tuid_ptr[i] == '/') {
                    break;
                }
                uri_tuid[i] = static_cast<char>(toupper(static_cast<unsigned char>(tuid_ptr[i])));
            }
            if (i != 12) {
                rx_reject_counter++;
                LogError("RX reject: malformed manager URI TUID segment.");
                return;
            }
            uri_tuid[12] = 0;

            char local_tuid[13];
            SigNet::Crypto::TUID_ToHexString(tuid, local_tuid);
            if (strcmp(uri_tuid, local_tuid) != 0) {
                rx_reject_counter++;
                LogMessage("RX ignored: /manager URI targeted to different TUID.");
                return;
            }
        }
    }

    if (options.security_mode == SigNet::SECURITY_MODE_UNPROVISIONED) {
        // Offboard beacon mode packets are not control inputs for onboarded nodes.
        return;
    }

    if (options.security_mode == SigNet::SECURITY_MODE_OPEN) {
        // Prevent downgrade in onboarded secure operation.
        rx_reject_counter++;
        return;
    }

    const uint8_t* validation_key = SigNet::Node::SelectValidationKey(uri,
                                                                       manager_global_key,
                                                                       manager_local_key,
                                                                       citizen_key,
                                                                       sender_key);
    if (!validation_key) {
        rx_reject_counter++;
        LogError("RX rejected: no validation key for URI.");
        return;
    }

    if (SigNet::Parse::VerifyPacketHMAC(uri, options, payload, payload_len, validation_key) != SigNet::SIGNET_SUCCESS) {
        rx_reject_counter++;
        RecordSecurityEvent(0x0001, static_cast<uint32_t>(source_addr.sin_addr.s_addr));  // HMAC Verification Failure
        SendSecurityEvent(0x0001);  // spec 11.8.1: unilateral multicast on HMAC failure
        LogError("RX rejected: HMAC verification failed.");
        return;
    }

    uint32_t now_ms = static_cast<uint32_t>(GetTickCount());
    if (!SigNet::Node::ValidateAndCommitFreshness(node_freshness_tracker, options, now_ms)) {
        rx_reject_counter++;
        RecordSecurityEvent(0x0002, static_cast<uint32_t>(source_addr.sin_addr.s_addr));  // Replay Attack Detected
        SendSecurityEvent(0x0002);  // spec 11.8.1: unilateral multicast on replay/freshness failure
        LogError("RX rejected: replay/freshness validation failed.");
        return;
    }

    rx_accept_counter++;
    if (!is_data_ep_packet) {
        LogMessage(String().sprintf(L"RX accepted (%u accepted / %u rejected)", rx_accept_counter, rx_reject_counter));
    }

    if (!payload || payload_len == 0) {
        return;
    }

    SigNet::Parse::PacketReader payload_reader(payload, payload_len);
    const int MAX_SET_TIDS_PER_PACKET = 32;
    bool poll_triggered = false;
    uint16_t set_tids[MAX_SET_TIDS_PER_PACKET];
    int set_tid_count = 0;
    bool set_any_persistent = false;
    bool set_transaction_invalid = false;
    uint16_t set_reply_endpoint = uri_endpoint;

    while (payload_reader.GetRemaining() >= 4) {
        SigNet::TLVBlock tlv;
        if (SigNet::Parse::ParseTLVBlock(payload_reader, tlv) != SigNet::SIGNET_SUCCESS) {
            break;
        }

        if (!SigNet::Node::IsTidAllowedForUriLane(uri, tlv.type_id)) {
            LogMessage(String().sprintf(L"RX ignored: TID 0x%04X not allowed on URI lane %S", tlv.type_id, uri));
            continue;
        }

        switch (tlv.type_id) {
            case SigNet::TID_LEVEL:
            {
                uint16_t uri_universe = 0;
                if (!SigNet::Node::ParseUniverseFromURI(uri, uri_universe)) {
                    break;
                }

                if (uri_universe != static_cast<uint16_t>(SpinUniverse->Value)) {
                    break;
                }

                uint8_t level_data[SigNet::MAX_DMX_SLOTS];
                uint16_t slot_count = 0;
                if (SigNet::Parse::ParseTID_LEVEL(tlv, level_data, slot_count) == SigNet::SIGNET_SUCCESS) {
                    StoreBlobFromBytes(node_user_data.ep1.tid_level,
                                       SigNet::TID_LEVEL,
                                       level_data,
                                       slot_count,
                                       SigNet::TID_BLOB_BYTES);
                    StoreBlobFromBytes(node_user_data.ep1.tid_dg_level_foldback,
                                       SigNet::TID_DG_LEVEL_FOLDBACK,
                                       level_data,
                                       slot_count,
                                       SigNet::TID_BLOB_BYTES);
                    node_user_data.ep1.tid_level.ui_is_stale = true;
                }
                break;
            }

            case SigNet::TID_POLL:
            {
                // Any authenticated poll proves the management network is alive.
                last_valid_poll_tick = static_cast<uint32_t>(GetTickCount());
                if (node_in_lost_mode) {
                    node_in_lost_mode = false;
                    LogMessage("Manager poll received; exiting Lost Mode.");
                }
                if (HandlePollTLV(tlv)) {
                    if (tlv.length == 25 && tlv.value) {
                        last_poll_query_level = tlv.value[24];
                    }
                    poll_triggered = true;
                }
                break;
            }

            default:
            {
                // Broadcast endpoint (0xFFFF): the spec directs the node to process
                // the enclosed TIDs against every applicable endpoint. On this
                // single-data-endpoint node, resolve each TID to its natural
                // endpoint (data TID -> EP1, otherwise root EP0) so the reply is
                // emitted on the correct Reply URI.
                uint16_t effective_ep = uri_endpoint;
                if (uri_endpoint == SigNet::BROADCAST_ENDPOINT) {
                    effective_ep = SigNet::Node::IsTidAllowedForIncomingEndpoint(tlv.type_id, 1) ? 1 : 0;
                }

                if (!SigNet::Node::IsTidAllowedForIncomingEndpoint(tlv.type_id, effective_ep)) {
                    LogMessage(String().sprintf(L"RX ignored: TID 0x%04X not valid for endpoint %u", tlv.type_id, effective_ep));
                    break;
                }

                if (tlv.length == 0) {
                    if (!SigNet::Node::IsTidGetSupported(tlv.type_id)) {
                        LogMessage(String().sprintf(L"RX ignored: GET not supported for TID 0x%04X", tlv.type_id));
                        break;
                    }
                    // HandleGetRequest sends its own targeted Get-Response on the
                    // Reply URI, so no generic proactive poll-reply is needed here.
                    HandleGetRequest(tlv.type_id, effective_ep);
                } else {
                    int set_result = HandleSetRequest(tlv.type_id, tlv.value, tlv.length, true);
                    if (set_result == SET_RESULT_REJECTED) {
                        set_transaction_invalid = true;
                    } else {
                        if (set_tid_count < MAX_SET_TIDS_PER_PACKET) {
                            set_tids[set_tid_count++] = tlv.type_id;
                        }
                        set_reply_endpoint = effective_ep;
                        if (set_result == SET_RESULT_CHANGED && SigNet::Node::IsTidPersistent(tlv.type_id)) {
                            set_any_persistent = true;
                        }
                    }
                }
                break;
            }
        }
    }

    if (poll_triggered) {
        SendProactiveResponse("manager poll trigger");
    }

    // Spec 10.4.x: an invalid SET voids the entire transaction — the Node emits no
    // confirmation reply and leaves CHANGE_COUNT unchanged. Otherwise, increment
    // CHANGE_COUNT once for the transaction if any persistent parameter changed
    // (spec 10.4.4) and send the trailing TID_SET_REPLY confirmation.
    if (set_tid_count > 0 && !set_transaction_invalid) {
        if (set_any_persistent) {
            node_config.change_count++;
        }
        SendSetReply(set_tids, set_tid_count, set_reply_endpoint);
    }
}
//---------------------------------------------------------------------------

void TFormSigNetNode::UpdateStatusDisplay()
{
    // Placeholder - will be populated in Phase 2
}
//---------------------------------------------------------------------------

// SyncUIFromStaleBlobs
//
// Called from the receive timer.  For every blob where ui_is_stale is true
// (meaning the Manager / Sig-Net sent a SET that changed this value), update
// the corresponding UI control and clear the flag.
//
// UpdateLevelMimic
//
// Mirrors the current received TID_LEVEL data onto the three read-only channel
// trackbars (EP1 slots 1-3). A slot with no received data reads as 0.
//
void TFormSigNetNode::UpdateLevelMimic()
{
    const SigNet::TidDataBlob& blob = node_user_data.ep1.tid_level;
    TTrackBar* bars[3] = { TrackLevelCh1, TrackLevelCh2, TrackLevelCh3 };
    TLabel* vals[3] = { LabelLevelCh1Val, LabelLevelCh2Val, LabelLevelCh3Val };

    int i;
    for (i = 0; i < 3; ++i) {
        int level = (blob.length > (uint16_t)i) ? blob.data.bytes[i] : 0;
        bars[i]->Position = level;
        vals[i]->Caption = IntToStr(level);
    }
}
//---------------------------------------------------------------------------

void TFormSigNetNode::SyncUIFromStaleBlobs()
{
    suppress_ui_change_events = true;

    if (node_user_data.root.tid_rt_device_label.ui_is_stale) {
        // Wire format is [0] encoding byte + [1..] text; display from byte 1.
        const SigNet::TidDataBlob& lbl_blob = node_user_data.root.tid_rt_device_label;
        const char* lbl_text = (lbl_blob.length > 1) ? (const char*)&lbl_blob.data.bytes[1] : "";
        EditRootDeviceLabel->Text = String(lbl_text);
        node_user_data.root.tid_rt_device_label.ui_is_stale = false;
    }

    if (node_user_data.root.tid_rt_identify.ui_is_stale) {
        node_user_data.root.tid_rt_identify.ui_is_stale = false;
    }

    if (node_user_data.root.tid_rt_scope.ui_is_stale) {
        node_user_data.root.tid_rt_scope.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_universe.ui_is_stale) {
        if (node_user_data.ep1.tid_ep_universe.length >= 2) {
            uint16_t universe = ((uint16_t)node_user_data.ep1.tid_ep_universe.data.bytes[0] << 8) |
                                  node_user_data.ep1.tid_ep_universe.data.bytes[1];
            if (universe >= SigNet::MIN_UNIVERSE && universe <= SigNet::MAX_UNIVERSE) {
                SpinUniverse->Value = universe;
                RefreshReceiverGroups();
            }
        }
        node_user_data.ep1.tid_ep_universe.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_label.ui_is_stale) {
        node_user_data.ep1.tid_ep_label.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_direction.ui_is_stale) {
        node_user_data.ep1.tid_ep_direction.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_failover.ui_is_stale) {
        node_user_data.ep1.tid_ep_failover.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_rdm_port_config.ui_is_stale) {
        node_user_data.ep1.tid_rdm_port_config.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_protocol.ui_is_stale) {
        node_user_data.ep1.tid_ep_protocol.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_level.ui_is_stale) {
        UpdateLevelMimic();
        node_user_data.ep1.tid_level.ui_is_stale = false;
    }

    suppress_ui_change_events = false;
}
//---------------------------------------------------------------------------

// SendStaleTIDsToManager
//
// Called from the receive timer.  If any blob has manager_is_stale == true
// (meaning the UI changed a value that the Manager does not yet know about),
// send a proactive poll reply at QUERY_CONFIG level and clear all stale flags.
//
void TFormSigNetNode::SendStaleTIDsToManager()
{
    if (!keys_valid) {
        return;
    }

    int i;
    int root_blob_count = SigNet::Node::GetSupportedRootBlobCount();
    int ep1_blob_count = SigNet::Node::GetSupportedDataBlobCount();

    bool root_stale = false;
    bool data_stale = false;

    for (i = 0; i < root_blob_count; ++i) {
        const SigNet::TidDataBlob* blob = SigNet::Node::GetSupportedRootBlobByIndex(node_user_data, i);
        root_stale = root_stale || (blob && blob->manager_is_stale);
    }
    for (i = 0; i < ep1_blob_count; ++i) {
        const SigNet::TidDataBlob* blob = SigNet::Node::GetSupportedDataBlobByIndex(node_user_data, i);
        data_stale = data_stale || (blob && blob->manager_is_stale);
    }

    bool all_sent = true;

    if (root_stale) {
        if (!SendStaleResponseForEndpoint(0, "manager_is_stale timer flush [EP0]")) {
            all_sent = false;
        }
    }

    if (data_stale) {
        uint16_t ui_endpoint = 1;
        if (!SendStaleResponseForEndpoint(ui_endpoint, "manager_is_stale timer flush [Data EP]")) {
            all_sent = false;
        }
    }

    if ((root_stale || data_stale) && all_sent) {
        SigNet::Node::ClearAllManagerStaleFlags(node_user_data);
        LogMessage("Stale flush sent; manager_is_stale flags cleared.");
    }
}
//---------------------------------------------------------------------------

void TFormSigNetNode::LogMessage(const String& msg)
{
    String timestamp = FormatDateTime("hh:nn:ss", Now());
    MemoStatus->Lines->BeginUpdate();
    MemoStatus->Lines->Add("[" + timestamp + "] " + msg);

    while (MemoStatus->Lines->Count > 100) {
        MemoStatus->Lines->Delete(0);
    }
    MemoStatus->Lines->EndUpdate();

    MemoStatus->SelStart = MemoStatus->GetTextLen();
    MemoStatus->SelLength = 0;
    MemoStatus->Perform(EM_SCROLLCARET, 0, 0);
    MemoStatus->Perform(WM_VSCROLL, SB_BOTTOM, 0);
}
//---------------------------------------------------------------------------

void TFormSigNetNode::LogError(const String& msg)
{
    LogMessage("ERROR: " + msg);
}
//---------------------------------------------------------------------------

bool TFormSigNetNode::ApplyScopeFromUI()
{
    int32_t rc = SigNet::CoAP::SetURIScope(SigNet::Node::FIXED_SCOPE);
    if (rc != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Invalid scope value (error %d)", rc));
        return false;
    }

    return true;
}
//---------------------------------------------------------------------------

void TFormSigNetNode::WarnIfLoopbackSelected()
{
    char nic_ip[16];
    nic_ip[0] = '\0';
    SigNet::ExtractIPv4Token(selected_nic_ip.c_str(), nic_ip, sizeof(nic_ip));
    if (nic_ip[0] == '\0') {
        strncpy(nic_ip, selected_nic_ip.c_str(), sizeof(nic_ip) - 1);
        nic_ip[sizeof(nic_ip) - 1] = '\0';
    }

    if (strncmp(nic_ip, "127.", 4) == 0) {
        LogMessage("multicast not available in loopback mode");
    }
}
//---------------------------------------------------------------------------

bool TFormSigNetNode::ParseK0FromHex(const String& hex_string)
{
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseK0Hex(token.c_str(), k0_key) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

bool TFormSigNetNode::ParseTUIDFromHex(const String& hex_string)
{
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseTUIDHex(token.c_str(), tuid) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

bool TFormSigNetNode::ParseHexTUIDField(const String& hex_string, uint8_t out_tuid[6])
{
    if (!out_tuid) {
        return false;
    }
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseTUIDHex(token.c_str(), out_tuid) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

void TFormSigNetNode::UpdateK0DependentControls()
{
    ButtonDeprovision->Enabled = true;

}
//---------------------------------------------------------------------------

