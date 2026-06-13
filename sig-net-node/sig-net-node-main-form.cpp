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
// Description:  Node application main form. Phase 1: UI construction only.
//               Sig-Net Node protocol (TID_POLL_REPLY, RX processing, key
//               management state machine) is deferred to Phase 2.
//==============================================================================

//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "sig-net-node-main-form.h"
#include "..\sig-net-crypto.hpp"
#include "sig-net-parse.hpp"
#include "..\sig-net-node-data.hpp"
#include <Vcl.Themes.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TFormSigNetNode *FormSigNetNode;

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 5
#define APP_VERSION_ID ((APP_VERSION_MAJOR << 8) | APP_VERSION_MINOR)

static void SecureZeroBuffer(void* ptr, size_t len)
{
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len > 0) {
        *p++ = 0;
        --len;
    }
}

static void SetLabelsTransparentRecursive(TWinControl* root)
{
    if (!root) {
        return;
    }
    int i;
    for (i = 0; i < root->ControlCount; i++) {
        TControl* ctrl = root->Controls[i];
        TLabel* lbl = dynamic_cast<TLabel*>(ctrl);
        if (lbl) {
            lbl->Transparent = true;
        }

        TWinControl* child = dynamic_cast<TWinControl*>(ctrl);
        if (child) {
            SetLabelsTransparentRecursive(child);
        }
    }
}

static bool TryParseNodeUriEndpoint(const char* uri, uint16_t& endpoint_out)
{
    endpoint_out = 0;
    if (!uri) {
        return false;
    }

    const char* node_ptr = strstr(uri, "/node/");
    if (!node_ptr) {
        return false;
    }

    const char* endpoint_ptr = strrchr(uri, '/');
    if (!endpoint_ptr || *(endpoint_ptr + 1) == 0) {
        return false;
    }

    endpoint_ptr++;
    uint32_t parsed = 0;
    while (*endpoint_ptr != 0) {
        if (*endpoint_ptr < '0' || *endpoint_ptr > '9') {
            return false;
        }
        parsed = (parsed * 10) + static_cast<uint32_t>(*endpoint_ptr - '0');
        if (parsed > 65535U) {
            return false;
        }
        endpoint_ptr++;
    }

    endpoint_out = static_cast<uint16_t>(parsed);
    return true;
}

static bool IsTidAllowedForIncomingEndpoint(uint16_t tid, uint16_t endpoint)
{
    bool is_root_ep = (endpoint == 0);
    bool is_data_ep = !is_root_ep;
    return SigNet::Node::IsTidAllowedForEndpoint(tid, is_root_ep, is_data_ep);
}

static bool ExtractValidIPv4FromText(const AnsiString& source, char* out_ip, size_t out_len)
{
    if (!out_ip || out_len < 8) {
        return false;
    }

    out_ip[0] = 0;
    AnsiString trimmed = source.Trim();
    if (trimmed.IsEmpty()) {
        return false;
    }

    SigNet::ExtractIPv4Token(trimmed.c_str(), out_ip, out_len);
    if (out_ip[0] == 0) {
        strncpy(out_ip, trimmed.c_str(), out_len - 1);
        out_ip[out_len - 1] = 0;
        char* space = strchr(out_ip, ' ');
        if (space) {
            *space = 0;
        }
    }

    if (out_ip[0] == 0) {
        return false;
    }

    u_long addr = inet_addr(out_ip);
    if (addr == INADDR_NONE && strcmp(out_ip, "255.255.255.255") != 0) {
        out_ip[0] = 0;
        return false;
    }

    return true;
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
    level_preview_frame_valid = false;
    level_preview_bitmap = 0;

    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));
    memset(manager_global_key, 0, sizeof(manager_global_key));
    memset(tuid, 0, sizeof(tuid));
    memset(level_preview_frame, 0, sizeof(level_preview_frame));
}

bool TFormSigNetNode::EnsureSocketInitialized()
{
    return SigNet::Node::EnsureSocketInitialized(udp_socket,
                                                 winsock_started,
                                                 socket_initialized,
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
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::FormCreate(TObject *Sender)
{
    Caption = String().sprintf(L"Sig-Net [Node]   Copyright Singularity (UK) Ltd  V%d.%d",
                               APP_VERSION_MAJOR,
                               APP_VERSION_MINOR);

    srand(static_cast<unsigned int>(GetTickCount()));

    // NIC selection with preferred physical NIC.
    selected_nic_ip = SigNet::SelectDefaultStartupNicIP();
    if (selected_nic_ip.IsEmpty()) {
        selected_nic_ip = "127.0.0.1";
    }
    EditNicIP->Text = String(selected_nic_ip.c_str());
    EditNicIP->ReadOnly = true;

    EditScope->Text = String(SigNet::CoAP::GetURIScope());
    ApplyScopeFromUI();

    EditRootDeviceLabel->MaxLength = 64;
    EditRootModelName->MaxLength = 64;
    EditEP1Label->MaxLength = 64;

    // Announce / on-boot packet fields
    EditAnnounceVersionNum->Text = IntToStr(APP_VERSION_ID);
    EditAnnounceVersionString->Text = "v0.15-test";
    EditAnnounceMfgCode->Text = String().sprintf(L"0x%04x", (unsigned int)((SigNet::SoemCodeSdkNode >> 16) & 0xFFFF));
    EditAnnounceProductVariant->Text = String().sprintf(L"0x%04x", (unsigned int)(SigNet::SoemCodeSdkNode & 0xFFFF));

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
    SpinEndpoint->MinValue = 1;
    SpinEndpoint->Value = 1;
    SpinUniverse->MinValue = SigNet::MIN_UNIVERSE;
    SpinUniverse->MaxValue = SigNet::MAX_UNIVERSE;
    SpinUniverse->Value = 1;

    EditSessionID->Text = "1";
    EditSessionID->ReadOnly = true;
    EditSequence->Text = "1";
    EditSequence->ReadOnly = true;
    EditMessageID->Text = "1";
    EditMessageID->ReadOnly = true;

    PageControlNode->ActivePage = TabSheetRoot;

    // ---------------------------------------------------------------------------
    // Tab 1: Root EP (Mandated) defaults
    // ---------------------------------------------------------------------------
    EditRootDeviceLabel->Text = "Sig-Net Test Node";
    EditRootDeviceLabel->OnExit = EditRootDeviceLabelExit;
    EditRootDeviceLabel->OnKeyPress = EditRootDeviceLabelKeyPress;
    ButtonSetDeviceLabel->Visible = false;
    ButtonSetDeviceLabel->Enabled = false;
    EditRootSoemCode->Text = String().sprintf(L"0x%08x", (unsigned int)SigNet::SoemCodeSdkNode);
    EditRootSoemCode->ReadOnly = true;
    EditRootProtVersion->Text = "1";
    EditRootProtVersion->ReadOnly = true;
    EditRootFirmwareID->Text = IntToStr(APP_VERSION_ID);
    EditRootFirmwareID->ReadOnly = true;
	EditRootFirmwareStr->Text = "v0.16 Spec";
	EditRootFirmwareStr->ReadOnly = true;
	EditAnnounceVersionString->Text=EditRootFirmwareStr->Text;
    EditRootModelName->Text = "Fogmaster 5000";
    EditRootModelName->OnExit = GenericEditExit;
    EditRootModelName->OnKeyPress = GenericEditKeyPress;

    // Identify combo: Off / Subtle / Full / Dark-sky Mute
    ComboRootIdentify->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::IDENTIFY_STATE_COUNT; ++i) {
            ComboRootIdentify->Items->Add(SigNet::Node::GetIdentifyStateLabel(static_cast<SigNet::IdentifyState>(i)));
        }
    }
    ComboRootIdentify->ItemIndex = 0;
    ComboRootIdentify->OnChange = GenericComboChange;

    // Root Status - 3 checkboxes for hardware fault, factory boot, config lock
    CBStatusHwFault->Checked = false;
    CBStatusHwFault->OnClick = GenericCheckBoxClick;
    CBStatusFactoryBoot->Checked = false;
    CBStatusFactoryBoot->OnClick = GenericCheckBoxClick;
    CBStatusConfigLock->Checked = false;
    CBStatusConfigLock->OnClick = GenericCheckBoxClick;

    EditRootEndpCount->OnExit = GenericEditExit;
    EditRootEndpCount->OnKeyPress = GenericEditKeyPress;

    // Role capability checkboxes - this device is a Node
    CBRoleNode->Checked = true;
    CBRoleSender->Checked = false;
    CBRoleManager->Checked = false;
    CBRoleNode->OnClick = GenericCheckBoxClick;
    CBRoleSender->OnClick = GenericCheckBoxClick;
    CBRoleManager->OnClick = GenericCheckBoxClick;

    EditRootMultState->Text = "0x00 - Default";
    EditRootMultState->ReadOnly = true;
    CheckListRootSupportedTids->Items->Clear();
    {
        const SigNet::Node::SupportedTidEntry* tid_table = SigNet::Node::GetSupportedTidTable();
        int i;
        for (i = 0; i < SigNet::Node::SUPPORTED_TID_COUNT; ++i) {
            CheckListRootSupportedTids->Items->Add(tid_table[i].label);
        }
        for (i = 0; i < SigNet::Node::SUPPORTED_TID_COUNT; ++i) {
            CheckListRootSupportedTids->Checked[i] = tid_table[i].mandated;
        }
    }
    CheckListRootSupportedTids->OnClickCheck = SupportedTidsClickCheck;

    // Supported TIDs filter buttons
    ButtonSupportedTidsNone->OnClick = ButtonSupportedTidsNoneClick;
    ButtonSupportedTidsMandated->OnClick = ButtonSupportedTidsMandatedClick;
    ButtonSupportedTidsAll->OnClick = ButtonSupportedTidsAllClick;

    // ---------------------------------------------------------------------------
    // Tab 2: Root EP (Optional) defaults
    // ---------------------------------------------------------------------------
    EditRootMac->Text = "00:00:00:00:00:00";
    EditRootMac->ReadOnly = true;
    ComboRootIpv4Mode->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::IPV4_MODE_COUNT; ++i) {
            ComboRootIpv4Mode->Items->Add(SigNet::Node::GetIpv4ModeLabel(static_cast<SigNet::Ipv4Mode>(i)));
        }
    }
    ComboRootIpv4Mode->ItemIndex = 0;
    ComboRootIpv4Mode->OnChange = GenericComboChange;
    EditRootIpv4Addr->Text = "192.168.1.100";
    EditRootIpv4Addr->OnExit = EditRootIpv4AddrExit;
    EditRootIpv4Addr->OnKeyPress = EditRootIpv4AddrKeyPress;
    EditRootIpv4Mask->Text = "255.255.255.0";
    EditRootIpv4Mask->OnExit = GenericEditExit;
    EditRootIpv4Mask->OnKeyPress = GenericEditKeyPress;
    EditRootIpv4Gateway->Text = "192.168.1.1";
    EditRootIpv4Gateway->OnExit = GenericEditExit;
    EditRootIpv4Gateway->OnKeyPress = GenericEditKeyPress;
    EditRootIpv4Current->Text = "192.168.1.100/255.255.255.0 gw 192.168.1.1";
    EditRootIpv4Current->ReadOnly = true;

    ComboRootIpv6Mode->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::IPV6_MODE_COUNT; ++i) {
            ComboRootIpv6Mode->Items->Add(SigNet::Node::GetIpv6ModeLabel(static_cast<SigNet::Ipv6Mode>(i)));
        }
    }
    ComboRootIpv6Mode->ItemIndex = 1;  // SLAAC default
    ComboRootIpv6Mode->OnChange = GenericComboChange;
    EditRootIpv6Addr->Text = "fe80::100";
    SpinRootIpv6Prefix->MinValue = 0;
    SpinRootIpv6Prefix->MaxValue = 128;
    SpinRootIpv6Prefix->Value = 64;
    SpinRootIpv6Prefix->OnChange = GenericSpinChange;
    EditRootIpv6Gateway->Text = "fe80::1";
    EditRootIpv6Current->Text = "fe80::100/64 gw fe80::1";
    EditRootIpv6Current->ReadOnly = true;

    // ---------------------------------------------------------------------------
    // Tab 3: EP1 (Virtual) defaults
    // ---------------------------------------------------------------------------
    SpinEP1Universe->MinValue = SigNet::MIN_UNIVERSE;
    SpinEP1Universe->MaxValue = SigNet::MAX_UNIVERSE;
    SpinEP1Universe->Value = 1;
    SpinEP1Universe->OnChange = GenericSpinChange;

    EditEP1Label->Text = "EP1 Virtual";
    EditEP1Label->OnExit = EditEP1LabelExit;
    EditEP1Label->OnKeyPress = EditEP1LabelKeyPress;

    // Direction combo: Disabled / Consumer / Supplier
    ComboEP1Direction->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::EP_DIRECTION_COUNT; ++i) {
            ComboEP1Direction->Items->Add(SigNet::Node::GetEpDirectionLabel(static_cast<SigNet::EpDirection>(i)));
        }
    }
    ComboEP1Direction->ItemIndex = 1;  // Consumer by default
    ComboEP1Direction->OnChange = GenericComboChange;

    CBEp1RdmEnable->Checked = true;
    CBEp1RdmEnable->OnClick = GenericCheckBoxClick;

    // Capability - Virtual endpoint: consume level + consume RDM + virtual flag
    CBCapConsumeLevel->Checked = true;
    CBCapSupplyLevel->Checked = false;
    CBCapConsumeRDM->Checked = true;
    CBCapSupplyRDM->Checked = false;
    CBCapVirtual->Checked = true;
    CBCapConsumeLevel->OnClick = GenericCheckBoxClick;
    CBCapSupplyLevel->OnClick = GenericCheckBoxClick;
    CBCapConsumeRDM->OnClick = GenericCheckBoxClick;
    CBCapSupplyRDM->OnClick = GenericCheckBoxClick;
    CBCapVirtual->OnClick = GenericCheckBoxClick;

    EditEP1Status->Text = "0x00000000";
    EditEP1Status->ReadOnly = true;

    // Failover combo: Hold / Blackout / Full / Scene
    ComboEP1Failover->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::FAILOVER_MODE_COUNT; ++i) {
            ComboEP1Failover->Items->Add(SigNet::Node::GetFailoverModeLabel(static_cast<SigNet::FailoverMode>(i)));
        }
    }
    ComboEP1Failover->ItemIndex = 0;

    SpinEP1FailoverScene->MinValue = 1;
    SpinEP1FailoverScene->MaxValue = 60000;
    SpinEP1FailoverScene->Value = 1;
    SpinEP1FailoverScene->OnChange = GenericSpinChange;

    EditEP1MultOverride->Text = "0.0.0.0";
    EditEP1MultOverride->OnExit = GenericEditExit;
    EditEP1MultOverride->OnKeyPress = GenericEditKeyPress;

    EditEP1RefreshCap->Text = "44";
    EditEP1RefreshCap->ReadOnly = true;

    // DMX Timing - transmission mode
    ComboEP1DmxTransMode->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::DMX_TRANSMIT_MODE_COUNT; ++i) {
            ComboEP1DmxTransMode->Items->Add(SigNet::Node::GetDmxTransmitModeLabel(static_cast<SigNet::DmxTransmitMode>(i)));
        }
    }
    ComboEP1DmxTransMode->ItemIndex = 0;
    ComboEP1DmxTransMode->OnChange = GenericComboChange;

    // DMX Timing - output timing
    ComboEP1DmxOutputTiming->Clear();
    {
        int i;
        for (i = 0; i < SigNet::Node::DMX_OUTPUT_TIMING_COUNT; ++i) {
            ComboEP1DmxOutputTiming->Items->Add(SigNet::Node::GetDmxOutputTimingLabel(static_cast<SigNet::DmxOutputTiming>(i)));
        }
    }
    ComboEP1DmxOutputTiming->ItemIndex = 0;
    ComboEP1DmxOutputTiming->OnChange = GenericComboChange;

    // RDM Virtual Responder PIDs
    EditRdmDevLabel->Text = "Sig-Net Virtual Node";
    SpinRdmStartAddr->MinValue = 1;
    SpinRdmStartAddr->MaxValue = 512;
    SpinRdmStartAddr->Value = 1;
    SpinRdmPersonality->MinValue = 1;
    SpinRdmPersonality->MaxValue = 255;
    SpinRdmPersonality->Value = 1;

    // DMX level display - initialise renderer with all-zero frame
    memset(level_preview_frame, 0, sizeof(level_preview_frame));
    level_preview_frame_valid = true;
    level_preview_bitmap = 0;
    PaintBoxEP1Levels->OnPaint = PaintBoxEP1LevelsPaint;
    PaintBoxEP1Levels->Repaint();

    // ---------------------------------------------------------------------------
    UpdateFailoverSceneVisibility();
    SetLabelsTransparentRecursive(this);
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

    if (level_preview_bitmap) {
        delete level_preview_bitmap;
        level_preview_bitmap = 0;
    }
    SecureZeroBuffer(level_preview_frame, sizeof(level_preview_frame));
    level_preview_frame_valid = false;

    SecureZeroBuffer(k0_key, sizeof(k0_key));
    SecureZeroBuffer(sender_key, sizeof(sender_key));
    SecureZeroBuffer(citizen_key, sizeof(citizen_key));
    SecureZeroBuffer(manager_global_key, sizeof(manager_global_key));
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

            keys_valid = true;
            k0_set = true;
            UpdateK0DependentControls();
            LogMessage("K0 selected. Ks, Kc and Km_global derived successfully.");
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

void __fastcall TFormSigNetNode::ButtonSendAnnounceClick(TObject *Sender)
{
    if (SendAnnouncePacket()) {
        LogMessage(String().sprintf(L"On-Boot Announce sent: seq=%u, size=%u bytes",
                   sequence_num - 1, last_packet_size));
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

void __fastcall TFormSigNetNode::ButtonSelectNicClick(TObject *Sender)
{
    TNicSelectDialog* dlg = new TNicSelectDialog(Application);
    dlg->SetCurrentIP(selected_nic_ip);
    try {
        if (dlg->ShowModal() == mrOk) {
            selected_nic_ip = dlg->GetSelectedIP();
            EditNicIP->Text = String(selected_nic_ip.c_str());
            LogMessage("Node interface set to: " + String(selected_nic_ip.c_str()));

            SigNet::Node::LeaveAllReceiverGroups(udp_socket,
                                                 socket_initialized,
                                                 udp_groups,
                                                 TFormSigNetNode::UdpLogThunk,
                                                 this);
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
    bool changed = false;
    if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_device_label,
                                                      SigNet::TID_RT_DEVICE_LABEL,
                                                      (const uint8_t*)ansi_lbl.c_str(),
                                                      (uint16_t)ansi_lbl.Length(),
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

void TFormSigNetNode::CommitEP1LabelFromUI(const String& trigger_source)
{
    if (suppress_ui_change_events) {
        return;
    }

    String lbl = EditEP1Label->Text.Trim();
    if (lbl.IsEmpty()) {
        return;
    }

    AnsiString ansi_lbl = AnsiString(lbl);
    bool changed = false;
    if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_label,
                                                      SigNet::TID_EP_LABEL,
                                                      (const uint8_t*)ansi_lbl.c_str(),
                                                      (uint16_t)ansi_lbl.Length(),
                                                      SigNet::TID_BLOB_TEXT,
                                                      changed) && changed) {
        MarkBlobStale(node_user_data.ep1.tid_ep_label);
        LogMessage("EP1 label committed (" + trigger_source + ") and marked stale.");
        if (!keys_valid) {
            LogMessage("K0/keys not set yet; proactive TX is deferred.");
        }
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditEP1LabelExit(TObject *Sender)
{
    CommitEP1LabelFromUI("focus-exit");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditEP1LabelKeyPress(TObject *Sender, wchar_t &Key)
{
    if (Key == L'\r') {
        CommitEP1LabelFromUI("enter");
        Key = 0;
    }
}
//---------------------------------------------------------------------------

void TFormSigNetNode::CommitRootIpv4AddrFromUI(const String& trigger_source)
{
    if (suppress_ui_change_events) {
        return;
    }

    AnsiString addr_str = AnsiString(EditRootIpv4Addr->Text.Trim());
    if (addr_str.IsEmpty()) {
        return;
    }

    u_long addr = inet_addr(addr_str.c_str());
    if (addr == INADDR_NONE && strcmp(addr_str.c_str(), "255.255.255.255") != 0) {
        LogError("Invalid IPv4 address format; stale update skipped.");
        return;
    }

    bool changed = false;
    if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv4_address,
                                                      SigNet::TID_NW_IPV4_ADDRESS,
                                                      (const uint8_t*)&addr,
                                                      4,
                                                      SigNet::TID_BLOB_BYTES,
                                                      changed) && changed) {
        MarkBlobStale(node_user_data.root.tid_nw_ipv4_address);
        LogMessage("Root IPv4 address committed (" + trigger_source + ") and marked stale.");
        if (!keys_valid) {
            LogMessage("K0/keys not set yet; proactive TX is deferred.");
        }
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditRootIpv4AddrExit(TObject *Sender)
{
    CommitRootIpv4AddrFromUI("focus-exit");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditRootIpv4AddrKeyPress(TObject *Sender, wchar_t &Key)
{
    if (Key == L'\r') {
        CommitRootIpv4AddrFromUI("enter");
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

    if (sender == EditRootModelName) {
        AnsiString model_name = AnsiString(EditRootModelName->Text.Trim());
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_model_name,
                                                          SigNet::TID_RT_MODEL_NAME,
                                                          (const uint8_t*)model_name.c_str(),
                                                          (uint16_t)model_name.Length(),
                                                          SigNet::TID_BLOB_TEXT,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_rt_model_name);
            LogMessage("Root model name committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == CBStatusHwFault || sender == CBStatusFactoryBoot || sender == CBStatusConfigLock) {
        uint32_t status_val = 0;
        if (CBStatusHwFault->Checked)     { status_val |= SigNet::RT_STATUS_HW_FAULT; }
        if (CBStatusFactoryBoot->Checked) { status_val |= SigNet::RT_STATUS_FACTORY_BOOT; }
        if (CBStatusConfigLock->Checked)  { status_val |= SigNet::RT_STATUS_CONFIG_LOCK; }
        uint8_t rt_status[4] = {(uint8_t)(status_val >> 24), (uint8_t)(status_val >> 16),
                                 (uint8_t)(status_val >> 8),  (uint8_t)(status_val & 0xFF)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_status,
                                                          SigNet::TID_RT_STATUS,
                                                          rt_status, 4,
                                                          SigNet::TID_BLOB_U32,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_rt_status);
            LogMessage("Root RT_STATUS committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == EditRootEndpCount) {
        int ep_count_val = StrToIntDef(EditRootEndpCount->Text.Trim(), 1);
        uint8_t ep_count[2] = {(uint8_t)(ep_count_val >> 8), (uint8_t)(ep_count_val & 0xFF)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_endpoint_count,
                                                          SigNet::TID_RT_ENDPOINT_COUNT,
                                                          ep_count, 2,
                                                          SigNet::TID_BLOB_U16,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_rt_endpoint_count);
            LogMessage("Root endpoint count committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == EditRootIpv4Mask || sender == EditRootIpv4Gateway) {
        AnsiString mask_str = AnsiString(EditRootIpv4Mask->Text.Trim());
        AnsiString gw_str = AnsiString(EditRootIpv4Gateway->Text.Trim());
        AnsiString addr_str = AnsiString(EditRootIpv4Addr->Text.Trim());

        u_long addr = inet_addr(addr_str.c_str());
        if (addr == INADDR_NONE && strcmp(addr_str.c_str(), "255.255.255.255") != 0) {
            LogError("Invalid IPv4 address format; stale update skipped.");
            return;
        }

        u_long mask = inet_addr(mask_str.c_str());
        if (mask == INADDR_NONE && strcmp(mask_str.c_str(), "255.255.255.255") != 0) {
            LogError("Invalid IPv4 netmask format; stale update skipped.");
            return;
        }

        u_long gw = inet_addr(gw_str.c_str());
        if (gw == INADDR_NONE && strcmp(gw_str.c_str(), "255.255.255.255") != 0) {
            LogError("Invalid IPv4 gateway format; stale update skipped.");
            return;
        }

        bool changed_mask = false;
        bool changed_gw = false;
        bool changed_current = false;

        SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv4_netmask,
                                                      SigNet::TID_NW_IPV4_NETMASK,
                                                      (const uint8_t*)&mask,
                                                      4,
                                                      SigNet::TID_BLOB_BYTES,
                                                      changed_mask);
        SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv4_gateway,
                                                      SigNet::TID_NW_IPV4_GATEWAY,
                                                      (const uint8_t*)&gw,
                                                      4,
                                                      SigNet::TID_BLOB_BYTES,
                                                      changed_gw);

        uint8_t current[12];
        memcpy(current, &addr, 4);
        memcpy(current + 4, &mask, 4);
        memcpy(current + 8, &gw, 4);
        SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv4_current,
                                                      SigNet::TID_NW_IPV4_CURRENT,
                                                      current,
                                                      12,
                                                      SigNet::TID_BLOB_BYTES,
                                                      changed_current);

        if (changed_mask) {
            MarkBlobStale(node_user_data.root.tid_nw_ipv4_netmask);
        }
        if (changed_gw) {
            MarkBlobStale(node_user_data.root.tid_nw_ipv4_gateway);
        }
        if (changed_current) {
            MarkBlobStale(node_user_data.root.tid_nw_ipv4_current);
        }

        if (changed_mask || changed_gw || changed_current) {
            LogMessage("Root IPv4 routing committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == EditEP1MultOverride) {
        AnsiString mult_ip_str = AnsiString(EditEP1MultOverride->Text.Trim());
        u_long mult_addr = inet_addr(mult_ip_str.c_str());
        if (mult_addr == INADDR_NONE && strcmp(mult_ip_str.c_str(), "255.255.255.255") != 0) {
            LogError("Invalid EP1 multicast override IPv4 format; stale update skipped.");
            return;
        }

        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_mult_override,
                                                          SigNet::TID_EP_MULT_OVERRIDE,
                                                          (const uint8_t*)&mult_addr,
                                                          4,
                                                          SigNet::TID_BLOB_BYTES,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.ep1.tid_ep_mult_override);
            LogMessage("EP1 multicast override committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == ComboRootIdentify) {
        uint8_t identify[1] = {(uint8_t)(ComboRootIdentify->ItemIndex & 0x03)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_identify,
                                                          SigNet::TID_RT_IDENTIFY,
                                                          identify,
                                                          1,
                                                          SigNet::TID_BLOB_U8,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_rt_identify);
            LogMessage("Root identify committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == ComboRootIpv4Mode) {
        uint8_t ipv4_mode[1] = {(uint8_t)(ComboRootIpv4Mode->ItemIndex & 0x01)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv4_mode,
                                                          SigNet::TID_NW_IPV4_MODE,
                                                          ipv4_mode,
                                                          1,
                                                          SigNet::TID_BLOB_U8,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_nw_ipv4_mode);
            LogMessage("Root IPv4 mode committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == ComboRootIpv6Mode) {
        uint8_t ipv6_mode[1] = {(uint8_t)(ComboRootIpv6Mode->ItemIndex & 0x03)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv6_mode,
                                                          SigNet::TID_NW_IPV6_MODE,
                                                          ipv6_mode,
                                                          1,
                                                          SigNet::TID_BLOB_U8,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_nw_ipv6_mode);
            LogMessage("Root IPv6 mode committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == SpinRootIpv6Prefix) {
        uint8_t prefix[1] = {(uint8_t)(SpinRootIpv6Prefix->Value & 0xFF)};
        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_nw_ipv6_prefix,
                                                          SigNet::TID_NW_IPV6_PREFIX,
                                                          prefix,
                                                          1,
                                                          SigNet::TID_BLOB_U8,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_nw_ipv6_prefix);
            LogMessage("Root IPv6 prefix committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == CBRoleNode || sender == CBRoleSender || sender == CBRoleManager) {
        uint8_t role = 0;
        if (CBRoleNode->Checked)    { role |= SigNet::ROLE_CAP_NODE; }
        if (CBRoleSender->Checked)  { role |= SigNet::ROLE_CAP_SENDER; }
        if (CBRoleManager->Checked) { role |= SigNet::ROLE_CAP_MANAGER; }

        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_role_capability,
                                                          SigNet::TID_RT_ROLE_CAPABILITY,
                                                          &role,
                                                          1,
                                                          SigNet::TID_BLOB_U8,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_rt_role_capability);
            LogMessage("Root role capability committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == CheckListRootSupportedTids) {
        const SigNet::Node::SupportedTidEntry* tid_table = SigNet::Node::GetSupportedTidTable();
        const int item_count = CheckListRootSupportedTids->Items->Count;
        uint8_t tid_bytes[SigNet::Node::SUPPORTED_TID_COUNT * 2];
        uint16_t tid_byte_count = 0;
        int i;
        for (i = 0; i < item_count && i < SigNet::Node::SUPPORTED_TID_COUNT; ++i) {
            if (CheckListRootSupportedTids->Checked[i]) {
                uint16_t tid_val = tid_table[i].tid;
                tid_bytes[tid_byte_count++] = (uint8_t)(tid_val >> 8);
                tid_bytes[tid_byte_count++] = (uint8_t)(tid_val & 0xFF);
            }
        }

        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.root.tid_rt_supported_tids,
                                                          SigNet::TID_RT_SUPPORTED_TIDS,
                                                          tid_bytes,
                                                          tid_byte_count,
                                                          SigNet::TID_BLOB_BYTES,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.root.tid_rt_supported_tids);
            LogMessage("Root supported TIDs committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == SpinEP1Universe) {
        uint16_t ep1_universe = static_cast<uint16_t>(SpinEP1Universe->Value);
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

    if (sender == ComboEP1Direction || sender == CBEp1RdmEnable) {
        uint8_t ep_dir = (uint8_t)(ComboEP1Direction->ItemIndex & 0x03);
        if (CBEp1RdmEnable->Checked) { ep_dir |= SigNet::EP_DIR_RDM_ENABLE; }

        bool changed_dir = false;
        bool changed_rdm_bg = false;
        SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_direction,
                                                      SigNet::TID_EP_DIRECTION,
                                                      &ep_dir,
                                                      1,
                                                      SigNet::TID_BLOB_U8,
                                                      changed_dir);

        uint8_t rdm_bg[1] = {(uint8_t)(CBEp1RdmEnable->Checked ? 1 : 0)};
        SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_rdm_tod_background,
                                                      SigNet::TID_RDM_TOD_BACKGROUND,
                                                      rdm_bg,
                                                      1,
                                                      SigNet::TID_BLOB_U8,
                                                      changed_rdm_bg);

        if (changed_dir) {
            MarkBlobStale(node_user_data.ep1.tid_ep_direction);
        }
        if (changed_rdm_bg) {
            MarkBlobStale(node_user_data.ep1.tid_rdm_tod_background);
        }
        if (changed_dir || changed_rdm_bg) {
            LogMessage("EP1 direction/RDM committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == CBCapConsumeLevel || sender == CBCapSupplyLevel ||
        sender == CBCapConsumeRDM || sender == CBCapSupplyRDM || sender == CBCapVirtual) {
        uint8_t cap = 0;
        if (CBCapConsumeLevel->Checked) { cap |= SigNet::EP_CAP_CONSUME_LEVEL; }
        if (CBCapSupplyLevel->Checked)  { cap |= SigNet::EP_CAP_SUPPLY_LEVEL; }
        if (CBCapConsumeRDM->Checked)   { cap |= SigNet::EP_CAP_CONSUME_RDM; }
        if (CBCapSupplyRDM->Checked)    { cap |= SigNet::EP_CAP_SUPPLY_RDM; }
        if (CBCapVirtual->Checked)      { cap |= SigNet::EP_CAP_VIRTUAL; }

        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_capability,
                                                          SigNet::TID_EP_CAPABILITY,
                                                          &cap,
                                                          1,
                                                          SigNet::TID_BLOB_U8,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.ep1.tid_ep_capability);
            LogMessage("EP1 capability committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == ComboEP1Failover || sender == SpinEP1FailoverScene) {
        UpdateFailoverSceneVisibility();
        uint8_t mode = (uint8_t)(ComboEP1Failover->ItemIndex & 0x07);
        uint16_t scene = (mode == 0x03) ? (uint16_t)SpinEP1FailoverScene->Value : 0;
        uint8_t failover[3] = {mode, (uint8_t)(scene >> 8), (uint8_t)(scene & 0xFF)};

        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_failover,
                                                          SigNet::TID_EP_FAILOVER,
                                                          failover,
                                                          3,
                                                          SigNet::TID_BLOB_BYTES,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.ep1.tid_ep_failover);
            LogMessage("EP1 failover committed (" + trigger_source + ") and marked stale.");
        }
        return;
    }

    if (sender == ComboEP1DmxTransMode || sender == ComboEP1DmxOutputTiming) {
        uint8_t dmx_timing[2] = {
            (uint8_t)(ComboEP1DmxTransMode->ItemIndex & 0x01),
            (uint8_t)(ComboEP1DmxOutputTiming->ItemIndex & 0x03)
        };

        if (SigNet::Node::StoreNodeBlobFromBytesIfChanged(node_user_data.ep1.tid_ep_dmx_timing,
                                                          SigNet::TID_EP_DMX_TIMING,
                                                          dmx_timing,
                                                          2,
                                                          SigNet::TID_BLOB_BYTES,
                                                          changed) && changed) {
            MarkBlobStale(node_user_data.ep1.tid_ep_dmx_timing);
            LogMessage("EP1 DMX timing committed (" + trigger_source + ") and marked stale.");
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

void __fastcall TFormSigNetNode::SupportedTidsClickCheck(TObject *Sender)
{
    CommitControlFromUI(Sender, "change");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ComboEP1FailoverChange(TObject *Sender)
{
    CommitControlFromUI(Sender, "change");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSupportedTidsNoneClick(TObject *Sender)
{
    for (int i = 0; i < CheckListRootSupportedTids->Items->Count; ++i) {
        CheckListRootSupportedTids->Checked[i] = false;
    }
    CommitControlFromUI(CheckListRootSupportedTids, "button");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSupportedTidsMandatedClick(TObject *Sender)
{
    const SigNet::Node::SupportedTidEntry* tid_table = SigNet::Node::GetSupportedTidTable();
    for (int i = 0; i < SigNet::Node::SUPPORTED_TID_COUNT; ++i) {
        CheckListRootSupportedTids->Checked[i] = tid_table[i].mandated;
    }
    CommitControlFromUI(CheckListRootSupportedTids, "button");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::ButtonSupportedTidsAllClick(TObject *Sender)
{
    for (int i = 0; i < CheckListRootSupportedTids->Items->Count; ++i) {
        CheckListRootSupportedTids->Checked[i] = true;
    }
    CommitControlFromUI(CheckListRootSupportedTids, "button");
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

bool TFormSigNetNode::SendAnnouncePacket()
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send announce - Kc not available. Click Select K0 first.");
        error_count++;
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Invalid TUID - must be 12 hex characters");
        error_count++;
        return false;
    }

    uint16_t firmware_version_id = 0;
    uint16_t mfg_code = 0;
    uint16_t product_variant_id = 0;

    try {
        firmware_version_id = static_cast<uint16_t>(StrToInt(EditAnnounceVersionNum->Text.Trim()));
    }
    catch (...) {
        LogError("Announce version number must be a valid 16-bit decimal value");
        error_count++;
        return false;
    }

    try {
        String mfg_code_text = EditAnnounceMfgCode->Text.Trim();
        if (mfg_code_text.Pos("0x") != 1 && mfg_code_text.Pos("0X") != 1) {
            mfg_code_text = "0x" + mfg_code_text;
        }
        mfg_code = static_cast<uint16_t>(StrToInt(mfg_code_text));
    }
    catch (...) {
        LogError("Manufacturer code must be valid hex (e.g. 534c or 0x534c)");
        error_count++;
        return false;
    }

    try {
        String variant_text = EditAnnounceProductVariant->Text.Trim();
        if (variant_text.Pos("0x") != 1 && variant_text.Pos("0X") != 1) {
            variant_text = "0x" + variant_text;
        }
        product_variant_id = static_cast<uint16_t>(StrToInt(variant_text));
    }
    catch (...) {
        LogError("Product variant ID must be valid hex (e.g. 0001 or 0x0001)");
        error_count++;
        return false;
    }

    String fw_text = EditAnnounceVersionString->Text.Trim();
    if (fw_text.IsEmpty()) {
        LogError("Version string cannot be empty");
        error_count++;
        return false;
    }

    AnsiString fw_ansi = AnsiString(fw_text);

    const uint8_t protocol_version = 0x01;
    // Node role only (Bit 0 = Node)
    const uint8_t role_capability_bits = SigNet::ROLE_CAP_NODE;
    const uint16_t change_count = 0x0000;

    SigNet::PacketBuffer buffer;
    int32_t result = SigNet::BuildAnnouncePacket(
        buffer,
        tuid,
        mfg_code,
        product_variant_id,
        firmware_version_id,
        fw_ansi.c_str(),
        protocol_version,
        role_capability_bits,
        change_count,
        session_id,
        sequence_num,
        citizen_key,
        message_id
    );

    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Failed to build announce packet: error %d", result));
        error_count++;
        return false;
    }

    last_packet_size = buffer.GetSize();

    if (!SendRawPacket(buffer.GetBuffer(), buffer.GetSize(), SigNet::MULTICAST_NODE_SEND_IP, "Announce")) {
        return false;
    }

    send_count++;
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;

    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
        LogMessage(String().sprintf(L"Session rolled over to %u", session_id));
    }

    EditSequence->Text = String().sprintf(L"%u", sequence_num);
    EditMessageID->Text = String().sprintf(L"%u", message_id);
    EditSessionID->Text = String().sprintf(L"%u", session_id);

    return true;
}
//---------------------------------------------------------------------------

void TFormSigNetNode::RefreshReceiverGroups()
{
    char nic_ip[16];
    nic_ip[0] = 0;

    // Resolve a valid NIC IP in priority order:
    // selected_nic_ip -> EditNicIP -> startup auto-select -> loopback fallback.
    if (!ExtractValidIPv4FromText(selected_nic_ip, nic_ip, sizeof(nic_ip))) {
        ExtractValidIPv4FromText(AnsiString(EditNicIP->Text), nic_ip, sizeof(nic_ip));
    }

    if (nic_ip[0] == 0) {
        AnsiString auto_nic = SigNet::SelectDefaultStartupNicIP();
        if (!ExtractValidIPv4FromText(auto_nic, nic_ip, sizeof(nic_ip))) {
            strncpy(nic_ip, "127.0.0.1", sizeof(nic_ip) - 1);
            nic_ip[sizeof(nic_ip) - 1] = 0;
        }
    }

    if (selected_nic_ip != nic_ip) {
        selected_nic_ip = nic_ip;
        EditNicIP->Text = String(nic_ip);
    }

    uint16_t ep1_universe = static_cast<uint16_t>(SpinEP1Universe->Value);
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

SigNet::TidDataBlob* TFormSigNetNode::FindTidBlob(uint16_t tid)
{
    switch (tid) {
        case SigNet::TID_RT_SUPPORTED_TIDS: return &node_user_data.root.tid_rt_supported_tids;
        case SigNet::TID_RT_ENDPOINT_COUNT: return &node_user_data.root.tid_rt_endpoint_count;
        case SigNet::TID_RT_PROTOCOL_VERSION: return &node_user_data.root.tid_rt_protocol_version;
        case SigNet::TID_RT_FIRMWARE_VERSION: return &node_user_data.root.tid_rt_firmware_version;
        case SigNet::TID_RT_DEVICE_LABEL: return &node_user_data.root.tid_rt_device_label;
        case SigNet::TID_RT_MULT: return &node_user_data.root.tid_rt_mult;
        case SigNet::TID_RT_IDENTIFY: return &node_user_data.root.tid_rt_identify;
        case SigNet::TID_RT_STATUS: return &node_user_data.root.tid_rt_status;
        case SigNet::TID_RT_ROLE_CAPABILITY: return &node_user_data.root.tid_rt_role_capability;
        case SigNet::TID_RT_REBOOT: return &node_user_data.root.tid_rt_reboot;
        case SigNet::TID_RT_MODEL_NAME: return &node_user_data.root.tid_rt_model_name;
        case SigNet::TID_RT_SCOPE: return &node_user_data.root.tid_rt_scope;
        case SigNet::TID_RT_UNPROVISION: return &node_user_data.root.tid_rt_unprovision;
        case SigNet::TID_NW_MAC_ADDRESS: return &node_user_data.root.tid_nw_mac_address;
        case SigNet::TID_NW_IPV4_MODE: return &node_user_data.root.tid_nw_ipv4_mode;
        case SigNet::TID_NW_IPV4_ADDRESS: return &node_user_data.root.tid_nw_ipv4_address;
        case SigNet::TID_NW_IPV4_NETMASK: return &node_user_data.root.tid_nw_ipv4_netmask;
        case SigNet::TID_NW_IPV4_GATEWAY: return &node_user_data.root.tid_nw_ipv4_gateway;
        case SigNet::TID_NW_IPV4_CURRENT: return &node_user_data.root.tid_nw_ipv4_current;
        case SigNet::TID_NW_IPV6_MODE: return &node_user_data.root.tid_nw_ipv6_mode;
        case SigNet::TID_NW_IPV6_ADDRESS: return &node_user_data.root.tid_nw_ipv6_address;
        case SigNet::TID_NW_IPV6_PREFIX: return &node_user_data.root.tid_nw_ipv6_prefix;
        case SigNet::TID_NW_IPV6_GATEWAY: return &node_user_data.root.tid_nw_ipv6_gateway;
        case SigNet::TID_NW_IPV6_CURRENT: return &node_user_data.root.tid_nw_ipv6_current;
        case SigNet::TID_DG_SECURITY_EVENT: return &node_user_data.root.tid_dg_security_event;
        case SigNet::TID_DG_MESSAGE: return &node_user_data.root.tid_dg_message;

        case SigNet::TID_EP_UNIVERSE: return &node_user_data.ep1.tid_ep_universe;
        case SigNet::TID_EP_LABEL: return &node_user_data.ep1.tid_ep_label;
        case SigNet::TID_EP_MULT_OVERRIDE: return &node_user_data.ep1.tid_ep_mult_override;
        case SigNet::TID_EP_CAPABILITY: return &node_user_data.ep1.tid_ep_capability;
        case SigNet::TID_EP_DIRECTION: return &node_user_data.ep1.tid_ep_direction;
        case SigNet::TID_EP_INPUT_PRIORITY: return &node_user_data.ep1.tid_ep_input_priority;
        case SigNet::TID_EP_STATUS: return &node_user_data.ep1.tid_ep_status;
        case SigNet::TID_EP_FAILOVER: return &node_user_data.ep1.tid_ep_failover;
        case SigNet::TID_EP_DMX_TIMING: return &node_user_data.ep1.tid_ep_dmx_timing;
        case SigNet::TID_EP_REFRESH_CAPABILITY: return &node_user_data.ep1.tid_ep_refresh_capability;
        case SigNet::TID_RDM_TOD_DATA: return &node_user_data.ep1.tid_rdm_tod_data;
        case SigNet::TID_RDM_FLOW_CONTROL: return &node_user_data.ep1.tid_rdm_flow_control;
        case SigNet::TID_DG_LEVEL_FOLDBACK: return &node_user_data.ep1.tid_dg_level_foldback;
        case SigNet::TID_LEVEL: return &node_user_data.ep1.tid_level;
        case SigNet::TID_PRIORITY: return &node_user_data.ep1.tid_priority;
        case SigNet::TID_SYNC: return &node_user_data.ep1.tid_sync;
        default:
            return 0;
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

void TFormSigNetNode::MarkBlobStale(SigNet::TidDataBlob& blob)
{
    if (SigNet::Node::IsTidWriteOnly(blob.tid)) {
        blob.manager_is_stale = false;
        return;
    }
    blob.manager_is_stale = true;
}

void TFormSigNetNode::ClearAllManagerStaleFlags()
{
    node_user_data.root.tid_rt_supported_tids.manager_is_stale = false;
    node_user_data.root.tid_rt_endpoint_count.manager_is_stale = false;
    node_user_data.root.tid_rt_protocol_version.manager_is_stale = false;
    node_user_data.root.tid_rt_firmware_version.manager_is_stale = false;
    node_user_data.root.tid_rt_device_label.manager_is_stale = false;
    node_user_data.root.tid_rt_mult.manager_is_stale = false;
    node_user_data.root.tid_rt_identify.manager_is_stale = false;
    node_user_data.root.tid_rt_status.manager_is_stale = false;
    node_user_data.root.tid_rt_role_capability.manager_is_stale = false;
    node_user_data.root.tid_rt_reboot.manager_is_stale = false;
    node_user_data.root.tid_rt_model_name.manager_is_stale = false;
    node_user_data.root.tid_rt_scope.manager_is_stale = false;
    node_user_data.root.tid_rt_unprovision.manager_is_stale = false;
    node_user_data.root.tid_nw_mac_address.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv4_mode.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv4_address.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv4_netmask.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv4_gateway.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv4_current.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv6_mode.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv6_address.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv6_prefix.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv6_gateway.manager_is_stale = false;
    node_user_data.root.tid_nw_ipv6_current.manager_is_stale = false;
    node_user_data.root.tid_dg_security_event.manager_is_stale = false;
    node_user_data.root.tid_dg_message.manager_is_stale = false;

    node_user_data.ep1.tid_ep_universe.manager_is_stale = false;
    node_user_data.ep1.tid_ep_label.manager_is_stale = false;
    node_user_data.ep1.tid_ep_mult_override.manager_is_stale = false;
    node_user_data.ep1.tid_ep_capability.manager_is_stale = false;
    node_user_data.ep1.tid_ep_direction.manager_is_stale = false;
    node_user_data.ep1.tid_ep_input_priority.manager_is_stale = false;
    node_user_data.ep1.tid_ep_status.manager_is_stale = false;
    node_user_data.ep1.tid_ep_failover.manager_is_stale = false;
    node_user_data.ep1.tid_ep_dmx_timing.manager_is_stale = false;
    node_user_data.ep1.tid_ep_refresh_capability.manager_is_stale = false;
    node_user_data.ep1.tid_rdm_tod_data.manager_is_stale = false;
    node_user_data.ep1.tid_rdm_tod_background.manager_is_stale = false;
    node_user_data.ep1.tid_rdm_flow_control.manager_is_stale = false;
    node_user_data.ep1.tid_dg_level_foldback.manager_is_stale = false;
    node_user_data.ep1.tid_level.manager_is_stale = false;
    node_user_data.ep1.tid_priority.manager_is_stale = false;
    node_user_data.ep1.tid_sync.manager_is_stale = false;
}

void TFormSigNetNode::InitializeNodeUserDataFromUI()
{
    // --- node_config: identity fields (not TID blobs) ---
    ParseTUIDFromHex(EditTUID->Text.Trim());  // updates this->tuid
    memcpy(node_config.tuid, tuid, 6);

    bool parse_ok = true;
    node_config.mfg_code = ParseMfgCodeFromUI(parse_ok);
    if (!parse_ok) { node_config.mfg_code = static_cast<uint16_t>((SigNet::SoemCodeSdkNode >> 16) & 0xFFFF); }
    node_config.product_variant_id = ParseProductVariantFromUI(parse_ok);
    if (!parse_ok) { node_config.product_variant_id = 0x0001; }
    node_config.endpoint = static_cast<uint16_t>(SpinEndpoint->Value);
    node_config.change_count = 0;

    // --- Root EP: ENDPOINT_COUNT ---
    {
        int ep_count_val = StrToIntDef(EditRootEndpCount->Text.Trim(), 1);
        uint8_t ep_count[2] = {(uint8_t)(ep_count_val >> 8), (uint8_t)(ep_count_val & 0xFF)};
        StoreBlobFromBytes(node_user_data.root.tid_rt_endpoint_count,
                           SigNet::TID_RT_ENDPOINT_COUNT, ep_count, 2, SigNet::TID_BLOB_U16);
    }

    // --- Root EP: PROTOCOL_VERSION ---
    {
        uint8_t prot_ver[1] = {(uint8_t)StrToIntDef(EditRootProtVersion->Text.Trim(), 1)};
        StoreBlobFromBytes(node_user_data.root.tid_rt_protocol_version,
                           SigNet::TID_RT_PROTOCOL_VERSION, prot_ver, 1, SigNet::TID_BLOB_U8);
    }

    // --- Root EP: FIRMWARE_VERSION (2-byte big-endian ID + string bytes) ---
    {
        uint16_t fw_id = (uint16_t)StrToIntDef(EditRootFirmwareID->Text.Trim(), APP_VERSION_ID);
        AnsiString fw_str = AnsiString(EditRootFirmwareStr->Text);
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
        StoreBlobFromBytes(node_user_data.root.tid_rt_device_label,
                           SigNet::TID_RT_DEVICE_LABEL,
                           (const uint8_t*)device_label.c_str(),
                           (uint16_t)device_label.Length(),
                           SigNet::TID_BLOB_TEXT);
    }

    // --- Root EP: RT_MULT ---
    {
        uint8_t mult_val = 0x00;
        String mult_text = EditRootMultState->Text.Trim();
        if (mult_text.Pos("0x01") == 1 || mult_text.Pos("0X01") == 1) { mult_val = 0x01; }
        StoreBlobFromBytes(node_user_data.root.tid_rt_mult,
                           SigNet::TID_RT_MULT, &mult_val, 1, SigNet::TID_BLOB_U8);
    }

    // --- Root EP: IDENTIFY ---
    {
        uint8_t identify[1] = {(uint8_t)(ComboRootIdentify->ItemIndex & 0x03)};
        StoreBlobFromBytes(node_user_data.root.tid_rt_identify,
                           SigNet::TID_RT_IDENTIFY, identify, 1, SigNet::TID_BLOB_U8);
    }

    // --- Root EP: STATUS ---
    {
        uint32_t status_val = 0;
        if (CBStatusHwFault->Checked)     { status_val |= SigNet::RT_STATUS_HW_FAULT; }
        if (CBStatusFactoryBoot->Checked) { status_val |= SigNet::RT_STATUS_FACTORY_BOOT; }
        if (CBStatusConfigLock->Checked)  { status_val |= SigNet::RT_STATUS_CONFIG_LOCK; }
        uint8_t rt_status[4] = {(uint8_t)(status_val >> 24), (uint8_t)(status_val >> 16),
                                 (uint8_t)(status_val >> 8),  (uint8_t)(status_val & 0xFF)};
        StoreBlobFromBytes(node_user_data.root.tid_rt_status,
                           SigNet::TID_RT_STATUS, rt_status, 4, SigNet::TID_BLOB_U32);
    }

    // --- Root EP: ROLE_CAPABILITY ---
    {
        uint8_t role = 0;
        if (CBRoleNode->Checked)    { role |= SigNet::ROLE_CAP_NODE; }
        if (CBRoleSender->Checked)  { role |= SigNet::ROLE_CAP_SENDER; }
        if (CBRoleManager->Checked) { role |= SigNet::ROLE_CAP_MANAGER; }
        StoreBlobFromBytes(node_user_data.root.tid_rt_role_capability,
                           SigNet::TID_RT_ROLE_CAPABILITY, &role, 1, SigNet::TID_BLOB_U8);
    }

    // --- Root EP: MODEL_NAME (SoemCode prefix stripped here – store just the name) ---
    {
        AnsiString model_name = AnsiString(EditRootModelName->Text);
        if (model_name.Length() > 64) {
            model_name = model_name.SubString(1, 64);
        }
        StoreBlobFromBytes(node_user_data.root.tid_rt_model_name,
                           SigNet::TID_RT_MODEL_NAME,
                           (const uint8_t*)model_name.c_str(),
                           (uint16_t)model_name.Length(),
                           SigNet::TID_BLOB_TEXT);
    }

    // --- Root EP: SCOPE ---
    {
        AnsiString scope_text = AnsiString(EditScope->Text.Trim());
        if (scope_text.IsEmpty()) {
            scope_text = SigNet::SIGNET_URI_SCOPE_DEFAULT;
        }
        StoreBlobFromBytes(node_user_data.root.tid_rt_scope,
                           SigNet::TID_RT_SCOPE,
                           (const uint8_t*)scope_text.c_str(),
                           (uint16_t)scope_text.Length(),
                           SigNet::TID_BLOB_TEXT);
    }

    // --- Root EP: SUPPORTED_TIDS (2 bytes per checked entry) ---
    {
        const SigNet::Node::SupportedTidEntry* tid_table = SigNet::Node::GetSupportedTidTable();
        const int item_count = CheckListRootSupportedTids->Items->Count;
        uint8_t tid_bytes[SigNet::Node::SUPPORTED_TID_COUNT * 2];
        uint16_t tid_byte_count = 0;
        int i;
        for (i = 0; i < item_count && i < SigNet::Node::SUPPORTED_TID_COUNT; ++i) {
            if (CheckListRootSupportedTids->Checked[i]) {
                uint16_t tid_val = tid_table[i].tid;
                tid_bytes[tid_byte_count++] = (uint8_t)(tid_val >> 8);
                tid_bytes[tid_byte_count++] = (uint8_t)(tid_val & 0xFF);
            }
        }
        StoreBlobFromBytes(node_user_data.root.tid_rt_supported_tids,
                           SigNet::TID_RT_SUPPORTED_TIDS, tid_bytes, tid_byte_count, SigNet::TID_BLOB_BYTES);
    }

    // --- Network: NW_MAC_ADDRESS ---
    {
        uint8_t mac[6] = {0, 0, 0, 0, 0, 0};
        AnsiString mac_str = AnsiString(EditRootMac->Text.Trim());
        unsigned int m[6] = {0};
        sscanf(mac_str.c_str(), "%2x:%2x:%2x:%2x:%2x:%2x",
               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
        int mi;
        for (mi = 0; mi < 6; ++mi) { mac[mi] = (uint8_t)m[mi]; }
        StoreBlobFromBytes(node_user_data.root.tid_nw_mac_address,
                           SigNet::TID_NW_MAC_ADDRESS, mac, 6, SigNet::TID_BLOB_BYTES);
    }

    // --- Network: NW_IPV4_MODE ---
    {
        uint8_t ipv4_mode[1] = {(uint8_t)(ComboRootIpv4Mode->ItemIndex & 0x01)};
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv4_mode,
                           SigNet::TID_NW_IPV4_MODE, ipv4_mode, 1, SigNet::TID_BLOB_U8);
    }

    // --- Network: NW_IPV4_ADDRESS / NETMASK / GATEWAY / CURRENT ---
    {
        AnsiString addr_str = AnsiString(EditRootIpv4Addr->Text.Trim());
        AnsiString mask_str = AnsiString(EditRootIpv4Mask->Text.Trim());
        AnsiString gw_str   = AnsiString(EditRootIpv4Gateway->Text.Trim());
        u_long addr = inet_addr(addr_str.c_str()); if (addr == INADDR_NONE) { addr = 0; }
        u_long mask = inet_addr(mask_str.c_str()); if (mask == INADDR_NONE) { mask = 0; }
        u_long gw   = inet_addr(gw_str.c_str());   if (gw   == INADDR_NONE) { gw   = 0; }
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv4_address,
                           SigNet::TID_NW_IPV4_ADDRESS, (uint8_t*)&addr, 4, SigNet::TID_BLOB_BYTES);
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv4_netmask,
                           SigNet::TID_NW_IPV4_NETMASK, (uint8_t*)&mask, 4, SigNet::TID_BLOB_BYTES);
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv4_gateway,
                           SigNet::TID_NW_IPV4_GATEWAY, (uint8_t*)&gw, 4, SigNet::TID_BLOB_BYTES);
        uint8_t current[12];
        memcpy(current,     &addr, 4);
        memcpy(current + 4, &mask, 4);
        memcpy(current + 8, &gw,   4);
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv4_current,
                           SigNet::TID_NW_IPV4_CURRENT, current, 12, SigNet::TID_BLOB_BYTES);
    }

    // --- Network: NW_IPV6_MODE / ADDRESS / PREFIX / GATEWAY / CURRENT ---
    //     (no real IPv6 stack; address and gateway bytes are zero)
    {
        uint8_t ipv6_mode[1] = {(uint8_t)(ComboRootIpv6Mode->ItemIndex & 0x03)};
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv6_mode,
                           SigNet::TID_NW_IPV6_MODE, ipv6_mode, 1, SigNet::TID_BLOB_U8);

        uint8_t ipv6_zero[16] = {0};
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv6_address,
                           SigNet::TID_NW_IPV6_ADDRESS, ipv6_zero, 16, SigNet::TID_BLOB_BYTES);

        uint8_t prefix[1] = {(uint8_t)(SpinRootIpv6Prefix->Value & 0xFF)};
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv6_prefix,
                           SigNet::TID_NW_IPV6_PREFIX, prefix, 1, SigNet::TID_BLOB_U8);

        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv6_gateway,
                           SigNet::TID_NW_IPV6_GATEWAY, ipv6_zero, 16, SigNet::TID_BLOB_BYTES);

        uint8_t ipv6_current[33] = {0};
        ipv6_current[16] = prefix[0];
        StoreBlobFromBytes(node_user_data.root.tid_nw_ipv6_current,
                           SigNet::TID_NW_IPV6_CURRENT, ipv6_current, 33, SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: UNIVERSE ---
    {
        uint16_t ep1_universe = static_cast<uint16_t>(SpinEP1Universe->Value);
        uint8_t universe_payload[2] = {(uint8_t)(ep1_universe >> 8), (uint8_t)(ep1_universe & 0xFF)};
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_universe,
                           SigNet::TID_EP_UNIVERSE, universe_payload, 2, SigNet::TID_BLOB_U16);
    }

    // --- EP1: LABEL ---
    {
        AnsiString ep1_label = AnsiString(EditEP1Label->Text);
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_label,
                           SigNet::TID_EP_LABEL,
                           (const uint8_t*)ep1_label.c_str(),
                           (uint16_t)ep1_label.Length(),
                           SigNet::TID_BLOB_TEXT);
    }

    // --- EP1: MULT_OVERRIDE (IPv4, network byte order) ---
    {
        AnsiString mult_ip_str = AnsiString(EditEP1MultOverride->Text.Trim());
        u_long mult_addr = inet_addr(mult_ip_str.c_str());
        if (mult_addr == INADDR_NONE) { mult_addr = 0; }
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_mult_override,
                           SigNet::TID_EP_MULT_OVERRIDE, (uint8_t*)&mult_addr, 4, SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: DIRECTION (bits 0..1 = direction, bit 2 = RDM enable) ---
    {
        uint8_t ep_dir = (uint8_t)(ComboEP1Direction->ItemIndex & 0x03);
        if (CBEp1RdmEnable->Checked) { ep_dir |= SigNet::EP_DIR_RDM_ENABLE; }
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_direction,
                           SigNet::TID_EP_DIRECTION, &ep_dir, 1, SigNet::TID_BLOB_U8);
    }

    // --- EP1: INPUT_PRIORITY (keep existing if already set by Sig-Net; seed from 100) ---
    if (node_user_data.ep1.tid_ep_input_priority.length == 0) {
        uint8_t default_prio[1] = {100};
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_input_priority,
                           SigNet::TID_EP_INPUT_PRIORITY, default_prio, 1, SigNet::TID_BLOB_U8);
    }

    // --- EP1: STATUS ---
    {
        uint32_t ep_status_val = 0;
        try {
            String s = EditEP1Status->Text.Trim();
            if (s.Pos("0x") != 1 && s.Pos("0X") != 1) { s = "0x" + s; }
            ep_status_val = (uint32_t)StrToInt(s);
        } catch (...) {}
        uint8_t ep_status[4] = {(uint8_t)(ep_status_val >> 24), (uint8_t)(ep_status_val >> 16),
                                 (uint8_t)(ep_status_val >> 8),  (uint8_t)(ep_status_val & 0xFF)};
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_status,
                           SigNet::TID_EP_STATUS, ep_status, 4, SigNet::TID_BLOB_U32);
    }

    // --- EP1: FAILOVER (mode + scene high + scene low = 3 bytes) ---
    {
        uint8_t mode = (uint8_t)(ComboEP1Failover->ItemIndex & 0x07);
        uint16_t scene = (mode == 0x03) ? (uint16_t)SpinEP1FailoverScene->Value : 0;
        uint8_t failover[3] = {mode, (uint8_t)(scene >> 8), (uint8_t)(scene & 0xFF)};
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_failover,
                           SigNet::TID_EP_FAILOVER, failover, 3, SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: CAPABILITY (bitfield) ---
    {
        uint8_t cap = 0;
        if (CBCapConsumeLevel->Checked) { cap |= SigNet::EP_CAP_CONSUME_LEVEL; }
        if (CBCapSupplyLevel->Checked)  { cap |= SigNet::EP_CAP_SUPPLY_LEVEL; }
        if (CBCapConsumeRDM->Checked)   { cap |= SigNet::EP_CAP_CONSUME_RDM; }
        if (CBCapSupplyRDM->Checked)    { cap |= SigNet::EP_CAP_SUPPLY_RDM; }
        if (CBCapVirtual->Checked)      { cap |= SigNet::EP_CAP_VIRTUAL; }
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_capability,
                           SigNet::TID_EP_CAPABILITY, &cap, 1, SigNet::TID_BLOB_U8);
    }

    // --- EP1: REFRESH_CAPABILITY ---
    {
        uint8_t refresh[1] = {(uint8_t)StrToIntDef(EditEP1RefreshCap->Text.Trim(), 44)};
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_refresh_capability,
                           SigNet::TID_EP_REFRESH_CAPABILITY, refresh, 1, SigNet::TID_BLOB_U8);
    }

    // --- EP1: DMX_TIMING (transmit mode byte + output timing byte) ---
    {
        uint8_t dmx_timing[2] = {
            (uint8_t)(ComboEP1DmxTransMode->ItemIndex   & 0x01),
            (uint8_t)(ComboEP1DmxOutputTiming->ItemIndex & 0x03)
        };
        StoreBlobFromBytes(node_user_data.ep1.tid_ep_dmx_timing,
                           SigNet::TID_EP_DMX_TIMING, dmx_timing, 2, SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: RDM_TOD_BACKGROUND ---
    {
        uint8_t rdm_bg[1] = {(uint8_t)(CBEp1RdmEnable->Checked ? 1 : 0)};
        StoreBlobFromBytes(node_user_data.ep1.tid_rdm_tod_background,
                           SigNet::TID_RDM_TOD_BACKGROUND, rdm_bg, 1, SigNet::TID_BLOB_U8);
    }

    // --- EP1: RDM_FLOW_CONTROL ---
    {
        uint8_t rdm_fifo[2] = { 0x00, 0x00 };
        StoreBlobFromBytes(node_user_data.ep1.tid_rdm_flow_control,
                           SigNet::TID_RDM_FLOW_CONTROL, rdm_fifo, 2, SigNet::TID_BLOB_BYTES);
    }

    // --- EP1: RDM_TOD_DATA ---
    {
        uint8_t tod_data[2] = { 0x01, 0x01 };  // packet 1 of 1, empty UID array
        StoreBlobFromBytes(node_user_data.ep1.tid_rdm_tod_data,
                           SigNet::TID_RDM_TOD_DATA, tod_data, 2, SigNet::TID_BLOB_BYTES);
    }

    ClearAllManagerStaleFlags();
    ClearAllUIStaleFlags();
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

    uint16_t ui_endpoint = static_cast<uint16_t>(SpinEndpoint->Value);
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

void TFormSigNetNode::HandleGetRequest(uint16_t tid)
{
    LogMessage(String().sprintf(L"GET request received for TID 0x%04X", tid));
}

void TFormSigNetNode::HandleSetRequest(uint16_t tid, const uint8_t* value, uint16_t length, bool from_manager)
{
    SigNet::TidDataBlob* blob = FindTidBlob(tid);
    if (!blob) {
        LogMessage(String().sprintf(L"SET received for unsupported TID 0x%04X (stored ignored)", tid));
        return;
    }

    if ((tid == SigNet::TID_RT_DEVICE_LABEL || tid == SigNet::TID_EP_LABEL || tid == SigNet::TID_RT_MODEL_NAME) &&
        length > 64) {
        LogError(String().sprintf(L"SET rejected for TID 0x%04X: length %u exceeds 64", tid, length));
        return;
    }

    if (tid == SigNet::TID_RT_SCOPE) {
        if (length < 1 || length > SigNet::SIGNET_URI_SCOPE_MAX_LENGTH || !value) {
            LogError("SET rejected for TID_RT_SCOPE: invalid length");
            return;
        }

        char scope[SigNet::SIGNET_URI_SCOPE_MAX_LENGTH + 1];
        memcpy(scope, value, length);
        scope[length] = 0;

        int32_t rc = SigNet::CoAP::SetURIScope(scope);
        if (rc != SigNet::SIGNET_SUCCESS) {
            LogError(String().sprintf(L"SET rejected for TID_RT_SCOPE: invalid value (error %d)", rc));
            return;
        }
    }

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
        return;
    }

    if (from_manager) {
        blob->manager_is_stale = false;
        blob->ui_is_stale = true;  // SyncUIFromStaleBlobs() will apply the change on the next timer tick
    } else {
        MarkBlobStale(*blob);
    }

    LogMessage(String().sprintf(L"SET applied for TID 0x%04X (len=%u)", tid, length) +
               (blob->manager_is_stale ? " [stale=true]" : " [stale=false]"));
}

bool TFormSigNetNode::SendProactiveResponse(const String& reason)
{
    bool send_root = last_poll_reply_root;
    bool send_data = last_poll_reply_data;
    uint16_t ui_endpoint = static_cast<uint16_t>(SpinEndpoint->Value);

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

    ClearAllManagerStaleFlags();
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

    EditSequence->Text = String().sprintf(L"%u", sequence_num);
    EditMessageID->Text = String().sprintf(L"%u", message_id);
    EditSessionID->Text = String().sprintf(L"%u", session_id);

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

    SigNet::TidDataBlob* root_blobs[] = {
        &node_user_data.root.tid_rt_supported_tids,
        &node_user_data.root.tid_rt_endpoint_count,
        &node_user_data.root.tid_rt_protocol_version,
        &node_user_data.root.tid_rt_firmware_version,
        &node_user_data.root.tid_rt_device_label,
        &node_user_data.root.tid_rt_mult,
        &node_user_data.root.tid_rt_identify,
        &node_user_data.root.tid_rt_status,
        &node_user_data.root.tid_rt_role_capability,
        &node_user_data.root.tid_rt_reboot,
        &node_user_data.root.tid_rt_model_name,
        &node_user_data.root.tid_rt_scope,
        &node_user_data.root.tid_rt_unprovision,
        &node_user_data.root.tid_nw_mac_address,
        &node_user_data.root.tid_nw_ipv4_mode,
        &node_user_data.root.tid_nw_ipv4_address,
        &node_user_data.root.tid_nw_ipv4_netmask,
        &node_user_data.root.tid_nw_ipv4_gateway,
        &node_user_data.root.tid_nw_ipv4_current,
        &node_user_data.root.tid_nw_ipv6_mode,
        &node_user_data.root.tid_nw_ipv6_address,
        &node_user_data.root.tid_nw_ipv6_prefix,
        &node_user_data.root.tid_nw_ipv6_gateway,
        &node_user_data.root.tid_nw_ipv6_current,
        &node_user_data.root.tid_dg_security_event,
        &node_user_data.root.tid_dg_message
    };
    SigNet::TidDataBlob* ep1_blobs[] = {
        &node_user_data.ep1.tid_ep_universe,
        &node_user_data.ep1.tid_ep_label,
        &node_user_data.ep1.tid_ep_mult_override,
        &node_user_data.ep1.tid_ep_capability,
        &node_user_data.ep1.tid_ep_direction,
        &node_user_data.ep1.tid_ep_input_priority,
        &node_user_data.ep1.tid_ep_status,
        &node_user_data.ep1.tid_ep_failover,
        &node_user_data.ep1.tid_ep_dmx_timing,
        &node_user_data.ep1.tid_ep_refresh_capability,
        &node_user_data.ep1.tid_rdm_tod_data,
        &node_user_data.ep1.tid_rdm_tod_background,
        &node_user_data.ep1.tid_rdm_flow_control,
        &node_user_data.ep1.tid_dg_level_foldback,
        &node_user_data.ep1.tid_level,
        &node_user_data.ep1.tid_priority,
        &node_user_data.ep1.tid_sync
    };

    SigNet::TidDataBlob** send_blobs = is_root_ep ? root_blobs : ep1_blobs;
    int send_blob_count = is_root_ep ? (int)(sizeof(root_blobs) / sizeof(root_blobs[0]))
                                     : (int)(sizeof(ep1_blobs) / sizeof(ep1_blobs[0]));

    int i;
    for (i = 0; i < send_blob_count; ++i) {
        SigNet::TidDataBlob* blob = send_blobs[i];
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

    EditSequence->Text = String().sprintf(L"%u", sequence_num);
    EditMessageID->Text = String().sprintf(L"%u", message_id);
    EditSessionID->Text = String().sprintf(L"%u", session_id);

    LogMessage(String().sprintf(L"Stale-only reply sent (endpoint=%u, payload=%u bytes)",
                                reply_endpoint,
                                payload.GetSize()) +
               " reason=" + reason);
    return true;
}

void TFormSigNetNode::UpdateEP1LevelPreview(const uint8_t* level_data, uint16_t slot_count)
{
    if (!level_data) {
        return;
    }

    const int MAX_DISPLAY = 512;
    int display_slots = (slot_count < MAX_DISPLAY) ? slot_count : MAX_DISPLAY;

    uint8_t frame[MAX_DISPLAY];
    memset(frame, 0, sizeof(frame));
    if (display_slots > 0) {
        memcpy(frame, level_data, display_slots);
    }

    if (level_preview_frame_valid && memcmp(level_preview_frame, frame, sizeof(frame)) == 0) {
        return;
    }
    memcpy(level_preview_frame, frame, sizeof(frame));
    level_preview_frame_valid = true;

    PaintBoxEP1Levels->Repaint();
}

void __fastcall TFormSigNetNode::PaintBoxEP1LevelsPaint(TObject *Sender)
{
    if (!PaintBoxEP1Levels) {
        return;
    }

    const int width = PaintBoxEP1Levels->ClientWidth;
    const int height = PaintBoxEP1Levels->ClientHeight;
    if (width <= 0 || height <= 0) {
        return;
    }

    TCanvas* canvas = PaintBoxEP1Levels->Canvas;
    TColor bg_color = this->Color;
    if (Vcl::Themes::StyleServices()) {
        bg_color = Vcl::Themes::StyleServices()->GetSystemColor(clBtnFace);
    }
    canvas->Brush->Color = bg_color;
    canvas->FillRect(TRect(0, 0, width, height));

    canvas->Font->Name = "Consolas";
    canvas->Font->Height = -12;
    canvas->Font->Color = clWindowText;
    canvas->Brush->Style = bsClear;

    const int CHANNELS_PER_ROW = 128;
    const int MAX_DISPLAY = 512;
    const int ROWS = MAX_DISPLAY / CHANNELS_PER_ROW;
    const int top_margin = 0;
    const int bottom_margin = 0;
    const int row_gap = 0;
    const int usable_height = height - top_margin - bottom_margin;
    const int row_height = (usable_height - ((ROWS - 1) * row_gap)) / ROWS;
    const int text_height = canvas->TextHeight("0");
    const int label_width = canvas->TextWidth("000:000 ");
    const int x_start = 4 + label_width;
    int cell_width = (width - x_start - 4) / CHANNELS_PER_ROW;
    if (cell_width < 2) {
        cell_width = 2;
    }
    int bar_width = (cell_width - 1) / 2;
    if (bar_width < 1) {
        bar_width = 1;
    }

    int row;
    for (row = 0; row < ROWS; ++row) {
        int row_top = top_margin + row * (row_height + row_gap);
        int row_bottom = (row == ROWS - 1)
                             ? (height - bottom_margin - 1)
                             : (row_top + row_height - 1);
        int bar_top_limit = row_top + 1;
        int bar_bottom = row_bottom;
        if (bar_bottom <= bar_top_limit) {
            bar_bottom = bar_top_limit + 1;
        }

        int row_start = row * CHANNELS_PER_ROW;
        String label = String().sprintf(L"%03d:%03u", row_start + 1,
                                        (unsigned int)level_preview_frame[row_start]);
        int label_y = row_top + (row_height - text_height) / 2;
        canvas->TextOut(4, label_y, label);

        canvas->Brush->Style = bsSolid;
        canvas->Brush->Color = clWindowText;
        int ch;
        for (ch = 0; ch < CHANNELS_PER_ROW; ++ch) {
            uint8_t val = level_preview_frame[row_start + ch];
            int x = x_start + ch * cell_width;

            int max_bar_height = bar_bottom - bar_top_limit + 1;
            if (max_bar_height < 1) {
                max_bar_height = 1;
            }

            int scaled_max_bar_height = (max_bar_height * 92) / 100;
            if (scaled_max_bar_height < 1) {
                scaled_max_bar_height = 1;
            }

            int bar_height = (val == 0)
                                 ? 1
                                 : ((val * scaled_max_bar_height + 254) / 255);
            if (bar_height < 1) {
                bar_height = 1;
            }
            if (bar_height > scaled_max_bar_height) {
                bar_height = scaled_max_bar_height;
            }

            TRect r(x,
                    bar_bottom - bar_height + 1,
                    x + bar_width,
                    bar_bottom + 1);
            canvas->FillRect(r);
        }
        canvas->Brush->Style = bsClear;
    }
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
    if (TryParseNodeUriEndpoint(uri, uri_endpoint)) {
        uint16_t ui_endpoint = static_cast<uint16_t>(SpinEndpoint->Value);
        if (uri_endpoint != 0 && uri_endpoint != ui_endpoint) {
            rx_reject_counter++;
            LogMessage(String().sprintf(L"RX ignored: URI endpoint %u not local endpoint %u", uri_endpoint, ui_endpoint));
            return;
        }
    } else {
        uri_endpoint = static_cast<uint16_t>(SpinEndpoint->Value);
    }

    bool is_data_ep_packet = (uri_endpoint != 0);
    if (!is_data_ep_packet) {
        LogMessage(String().sprintf(L"RX #%u from %S:%u (%u bytes)",
                                    rx_packet_counter,
                                    src_ip,
                                    ntohs(source_addr.sin_port),
                                    packet_len));
    }

    if (!keys_valid) {
        rx_reject_counter++;
        return;
    }

    const uint8_t* validation_key = SigNet::Node::SelectValidationKey(uri, manager_global_key, sender_key);
    if (!validation_key) {
        rx_reject_counter++;
        LogError("RX rejected: no validation key for URI.");
        return;
    }

    if (SigNet::Parse::VerifyPacketHMAC(uri, options, payload, payload_len, validation_key) != SigNet::SIGNET_SUCCESS) {
        rx_reject_counter++;
        LogError("RX rejected: HMAC verification failed.");
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
    bool needs_proactive_response = false;

    while (payload_reader.GetRemaining() >= 4) {
        SigNet::TLVBlock tlv;
        if (SigNet::Parse::ParseTLVBlock(payload_reader, tlv) != SigNet::SIGNET_SUCCESS) {
            break;
        }

        switch (tlv.type_id) {
            case SigNet::TID_LEVEL:
            {
                uint16_t uri_universe = 0;
                if (!SigNet::Node::ParseUniverseFromURI(uri, uri_universe)) {
                    break;
                }

                if (uri_universe != static_cast<uint16_t>(SpinEP1Universe->Value)) {
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
                if (HandlePollTLV(tlv)) {
                    if (tlv.length == 25 && tlv.value) {
                        last_poll_query_level = tlv.value[24];
                    }
                    needs_proactive_response = true;
                }
                break;
            }

            default:
            {
                if (!IsTidAllowedForIncomingEndpoint(tlv.type_id, uri_endpoint)) {
                    LogMessage(String().sprintf(L"RX ignored: TID 0x%04X not valid for endpoint %u", tlv.type_id, uri_endpoint));
                    break;
                }

                if (tlv.length == 0) {
                    if (!SigNet::Node::IsTidGetSupported(tlv.type_id)) {
                        LogMessage(String().sprintf(L"RX ignored: GET not supported for TID 0x%04X", tlv.type_id));
                        break;
                    }
                    HandleGetRequest(tlv.type_id);
                    needs_proactive_response = true;
                } else {
                    HandleSetRequest(tlv.type_id, tlv.value, tlv.length, true);
                    needs_proactive_response = true;
                }
                break;
            }
        }
    }

    if (needs_proactive_response) {
        SendProactiveResponse("manager poll/get/set trigger");
    }
}
//---------------------------------------------------------------------------

void TFormSigNetNode::UpdateStatusDisplay()
{
    // Placeholder - will be populated in Phase 2
}
//---------------------------------------------------------------------------

void TFormSigNetNode::ClearAllUIStaleFlags()
{
    node_user_data.root.tid_rt_supported_tids.ui_is_stale = false;
    node_user_data.root.tid_rt_endpoint_count.ui_is_stale = false;
    node_user_data.root.tid_rt_protocol_version.ui_is_stale = false;
    node_user_data.root.tid_rt_firmware_version.ui_is_stale = false;
    node_user_data.root.tid_rt_device_label.ui_is_stale = false;
    node_user_data.root.tid_rt_mult.ui_is_stale = false;
    node_user_data.root.tid_rt_identify.ui_is_stale = false;
    node_user_data.root.tid_rt_status.ui_is_stale = false;
    node_user_data.root.tid_rt_role_capability.ui_is_stale = false;
    node_user_data.root.tid_rt_reboot.ui_is_stale = false;
    node_user_data.root.tid_rt_model_name.ui_is_stale = false;
    node_user_data.root.tid_rt_scope.ui_is_stale = false;
    node_user_data.root.tid_rt_unprovision.ui_is_stale = false;
    node_user_data.root.tid_nw_mac_address.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv4_mode.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv4_address.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv4_netmask.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv4_gateway.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv4_current.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv6_mode.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv6_address.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv6_prefix.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv6_gateway.ui_is_stale = false;
    node_user_data.root.tid_nw_ipv6_current.ui_is_stale = false;
    node_user_data.root.tid_dg_security_event.ui_is_stale = false;
    node_user_data.root.tid_dg_message.ui_is_stale = false;

    node_user_data.ep1.tid_ep_universe.ui_is_stale = false;
    node_user_data.ep1.tid_ep_label.ui_is_stale = false;
    node_user_data.ep1.tid_ep_mult_override.ui_is_stale = false;
    node_user_data.ep1.tid_ep_capability.ui_is_stale = false;
    node_user_data.ep1.tid_ep_direction.ui_is_stale = false;
    node_user_data.ep1.tid_ep_input_priority.ui_is_stale = false;
    node_user_data.ep1.tid_ep_status.ui_is_stale = false;
    node_user_data.ep1.tid_ep_failover.ui_is_stale = false;
    node_user_data.ep1.tid_ep_dmx_timing.ui_is_stale = false;
    node_user_data.ep1.tid_ep_refresh_capability.ui_is_stale = false;
    node_user_data.ep1.tid_rdm_tod_data.ui_is_stale = false;
    node_user_data.ep1.tid_rdm_tod_background.ui_is_stale = false;
    node_user_data.ep1.tid_rdm_flow_control.ui_is_stale = false;
    node_user_data.ep1.tid_dg_level_foldback.ui_is_stale = false;
    node_user_data.ep1.tid_level.ui_is_stale = false;
    node_user_data.ep1.tid_priority.ui_is_stale = false;
    node_user_data.ep1.tid_sync.ui_is_stale = false;
}
//---------------------------------------------------------------------------

// SyncUIFromStaleBlobs
//
// Called from the receive timer.  For every blob where ui_is_stale is true
// (meaning the Manager / Sig-Net sent a SET that changed this value), update
// the corresponding UI control and clear the flag.
//
void TFormSigNetNode::SyncUIFromStaleBlobs()
{
    suppress_ui_change_events = true;

    if (node_user_data.root.tid_rt_device_label.ui_is_stale) {
        EditRootDeviceLabel->Text = String((const char*)node_user_data.root.tid_rt_device_label.data.text);
        node_user_data.root.tid_rt_device_label.ui_is_stale = false;
    }

    if (node_user_data.root.tid_rt_identify.ui_is_stale) {
        if (node_user_data.root.tid_rt_identify.length > 0) {
            int idx = node_user_data.root.tid_rt_identify.data.bytes[0] & 0x03;
            ComboRootIdentify->ItemIndex = idx;
        }
        node_user_data.root.tid_rt_identify.ui_is_stale = false;
    }

    if (node_user_data.root.tid_rt_scope.ui_is_stale) {
        if (node_user_data.root.tid_rt_scope.length > 0) {
            EditScope->Text = String((const char*)node_user_data.root.tid_rt_scope.data.text);
        }
        node_user_data.root.tid_rt_scope.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_universe.ui_is_stale) {
        if (node_user_data.ep1.tid_ep_universe.length >= 2) {
            uint16_t universe = ((uint16_t)node_user_data.ep1.tid_ep_universe.data.bytes[0] << 8) |
                                  node_user_data.ep1.tid_ep_universe.data.bytes[1];
            if (universe >= SigNet::MIN_UNIVERSE && universe <= SigNet::MAX_UNIVERSE) {
                SpinEP1Universe->Value = universe;
                RefreshReceiverGroups();
            }
        }
        node_user_data.ep1.tid_ep_universe.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_label.ui_is_stale) {
        EditEP1Label->Text = String((const char*)node_user_data.ep1.tid_ep_label.data.text);
        node_user_data.ep1.tid_ep_label.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_direction.ui_is_stale) {
        if (node_user_data.ep1.tid_ep_direction.length > 0) {
            int dir = node_user_data.ep1.tid_ep_direction.data.bytes[0] & 0x03;
            ComboEP1Direction->ItemIndex = dir;
            CBEp1RdmEnable->Checked = (node_user_data.ep1.tid_ep_direction.data.bytes[0] & SigNet::EP_DIR_RDM_ENABLE) != 0;
        }
        node_user_data.ep1.tid_ep_direction.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_ep_failover.ui_is_stale) {
        if (node_user_data.ep1.tid_ep_failover.length >= 3) {
            int mode = node_user_data.ep1.tid_ep_failover.data.bytes[0] & 0x07;
            ComboEP1Failover->ItemIndex = mode;
            if (mode == 3) {
                uint16_t scene = ((uint16_t)node_user_data.ep1.tid_ep_failover.data.bytes[1] << 8) |
                                   node_user_data.ep1.tid_ep_failover.data.bytes[2];
                if (scene >= 1 && scene <= 60000) {
                    SpinEP1FailoverScene->Value = scene;
                }
            }
            UpdateFailoverSceneVisibility();
        }
        node_user_data.ep1.tid_ep_failover.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_rdm_tod_background.ui_is_stale) {
        if (node_user_data.ep1.tid_rdm_tod_background.length > 0) {
            CBEp1RdmEnable->Checked = (node_user_data.ep1.tid_rdm_tod_background.data.bytes[0] != 0);
        }
        node_user_data.ep1.tid_rdm_tod_background.ui_is_stale = false;
    }

    if (node_user_data.ep1.tid_level.ui_is_stale) {
        UpdateEP1LevelPreview(node_user_data.ep1.tid_level.data.bytes,
                               node_user_data.ep1.tid_level.length);
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

    SigNet::TidDataBlob* root_blobs[] = {
        &node_user_data.root.tid_rt_supported_tids,
        &node_user_data.root.tid_rt_endpoint_count,
        &node_user_data.root.tid_rt_protocol_version,
        &node_user_data.root.tid_rt_firmware_version,
        &node_user_data.root.tid_rt_device_label,
        &node_user_data.root.tid_rt_mult,
        &node_user_data.root.tid_rt_identify,
        &node_user_data.root.tid_rt_status,
        &node_user_data.root.tid_rt_role_capability,
        &node_user_data.root.tid_rt_reboot,
        &node_user_data.root.tid_rt_model_name,
        &node_user_data.root.tid_rt_scope,
        &node_user_data.root.tid_rt_unprovision,
        &node_user_data.root.tid_nw_mac_address,
        &node_user_data.root.tid_nw_ipv4_mode,
        &node_user_data.root.tid_nw_ipv4_address,
        &node_user_data.root.tid_nw_ipv4_netmask,
        &node_user_data.root.tid_nw_ipv4_gateway,
        &node_user_data.root.tid_nw_ipv4_current,
        &node_user_data.root.tid_nw_ipv6_mode,
        &node_user_data.root.tid_nw_ipv6_address,
        &node_user_data.root.tid_nw_ipv6_prefix,
        &node_user_data.root.tid_nw_ipv6_gateway,
        &node_user_data.root.tid_nw_ipv6_current,
        &node_user_data.root.tid_dg_security_event,
        &node_user_data.root.tid_dg_message
    };
    SigNet::TidDataBlob* ep1_blobs[] = {
        &node_user_data.ep1.tid_ep_universe,
        &node_user_data.ep1.tid_ep_label,
        &node_user_data.ep1.tid_ep_mult_override,
        &node_user_data.ep1.tid_ep_capability,
        &node_user_data.ep1.tid_ep_direction,
        &node_user_data.ep1.tid_ep_input_priority,
        &node_user_data.ep1.tid_ep_status,
        &node_user_data.ep1.tid_ep_failover,
        &node_user_data.ep1.tid_ep_dmx_timing,
        &node_user_data.ep1.tid_ep_refresh_capability,
        &node_user_data.ep1.tid_rdm_tod_data,
        &node_user_data.ep1.tid_rdm_tod_background,
        &node_user_data.ep1.tid_rdm_flow_control,
        &node_user_data.ep1.tid_dg_level_foldback,
        &node_user_data.ep1.tid_level,
        &node_user_data.ep1.tid_priority,
        &node_user_data.ep1.tid_sync
    };

    enum { ROOT_BLOB_COUNT = (int)(sizeof(root_blobs) / sizeof(root_blobs[0])) };
    enum { EP1_BLOB_COUNT = (int)(sizeof(ep1_blobs) / sizeof(ep1_blobs[0])) };
    int i;

    bool root_stale = false;
    bool data_stale = false;

    for (i = 0; i < ROOT_BLOB_COUNT; ++i) {
        root_stale = root_stale || root_blobs[i]->manager_is_stale;
    }
    for (i = 0; i < EP1_BLOB_COUNT; ++i) {
        data_stale = data_stale || ep1_blobs[i]->manager_is_stale;
    }

    bool all_sent = true;

    if (root_stale) {
        if (!SendStaleResponseForEndpoint(0, "manager_is_stale timer flush [EP0]")) {
            all_sent = false;
        }
    }

    if (data_stale) {
        uint16_t ui_endpoint = static_cast<uint16_t>(SpinEndpoint->Value);
        if (!SendStaleResponseForEndpoint(ui_endpoint, "manager_is_stale timer flush [Data EP]")) {
            all_sent = false;
        }
    }

    if ((root_stale || data_stale) && all_sent) {
        ClearAllManagerStaleFlags();
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
    AnsiString scope = AnsiString(EditScope->Text.Trim());
    if (scope.IsEmpty() || scope.Length() > SigNet::SIGNET_URI_SCOPE_MAX_LENGTH) {
        LogError("Scope must be 1-32 UTF characters");
        return false;
    }
    if (scope.Pos("/") > 0) {
        LogError("Scope cannot contain '/'");
        return false;
    }

    int32_t rc = SigNet::CoAP::SetURIScope(scope.c_str());
    if (rc != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Invalid scope value (error %d)", rc));
        return false;
    }

    EditScope->Text = String(scope.c_str());
    return true;
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetNode::EditScopeChange(TObject *Sender)
{
    ApplyScopeFromUI();
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

bool TFormSigNetNode::ParseEndpointField(const String& text, uint16_t& endpoint_out)
{
    AnsiString token = AnsiString(text.Trim());
    return SigNet::Parse::ParseEndpointValue(token.c_str(), endpoint_out) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetNode::ParseMfgCodeFromUI(bool& ok_out)
{
    uint16_t parsed = 0;
    AnsiString token = AnsiString(EditAnnounceMfgCode->Text.Trim());
    ok_out = (SigNet::Parse::ParseHexWord(token.c_str(), parsed) == SigNet::SIGNET_SUCCESS);
    return ok_out ? parsed : 0;
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetNode::ParseProductVariantFromUI(bool& ok_out)
{
    uint16_t parsed = 0;
    AnsiString token = AnsiString(EditAnnounceProductVariant->Text.Trim());
    ok_out = (SigNet::Parse::ParseHexWord(token.c_str(), parsed) == SigNet::SIGNET_SUCCESS);
    return ok_out ? parsed : 0;
}
//---------------------------------------------------------------------------

void TFormSigNetNode::UpdateK0DependentControls()
{
    ButtonSendAnnounce->Enabled = k0_set;
    ButtonDeprovision->Enabled = true;
    PageControlNode->Enabled = keys_valid;
}
//---------------------------------------------------------------------------

void TFormSigNetNode::UpdateFailoverSceneVisibility()
{
    // Scene number spin only relevant when Failover = Play Scene (index 3)
    bool scene_active = (ComboEP1Failover->ItemIndex == 3);
    SpinEP1FailoverScene->Enabled = scene_active;
    LabelEP1FailoverScene->Enabled = scene_active;
}
//---------------------------------------------------------------------------
