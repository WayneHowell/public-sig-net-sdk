//==============================================================================
// Sig-Net Protocol Framework - Transmitter Application Implementation
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
// Description:  Implementation of Sig-Net TIDLevel transmitter main form.
//               Handles K0 validation, key derivation, DMX pattern generation,
//               packet building, hex dump display, and UDP transmission.
//==============================================================================

//---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "sig-net-poller-main-form.h"
#include "..\sig-net-crypto.hpp"
#include "..\sig-net-parse.hpp"
#include "..\sig-net-parse.cpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TFormSigNetPoller *FormSigNetPoller;

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 5
#define APP_VERSION_ID ((APP_VERSION_MAJOR << 8) | APP_VERSION_MINOR)

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

static bool ResolveSenderNic(AnsiString& selected_nic_ip, TEdit* nic_edit, char* out_ip, size_t out_len)
{
    if (!ExtractValidIPv4FromText(selected_nic_ip, out_ip, out_len)) {
        if (!(nic_edit && ExtractValidIPv4FromText(AnsiString(nic_edit->Text), out_ip, out_len))) {
            AnsiString auto_nic = SigNet::SelectDefaultStartupNicIP();
            if (!ExtractValidIPv4FromText(auto_nic, out_ip, out_len)) {
                strncpy(out_ip, "127.0.0.1", out_len - 1);
                out_ip[out_len - 1] = 0;
            }
        }
    }

    selected_nic_ip = out_ip;
    if (nic_edit) {
        nic_edit->Text = String(out_ip);
    }
    return true;
}

//---------------------------------------------------------------------------
__fastcall TFormSigNetPoller::TFormSigNetPoller(TComponent* Owner)
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

    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));
    memset(manager_global_key, 0, sizeof(manager_global_key));
    memset(tuid, 0, sizeof(tuid));
}

bool TFormSigNetPoller::EnsureSocketInitialized()
{
    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        return true;
    }

    if (!winsock_started) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            LogError(String().sprintf(L"WSAStartup failed: %d", result));
            return false;
        }
        winsock_started = true;
    }

    if (udp_socket != INVALID_SOCKET) {
        closesocket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket == INVALID_SOCKET) {
        LogError(String().sprintf(L"Socket creation failed: %d", WSAGetLastError()));
        return false;
    }

    sockaddr_in local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = 0;

    if (bind(udp_socket, (sockaddr*)&local_addr, sizeof(local_addr)) == SOCKET_ERROR) {
        LogMessage(String().sprintf(L"Socket bind failed: %d; continuing without explicit bind", WSAGetLastError()));
    }

    char loopback = 1;
    if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback)) == SOCKET_ERROR) {
        LogError(String().sprintf(L"Set loopback failed: %d", WSAGetLastError()));
    }

    unsigned char ttl = 16;
    if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_TTL, (char*)&ttl, sizeof(ttl)) == SOCKET_ERROR) {
        LogError(String().sprintf(L"Set TTL failed: %d", WSAGetLastError()));
    }

    int broadcast = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));

    socket_initialized = true;
    LogMessage("UDP socket initialized successfully.");
    return true;
}

void TFormSigNetPoller::ShutdownSocket()
{
    if (udp_socket != INVALID_SOCKET) {
        closesocket(udp_socket);
        udp_socket = INVALID_SOCKET;
    }

    socket_initialized = false;

    if (winsock_started) {
        WSACleanup();
        winsock_started = false;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::FormCreate(TObject *Sender)
{
	Caption = String().sprintf(L"Sig-Net [TID_POLL Transmitter]   Copyright Singularity (UK) Ltd  V%d.%d",
                               APP_VERSION_MAJOR,
                               APP_VERSION_MINOR);

    srand(static_cast<unsigned int>(GetTickCount()));

    // Initialize NIC selection with preferred physical NIC.
    selected_nic_ip = SigNet::SelectDefaultStartupNicIP();
    if (selected_nic_ip.IsEmpty()) {
        selected_nic_ip = "127.0.0.1";
    }
    {
        char nic_ip[16];
        ResolveSenderNic(selected_nic_ip, EditNicIP, nic_ip, sizeof(nic_ip));
    }
    EditNicIP->ReadOnly = true;

    EditScope->Text = String(SigNet::CoAP::GetURIScope());
    ApplyScopeFromUI();

    EditAnnounceVersionNum->Text = IntToStr(APP_VERSION_ID);
	EditAnnounceVersionString->Text = "v0.16 Spec";
    EditAnnounceMfgCode->Text = String().sprintf(L"0x%04x", (unsigned int)((SigNet::SoemCodeSdkPoller >> 16) & 0xFFFF));
    EditAnnounceProductVariant->Text = String().sprintf(L"0x%04x", (unsigned int)(SigNet::SoemCodeSdkPoller & 0xFFFF));
    
    // Initialize device parameters with ephemeral TUID (fallback if generation fails).
    {
        const uint16_t mfg_code = static_cast<uint16_t>((SigNet::SoemCodeSdkPoller >> 16) & 0xFFFF);
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

    EditPollTuidLo->Text = "0x000000000000";
    EditPollTuidHi->Text = "0xffffffffffff";
    EditPollEndpoint->Text = "65535";
    ComboPollQueryLevel->ItemIndex = 0;

    SpinPollRepeatMs->MinValue = 10;
    SpinPollRepeatMs->MaxValue = 10000;
    SpinPollRepeatMs->Value = 3000;
    SpinPollJitterMs->MinValue = 0;
    SpinPollJitterMs->MaxValue = 1000;
    SpinPollJitterMs->Value = 1000;
    CheckPollRepeat->Checked = false;
    CheckPollEnableJitter->Checked = false;

    TimerPollRepeat->Enabled = false;
    TimerPollRepeat->Interval = 3000;

    SetLabelsTransparentRecursive(this);

    // K0-dependent controls start disabled until key derivation succeeds.
    UpdateK0DependentControls();

    EnsureSocketInitialized();
    WarnIfLoopbackSelected();
    
    LogMessage("Sig-Net Poller initialized.");
    LogMessage("Click 'Provision' to configure the root key.");
    LogMessage("TID_POLL can be sent manually or by repeat timer.");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::FormDestroy(TObject *Sender)
{
    ShutdownSocket();
    LogMessage("UDP socket closed.");
}
//---------------------------------------------------------------------------
void __fastcall TFormSigNetPoller::ButtonSelectK0Click(TObject *Sender)
{
    // Parse TUID from UI so dialog can derive Manager Local key
    if (!ParseTUIDFromHex(EditTUID->Text)) {
        LogError("Invalid TUID - cannot open K0 dialog");
        return;
    }
    
    // Open K0 entry dialog
    TK0EntryDialog *dialog = new TK0EntryDialog(this);
    dialog->SetTUID(tuid);
    
    try {
        if (dialog->ShowModal() == mrOk) {
            // Get K0 from dialog
            dialog->GetK0(k0_key);
            
            // Derive keys required by this test application
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
            LogMessage("K0 selected and Ks/Kc/Km_global derived successfully.");
            LogMessage("Ready to transmit TID_POLL and Announce packets.");
        } else {
            LogMessage("K0 selection cancelled.");
        }
    }
    __finally {
        delete dialog;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::ButtonSendPollClick(TObject *Sender)
{
    if (SendPollPacket()) {
        LogMessage(String().sprintf(L"TID_POLL sent: seq=%u, size=%u bytes", 
                   sequence_num - 1, last_packet_size));
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::ButtonSendAnnounceClick(TObject *Sender)
{
    if (SendAnnouncePacket()) {
        LogMessage(String().sprintf(L"Announce packet sent: seq=%u, size=%u bytes",
                   sequence_num - 1, last_packet_size));
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::CheckPollRepeatClick(TObject *Sender)
{
    if (CheckPollRepeat->Checked && k0_set) {
        RearmPollTimer();
        LogMessage(String().sprintf(L"Repeat TID_POLL enabled (%u ms base)", GetPollRepeatMs()));
    } else {
        TimerPollRepeat->Enabled = false;
        LogMessage("Repeat TID_POLL disabled");
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::TimerPollRepeatTimer(TObject *Sender)
{
    TimerPollRepeat->Enabled = false;
    if (!k0_set || !CheckPollRepeat->Checked) {
        return;
    }
    if (SendPollPacket()) {
        LogMessage(String().sprintf(L"TID_POLL sent (repeat): seq=%u, size=%u bytes",
                   sequence_num - 1, last_packet_size));
    }
    RearmPollTimer();
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::ButtonSelfTestClick(TObject *Sender)
{
    TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
    form->ShowModal();
    delete form;
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::ButtonSelectNicClick(TObject *Sender)
{
    TNicSelectDialog* dlg = new TNicSelectDialog(Application);
    dlg->SetCurrentIP(selected_nic_ip);
    try {
        if (dlg->ShowModal() == mrOk) {
            selected_nic_ip = dlg->GetSelectedIP();
            EditNicIP->Text = String(selected_nic_ip.c_str());
            LogMessage("Sender interface set to: " + String(selected_nic_ip.c_str()));
            WarnIfLoopbackSelected();
        }
    }
    __finally {
        delete dlg;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetPoller::ButtonDeprovisionClick(TObject *Sender)
{
    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));
    memset(manager_global_key, 0, sizeof(manager_global_key));

    keys_valid = false;
    k0_set = false;
    UpdateK0DependentControls();
    LogMessage("Device de-provisioned. Keys cleared; select K0 to re-provision.");
}
//---------------------------------------------------------------------------

bool TFormSigNetPoller::SendRawPacket(const uint8_t* packet, uint16_t packet_len, const char* destination_ip, const String& context_label)
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
    ResolveSenderNic(selected_nic_ip, EditNicIP, nic_ip, sizeof(nic_ip));
    bool loopback = (strncmp(nic_ip, "127.", 4) == 0);
    if (!loopback && nic_ip[0] != '\0') {
        struct in_addr iface_addr;
        iface_addr.s_addr = inet_addr(nic_ip);
        if (iface_addr.s_addr == INADDR_NONE) {
            LogError(context_label + ": invalid selected NIC IP ('" + String(selected_nic_ip.c_str()) + "'); using OS default multicast interface.");
        } else {
            if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                           (char*)&iface_addr, sizeof(iface_addr)) == SOCKET_ERROR) {
                int if_err = WSAGetLastError();
                    LogError(context_label + String().sprintf(L": IP_MULTICAST_IF failed: WSA error %d; using OS default interface", if_err));
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
        int err = WSAGetLastError();
        if (err == WSAEHOSTUNREACH) {
            AnsiString auto_nic = SigNet::SelectDefaultStartupNicIP();
            char auto_ip[16];
            auto_ip[0] = 0;
            if (ExtractValidIPv4FromText(auto_nic, auto_ip, sizeof(auto_ip)) && strncmp(auto_ip, "127.", 4) != 0) {
                struct in_addr auto_iface_addr;
                auto_iface_addr.s_addr = inet_addr(auto_ip);
                if (auto_iface_addr.s_addr != INADDR_NONE &&
                    setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                               (char*)&auto_iface_addr, sizeof(auto_iface_addr)) != SOCKET_ERROR) {
                    bytes_sent = sendto(
                        udp_socket,
                        (const char*)packet,
                        packet_len,
                        0,
                        (sockaddr*)&dest_addr,
                        sizeof(dest_addr)
                    );
                    if (bytes_sent != SOCKET_ERROR) {
                        selected_nic_ip = auto_ip;
                        EditNicIP->Text = String(auto_ip);
                        LogMessage(context_label + ": retry succeeded after NIC auto-correct to: " + String(auto_ip));
                    }
                }
            }
        }
    }

    if (bytes_sent == SOCKET_ERROR && !loopback) {
        struct in_addr any_addr;
        any_addr.s_addr = INADDR_ANY;
        setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                   (char*)&any_addr, sizeof(any_addr));

        bytes_sent = sendto(
            udp_socket,
            (const char*)packet,
            packet_len,
            0,
            (sockaddr*)&dest_addr,
            sizeof(dest_addr)
        );
        if (bytes_sent != SOCKET_ERROR) {
            LogMessage(context_label + ": retry succeeded using default multicast interface.");
        }
    }

    if (bytes_sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        LogError(context_label + String().sprintf(L": sendto() failed: WSA error %d", err));
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

bool TFormSigNetPoller::SendPollPacket()
{
    if (!ApplyScopeFromUI()) {
        return false;
    }

    if (!keys_valid) {
        LogError("Cannot send TID_POLL - keys not derived. Click Select K0 and complete key setup.");
        error_count++;
        return false;
    }

    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Invalid manager TUID - must be 12 hex characters");
        error_count++;
        return false;
    }

    uint8_t tuid_lo[6];
    uint8_t tuid_hi[6];
    if (!ParseHexTUIDField(EditPollTuidLo->Text.Trim(), tuid_lo)) {
        LogError("Invalid TUID_LO - must be 12 hex characters");
        error_count++;
        return false;
    }
    if (!ParseHexTUIDField(EditPollTuidHi->Text.Trim(), tuid_hi)) {
        LogError("Invalid TUID_HI - must be 12 hex characters");
        error_count++;
        return false;
    }

    uint16_t target_endpoint = 0xFFFF;
    if (!ParseEndpointField(EditPollEndpoint->Text.Trim(), target_endpoint)) {
        LogError("Invalid poll endpoint - use decimal or hex (0xFFFF)");
        error_count++;
        return false;
    }

    bool parse_ok = true;
    uint16_t mfg_code = ParseMfgCodeFromUI(parse_ok);
    if (!parse_ok) {
        LogError("Manufacturer code must be valid hex (e.g. 534C or 0x534C)");
        error_count++;
        return false;
    }
    uint16_t product_variant_id = ParseProductVariantFromUI(parse_ok);
    if (!parse_ok) {
        LogError("Product variant ID must be valid hex (e.g. 0001)");
        error_count++;
        return false;
    }

    uint8_t query_level = GetSelectedQueryLevel();

    SigNet::PacketBuffer buffer;
    int32_t result = SigNet::BuildPollPacket(
        buffer,
        tuid,
        mfg_code,
        product_variant_id,
        tuid_lo,
        tuid_hi,
        target_endpoint,
        query_level,
        session_id,
        sequence_num,
        manager_global_key,
        message_id
    );

    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Failed to build TID_POLL packet: error %d", result));
        error_count++;
        return false;
    }

    last_packet_size = buffer.GetSize();
    if (!SendRawPacket(buffer.GetBuffer(), buffer.GetSize(), SigNet::MULTICAST_MANAGER_POLL_IP, "TID_POLL")) {
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

bool TFormSigNetPoller::SendAnnouncePacket()
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

    // Protocol major is v1 in current implementation.
    const uint8_t protocol_version = 0x01;
    // Test sender app advertises Sender role.
    const uint8_t role_capability_bits = 0x02;
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

// Update status display
void TFormSigNetPoller::UpdateStatusDisplay()
{
    // This would be called periodically to update statistics
    // For now, status is updated via LogMessage calls
}
//---------------------------------------------------------------------------

// Log info message
void TFormSigNetPoller::LogMessage(const String& msg)
{
    String timestamp = FormatDateTime("hh:nn:ss", Now());
    MemoStatus->Lines->BeginUpdate();
    MemoStatus->Lines->Add("[" + timestamp + "] " + msg);

    // Limit to 100 lines
    while (MemoStatus->Lines->Count > 100) {
        MemoStatus->Lines->Delete(0);
    }
    MemoStatus->Lines->EndUpdate();

    // Auto-scroll to bottom
    MemoStatus->SelStart = MemoStatus->GetTextLen();
    MemoStatus->SelLength = 0;
    MemoStatus->Perform(EM_SCROLLCARET, 0, 0);
    MemoStatus->Perform(WM_VSCROLL, SB_BOTTOM, 0);
}
//---------------------------------------------------------------------------

// Log error message
void TFormSigNetPoller::LogError(const String& msg)
{
    LogMessage("ERROR: " + msg);
}
//---------------------------------------------------------------------------

bool TFormSigNetPoller::ApplyScopeFromUI()
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

void __fastcall TFormSigNetPoller::EditScopeChange(TObject *Sender)
{
    ApplyScopeFromUI();
}
//---------------------------------------------------------------------------

void TFormSigNetPoller::WarnIfLoopbackSelected()
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

// Parse K0 from 64-character hex string
bool TFormSigNetPoller::ParseK0FromHex(const String& hex_string)
{
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseK0Hex(token.c_str(), k0_key) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

// Parse TUID from 12-character hex string
bool TFormSigNetPoller::ParseTUIDFromHex(const String& hex_string)
{
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseTUIDHex(token.c_str(), tuid) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

bool TFormSigNetPoller::ParseHexTUIDField(const String& hex_string, uint8_t out_tuid[6])
{
    if (!out_tuid) {
        return false;
    }
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseTUIDHex(token.c_str(), out_tuid) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

bool TFormSigNetPoller::ParseEndpointField(const String& text, uint16_t& endpoint_out)
{
    AnsiString token = AnsiString(text.Trim());
    return SigNet::Parse::ParseEndpointValue(token.c_str(), endpoint_out) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetPoller::GetPollRepeatMs()
{
    int value = SpinPollRepeatMs->Value;
    if (value < 10) {
        value = 10;
    }
    if (value > 10000) {
        value = 10000;
    }
    SpinPollRepeatMs->Value = value;
    return static_cast<uint16_t>(value);
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetPoller::GetPollJitterMs()
{
    int value = SpinPollJitterMs->Value;
    if (value < 0) {
        value = 0;
    }
    if (value > 1000) {
        value = 1000;
    }
    SpinPollJitterMs->Value = value;
    return static_cast<uint16_t>(value);
}
//---------------------------------------------------------------------------

uint8_t TFormSigNetPoller::GetSelectedQueryLevel()
{
    switch (ComboPollQueryLevel->ItemIndex) {
    case 1:
        return SigNet::QUERY_CONFIG;
    case 2:
        return SigNet::QUERY_FULL;
    case 3:
        return SigNet::QUERY_EXTENDED;
    default:
        return SigNet::QUERY_HEARTBEAT;
    }
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetPoller::ParseMfgCodeFromUI(bool& ok_out)
{
    uint16_t parsed = 0;
    AnsiString token = AnsiString(EditAnnounceMfgCode->Text.Trim());
    ok_out = (SigNet::Parse::ParseHexWord(token.c_str(), parsed) == SigNet::SIGNET_SUCCESS);
    return ok_out ? parsed : 0;
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetPoller::ParseProductVariantFromUI(bool& ok_out)
{
    uint16_t parsed = 0;
    AnsiString token = AnsiString(EditAnnounceProductVariant->Text.Trim());
    ok_out = (SigNet::Parse::ParseHexWord(token.c_str(), parsed) == SigNet::SIGNET_SUCCESS);
    return ok_out ? parsed : 0;
}
//---------------------------------------------------------------------------

uint16_t TFormSigNetPoller::ComputeNextPollIntervalMs()
{
    uint16_t interval = GetPollRepeatMs();
    if (!CheckPollEnableJitter->Checked) {
        return interval;
    }

    uint16_t jitter = GetPollJitterMs();
    if (jitter == 0) {
        return interval;
    }

    uint16_t jitter_add = static_cast<uint16_t>(rand() % (static_cast<int>(jitter) + 1));
    uint32_t next_interval = static_cast<uint32_t>(interval) + static_cast<uint32_t>(jitter_add);
    if (next_interval > 65535U) {
        next_interval = 65535U;
    }
    return static_cast<uint16_t>(next_interval);
}
//---------------------------------------------------------------------------

void TFormSigNetPoller::RearmPollTimer()
{
    TimerPollRepeat->Enabled = false;
    TimerPollRepeat->Interval = ComputeNextPollIntervalMs();
    TimerPollRepeat->Enabled = (CheckPollRepeat->Checked && k0_set);
}
//---------------------------------------------------------------------------

void TFormSigNetPoller::UpdateK0DependentControls()
{
    ButtonSendAnnounce->Enabled = k0_set;
    ButtonSendPoll->Enabled = k0_set;
    ButtonDeprovision->Enabled = true;
    GroupBoxTransmit->Enabled = k0_set;

    if (!k0_set) {
        TimerPollRepeat->Enabled = false;
        CheckPollRepeat->Checked = false;
    }
}
//---------------------------------------------------------------------------
