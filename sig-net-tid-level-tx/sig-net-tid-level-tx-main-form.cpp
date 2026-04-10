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

#include "sig-net-tid-level-tx-main-form.h"
#include "..\sig-net-crypto.hpp"
#include "..\sig-net-parse.hpp"
#include "..\sig-net-parse.cpp"
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TFormSigNetTx *FormSigNetTx;

#define APP_VERSION_MAJOR 0
#define APP_VERSION_MINOR 4
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
__fastcall TFormSigNetTx::TFormSigNetTx(TComponent* Owner)
    : TForm(Owner)
{
    keys_valid = false;
    k0_set = false;
    dmx_slot_count = 512;
    endpoint = 1;
    session_id = 1;
    sequence_num = 1;
    message_id = 1;
    send_count = 0;
    error_count = 0;
    last_packet_size = 0;
    good_frames_since_bad = 0;
    udp_socket = INVALID_SOCKET;
    winsock_started = false;
    socket_initialized = false;
    rgb_r = 255;
    rgb_g = 0;
    rgb_b = 0;
    rgb_phase = 0;
    
    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));
    memset(dmx_buffer, 0, sizeof(dmx_buffer));
    memset(tuid, 0, sizeof(tuid));
}

bool TFormSigNetTx::EnsureSocketInitialized()
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

void TFormSigNetTx::ShutdownSocket()
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

void __fastcall TFormSigNetTx::FormCreate(TObject *Sender)
{
	Caption = String().sprintf(L"Sig-Net [TIDLevel Sender]   Copyright Singularity (UK) Ltd  V%d.%d",
                               APP_VERSION_MAJOR,
                               APP_VERSION_MINOR);

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

    EditAnnounceVersionNum->Text = IntToStr(APP_VERSION_ID);
	EditAnnounceVersionString->Text = "v0.15-test";
    EditAnnounceMfgCode->Text = String().sprintf(L"0x%04x", (unsigned int)((SigNet::SoemCodeSdkLevelTx >> 16) & 0xFFFF));
    EditAnnounceProductVariant->Text = String().sprintf(L"0x%04x", (unsigned int)(SigNet::SoemCodeSdkLevelTx & 0xFFFF));
    
    // Initialize device parameters with ephemeral TUID (fallback if generation fails).
    {
        const uint16_t mfg_code = static_cast<uint16_t>((SigNet::SoemCodeSdkLevelTx >> 16) & 0xFFFF);
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

    ComboBoxDmxMode->ItemIndex = 0;  // Manual
    EditBadFrameInterval->Text = "50";
    CheckInsertBadFrames->Checked = false;
    
    // Initialize auto-send timer (44 Hz = ~22.7 ms interval)
    TimerKeepAlive->Interval = 900;  // milliseconds
    TimerKeepAlive->Enabled = false;
    
    // Initialize DMX buffer to zero
    memset(dmx_buffer, 0, sizeof(dmx_buffer));
    
    // Create DMX fader controls (trackbars and labels)
    dmx_scroll_position = 0;
    for (int i = 0; i < 32; i++) {
        dmx_trackbars[i] = 0;
        dmx_labels[i] = 0;
    }
    CreateDMXFaderControls();
    PanelTrackbars->OnResize = PanelTrackbarsResize;
    SetLabelsTransparentRecursive(this);

    TimerHeartBeat->Enabled = false;
    TimerHeartBeat->Interval = 10;

    // K0-dependent controls start disabled until key derivation succeeds.
    UpdateK0DependentControls();

    EnsureSocketInitialized();
    WarnIfLoopbackSelected();
    
    LogMessage("Sig-Net Test Application initialized.");
    LogMessage("Click 'Select K0...' to configure the root key.");
    LogMessage("Announce packets are manual: use the Announce button.");
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::FormDestroy(TObject *Sender)
{
    ShutdownSocket();
    LogMessage("UDP socket closed.");
}
//---------------------------------------------------------------------------
void __fastcall TFormSigNetTx::ButtonSelectK0Click(TObject *Sender)
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
            
            keys_valid = true;
            k0_set = true;
            UpdateK0DependentControls();
            LogMessage("K0 selected and Ks/Kc derived successfully.");
            LogMessage("Ready to transmit TID_LEVEL and Announce packets.");
        } else {
            LogMessage("K0 selection cancelled.");
        }
    }
    __finally {
        delete dialog;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::ButtonSendLevelPacketClick(TObject *Sender)
{
    if (SendPacket()) {
        LogMessage(String().sprintf(L"Packet sent: seq=%u, size=%u bytes", 
                   sequence_num - 1, last_packet_size));
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::ButtonSendAnnounceClick(TObject *Sender)
{
    if (SendAnnouncePacket()) {
        LogMessage(String().sprintf(L"Announce packet sent: seq=%u, size=%u bytes",
                   sequence_num - 1, last_packet_size));
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::ComboBoxDmxModeChange(TObject *Sender)
{
    bool is_dynamic = (ComboBoxDmxMode->ItemIndex == 1);
    TimerHeartBeat->Enabled = is_dynamic;
    if (is_dynamic) {
        LogMessage("DMX mode: Dynamic");
    } else {
        LogMessage("DMX mode: Manual");
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::CheckKeepAliveClick(TObject *Sender)
{
    // Only arm if K0 has been set
    if (CheckKeepAlive->Checked && k0_set) {
        TimerKeepAlive->Enabled = true;
        LogMessage("Keep-Alive enabled (900 ms)");
    } else {
        TimerKeepAlive->Enabled = false;
        LogMessage("Keep-Alive disabled");
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::CheckInsertBadFramesClick(TObject *Sender)
{
    good_frames_since_bad = 0;
    if (CheckInsertBadFrames->Checked) {
        LogMessage("Insert Bad Frames enabled.");
    } else {
        LogMessage("Insert Bad Frames disabled.");
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::TimerKeepAliveTimer(TObject *Sender)
{
    // Timer fired � no level packet sent in the last 900 ms; send keep-alive
    if (k0_set) {
        SendPacket();
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::TimerHeartBeatTimer(TObject *Sender)
{
    if (ComboBoxDmxMode->ItemIndex != 1) {
        return;
    }

    // Cycle RGB: R->G, G->B, B->R
    if (rgb_phase == 0) {
        if (rgb_r > 0) rgb_r--;
        if (rgb_g < 255) rgb_g++;
        if (rgb_r == 0 && rgb_g == 255) rgb_phase = 1;
    } else if (rgb_phase == 1) {
        if (rgb_g > 0) rgb_g--;
        if (rgb_b < 255) rgb_b++;
        if (rgb_g == 0 && rgb_b == 255) rgb_phase = 2;
    } else {
        if (rgb_b > 0) rgb_b--;
        if (rgb_r < 255) rgb_r++;
        if (rgb_b == 0 && rgb_r == 255) rgb_phase = 0;
    }

    // Fill DMX buffer: 1,4,7...=R 2,5,8...=G 3,6,9...=B
    for (int i = 0; i < 512; i++) {
        int slot = i % 3;
        if (slot == 0) {
            dmx_buffer[i] = rgb_r;
        } else if (slot == 1) {
            dmx_buffer[i] = rgb_g;
        } else {
            dmx_buffer[i] = rgb_b;
        }
    }

    SyncTrackbarsFromBuffer();
    SendPacket();
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::ButtonSelfTestClick(TObject *Sender)
{
    TSelfTestResultsForm* form = new TSelfTestResultsForm(Application);
    form->ShowModal();
    delete form;
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::ButtonSelectNicClick(TObject *Sender)
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

void __fastcall TFormSigNetTx::ButtonDeprovisionClick(TObject *Sender)
{
    memset(k0_key, 0, sizeof(k0_key));
    memset(sender_key, 0, sizeof(sender_key));
    memset(citizen_key, 0, sizeof(citizen_key));

    keys_valid = false;
    k0_set = false;
    UpdateK0DependentControls();
    LogMessage("Device de-provisioned. Keys cleared; select K0 to re-provision.");
}
//---------------------------------------------------------------------------

// Send a SigNet packet
bool TFormSigNetTx::SendPacket()
{
    if (!keys_valid) {
        LogError("Cannot send - keys not derived. Click Select K0 and complete key setup.");
        error_count++;
        return false;
    }
    
    // Parse TUID from UI
    if (!ParseTUIDFromHex(EditTUID->Text.Trim())) {
        LogError("Invalid TUID - must be 12 hex characters");
        error_count++;
        return false;
    }
    
    // Get parameters from UI
    uint16_t universe = SpinUniverse->Value;
    uint16_t endpoint_val = static_cast<uint16_t>(SpinEndpoint->Value);
    if (endpoint_val < 1) {
        endpoint_val = 1;
        SpinEndpoint->Value = 1;
        LogMessage("Endpoint adjusted to 1 (minimum allowed).");
    }
    
    // Build packet
    SigNet::PacketBuffer buffer;
    int32_t result = SigNet::BuildDMXPacket(
        buffer,
        universe,
        dmx_buffer,
        dmx_slot_count,
        tuid,
        endpoint_val,
        0x0000,  // mfg_code (standard messages)
        session_id,
        sequence_num,
        sender_key,
        message_id
    );
    
    if (result != SigNet::SIGNET_SUCCESS) {
        LogError(String().sprintf(L"Failed to build packet: error %d", result));
        error_count++;
        return false;
    }

    bool inject_bad_frame = false;
    if (CheckInsertBadFrames->Checked) {
        int bad_interval = GetBadFrameInterval();
        if (bad_interval < 1) {
            bad_interval = 1;
        }
        if (good_frames_since_bad >= static_cast<uint32_t>(bad_interval)) {
            inject_bad_frame = true;
            if (!InjectBadFrame(buffer)) {
                LogError("Failed to build intentionally bad frame; sending normal frame.");
                inject_bad_frame = false;
            }
        }
    }
    
    last_packet_size = buffer.GetSize();
    
    // Calculate multicast address
    char multicast_ip[32];  // Larger buffer for safety
    memset(multicast_ip, 0, sizeof(multicast_ip));
    SigNet::CalculateMulticastAddress(universe, multicast_ip);

    bool transmit_success = true;

    if (!EnsureSocketInitialized()) {
        error_count++;
        return false;
    }
    
    // Send via Winsock UDP multicast
    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        // Set multicast source interface for non-loopback NICs only.
        // For loopback (127.x), let the OS pick the default interface; IP_MULTICAST_LOOP
        // on the receiver socket will deliver the packet back to this machine.
        char nic_ip[16];
        ResolveSenderNic(selected_nic_ip, EditNicIP, nic_ip, sizeof(nic_ip));
        bool loopback = (strncmp(nic_ip, "127.", 4) == 0);
        if (!loopback && nic_ip[0] != '\0') {
            struct in_addr iface_addr;
            iface_addr.s_addr = inet_addr(nic_ip);
            if (iface_addr.s_addr == INADDR_NONE) {
                LogError("Invalid selected NIC IP ('" + String(selected_nic_ip.c_str()) + "'); using OS default multicast interface.");
            } else {
                if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                               (char*)&iface_addr, sizeof(iface_addr)) == SOCKET_ERROR) {
                    int if_err = WSAGetLastError();
                    LogError(String().sprintf(L"IP_MULTICAST_IF failed: WSA error %d; using OS default interface", if_err));
                }
            }
        }

        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);
        dest_addr.sin_addr.s_addr = inet_addr(multicast_ip);
        
        int bytes_sent = sendto(
            udp_socket,
            (const char*)buffer.GetBuffer(),
            buffer.GetSize(),
            0,
            (sockaddr*)&dest_addr,
            sizeof(dest_addr)
        );
        
        if (bytes_sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEHOSTUNREACH && !loopback) {
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
                            (const char*)buffer.GetBuffer(),
                            buffer.GetSize(),
                            0,
                            (sockaddr*)&dest_addr,
                            sizeof(dest_addr)
                        );
                        if (bytes_sent != SOCKET_ERROR) {
                            selected_nic_ip = auto_ip;
                            EditNicIP->Text = String(auto_ip);
                            LogMessage("sendto() retry succeeded after NIC auto-correct to: " + String(auto_ip));
                        }
                    }
                }
            }

            // Retry once using default interface if a selected NIC route fails.
            if (bytes_sent == SOCKET_ERROR && !loopback) {
                struct in_addr any_addr;
                any_addr.s_addr = INADDR_ANY;
                setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                           (char*)&any_addr, sizeof(any_addr));

                bytes_sent = sendto(
                    udp_socket,
                    (const char*)buffer.GetBuffer(),
                    buffer.GetSize(),
                    0,
                    (sockaddr*)&dest_addr,
                    sizeof(dest_addr)
                );
                if (bytes_sent != SOCKET_ERROR) {
                    LogMessage("sendto() retry succeeded using default multicast interface.");
                }
            }

            if (bytes_sent == SOCKET_ERROR) {
                err = WSAGetLastError();
                LogError(String().sprintf(L"sendto() failed: WSA error %d", err));
                error_count++;
                transmit_success = false;
            }
        } else if (bytes_sent != buffer.GetSize()) {
            LogError(String().sprintf(L"Partial send: %d of %d bytes", bytes_sent, buffer.GetSize()));
            error_count++;
            transmit_success = false;
        }
    }
    
    if (!transmit_success) {
        return false;
    }

    if (CheckInsertBadFrames->Checked) {
        if (inject_bad_frame) {
            good_frames_since_bad = 0;
            LogMessage("Inserted intentionally bad frame (payload marker text + inverted HMAC).");
        } else {
            good_frames_since_bad++;
        }
    }
    
    // Increment counters
    send_count++;
    sequence_num = SigNet::IncrementSequence(sequence_num);
    message_id++;
    
    // Check for session rollover
    if (SigNet::ShouldIncrementSession(sequence_num)) {
        session_id++;
        sequence_num = 1;
        LogMessage(String().sprintf(L"Session rolled over to %u", session_id));
    }
    
    // Update UI
    EditSequence->Text = String().sprintf(L"%u", sequence_num);
    EditMessageID->Text = String().sprintf(L"%u", message_id);
    EditSessionID->Text = String().sprintf(L"%u", session_id);
    
    // Reset keep-alive timer: any successful send pushes it back to 900 ms
    if (k0_set && CheckKeepAlive->Checked) {
        TimerKeepAlive->Enabled = false;
        TimerKeepAlive->Enabled = true;
    }

    return true;
}
//---------------------------------------------------------------------------

bool TFormSigNetTx::SendAnnouncePacket()
{
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

    bool transmit_success = true;

    if (!EnsureSocketInitialized()) {
        error_count++;
        return false;
    }

    if (socket_initialized && udp_socket != INVALID_SOCKET) {
        // Set multicast source interface for non-loopback NICs only.
        char nic_ip[16];
        ResolveSenderNic(selected_nic_ip, EditNicIP, nic_ip, sizeof(nic_ip));
        bool loopback = (strncmp(nic_ip, "127.", 4) == 0);
        if (!loopback && nic_ip[0] != '\0') {
            struct in_addr iface_addr;
            iface_addr.s_addr = inet_addr(nic_ip);
            if (iface_addr.s_addr == INADDR_NONE) {
                LogError("Invalid selected NIC IP ('" + String(selected_nic_ip.c_str()) + "'); using OS default multicast interface.");
            } else {
                if (setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                               (char*)&iface_addr, sizeof(iface_addr)) == SOCKET_ERROR) {
                    int if_err = WSAGetLastError();
                    LogError(String().sprintf(L"IP_MULTICAST_IF failed: WSA error %d; using OS default interface", if_err));
                }
            }
        }

        sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(SigNet::SIGNET_UDP_PORT);
        dest_addr.sin_addr.s_addr = inet_addr(SigNet::MULTICAST_NODE_SEND_IP);

        int bytes_sent = sendto(
            udp_socket,
            (const char*)buffer.GetBuffer(),
            buffer.GetSize(),
            0,
            (sockaddr*)&dest_addr,
            sizeof(dest_addr)
        );

        if (bytes_sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEHOSTUNREACH && !loopback) {
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
                            (const char*)buffer.GetBuffer(),
                            buffer.GetSize(),
                            0,
                            (sockaddr*)&dest_addr,
                            sizeof(dest_addr)
                        );
                        if (bytes_sent != SOCKET_ERROR) {
                            selected_nic_ip = auto_ip;
                            EditNicIP->Text = String(auto_ip);
                            LogMessage("Announce retry succeeded after NIC auto-correct to: " + String(auto_ip));
                        }
                    }
                }
            }

            // Retry once using default interface if a selected NIC route fails.
            if (bytes_sent == SOCKET_ERROR && !loopback) {
                struct in_addr any_addr;
                any_addr.s_addr = INADDR_ANY;
                setsockopt(udp_socket, IPPROTO_IP, IP_MULTICAST_IF,
                           (char*)&any_addr, sizeof(any_addr));

                bytes_sent = sendto(
                    udp_socket,
                    (const char*)buffer.GetBuffer(),
                    buffer.GetSize(),
                    0,
                    (sockaddr*)&dest_addr,
                    sizeof(dest_addr)
                );
                if (bytes_sent != SOCKET_ERROR) {
                    LogMessage("Announce retry succeeded using default multicast interface.");
                }
            }

            if (bytes_sent == SOCKET_ERROR) {
                err = WSAGetLastError();
                LogError(String().sprintf(L"Announce sendto() failed: WSA error %d", err));
                error_count++;
                transmit_success = false;
            }
        }
        if (bytes_sent != buffer.GetSize()) {
            LogError(String().sprintf(L"Announce partial send: %d of %d bytes", bytes_sent, buffer.GetSize()));
            error_count++;
            transmit_success = false;
        }
    }

    if (!transmit_success) {
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
void TFormSigNetTx::UpdateStatusDisplay()
{
    // This would be called periodically to update statistics
    // For now, status is updated via LogMessage calls
}
//---------------------------------------------------------------------------

// Log info message
void TFormSigNetTx::LogMessage(const String& msg)
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
void TFormSigNetTx::LogError(const String& msg)
{
    LogMessage("ERROR: " + msg);
}
//---------------------------------------------------------------------------

void TFormSigNetTx::WarnIfLoopbackSelected()
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
bool TFormSigNetTx::ParseK0FromHex(const String& hex_string)
{
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseK0Hex(token.c_str(), k0_key) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

// Parse TUID from 12-character hex string
bool TFormSigNetTx::ParseTUIDFromHex(const String& hex_string)
{
    AnsiString token = AnsiString(hex_string.Trim());
    return SigNet::Parse::ParseTUIDHex(token.c_str(), tuid) == SigNet::SIGNET_SUCCESS;
}
//---------------------------------------------------------------------------

int TFormSigNetTx::GetBadFrameInterval()
{
    String text = EditBadFrameInterval->Text.Trim();
    int value = 50;

    try {
        value = StrToInt(text);
    }
    catch (...) {
        value = 50;
    }

    if (value < 1) {
        value = 1;
    }
    if (value > 1000000) {
        value = 1000000;
    }

    if (EditBadFrameInterval->Text != IntToStr(value)) {
        EditBadFrameInterval->Text = IntToStr(value);
    }

    return value;
}
//---------------------------------------------------------------------------

bool TFormSigNetTx::InjectBadFrame(SigNet::PacketBuffer& buffer)
{
    static const char* BAD_TEXT = "This is an intentionally bad HMAC.";
    uint8_t* packet = buffer.GetMutableBuffer();
    uint16_t packet_len = buffer.GetSize();
    uint16_t hmac_offset = 0;
    uint16_t hmac_len = 0;
    uint16_t payload_offset = packet_len;

    if (!SigNet::CoAP::FindCoapOptionAndPayload(packet, packet_len, SigNet::SIGNET_OPTION_HMAC,
                                                hmac_offset, hmac_len, payload_offset)) {
        return false;
    }

    if (hmac_len != SigNet::HMAC_SHA256_LENGTH) {
        return false;
    }

    for (uint16_t i = 0; i < hmac_len; i++) {
        packet[hmac_offset + i] = static_cast<uint8_t>(~packet[hmac_offset + i]);
    }

    if (payload_offset < packet_len) {
        uint16_t payload_len = static_cast<uint16_t>(packet_len - payload_offset);
        uint16_t marker_len = static_cast<uint16_t>(strlen(BAD_TEXT));
        uint16_t copy_len = (payload_len < marker_len) ? payload_len : marker_len;
        memset(packet + payload_offset, 0, payload_len);
        memcpy(packet + payload_offset, BAD_TEXT, copy_len);
    }

    return true;
}
//---------------------------------------------------------------------------

// Create DMX fader controls (512 trackbars with labels)
void TFormSigNetTx::CreateDMXFaderControls()
{
    for (int i = 0; i < DMX_VISIBLE_COUNT; i++) {
        // Trackbar (Tag = slot index 0-31)
        TTrackBar* tb = new TTrackBar(PanelTrackbars);
        tb->Parent = PanelTrackbars;
        tb->Min = 0;
        tb->Max = 255;
        tb->Position = 255 - dmx_buffer[i];
        tb->Orientation = trVertical;
        tb->Width = 20;
        tb->Height = 150;
        tb->Left = 0;
        tb->Top = 0;
        tb->TickStyle = tsNone;
        tb->Tag = i;  // Slot index (0-31); channel = Tag + dmx_scroll_position
        tb->OnChange = TrackBarDMXChange;
        
        // Label below trackbar showing channel number
        TLabel* lbl = new TLabel(PanelTrackbars);
        lbl->Parent = PanelTrackbars;
        lbl->Caption = IntToStr(i + 1);  // Will be updated on scroll
        lbl->Transparent = true;
        lbl->Font->Height = -10;
        lbl->AutoSize = false;
        lbl->Width = 20;
        lbl->Height = 14;
        lbl->Left = 0;
        lbl->Top = 0;
        lbl->Alignment = taCenter;
        
        dmx_trackbars[i] = tb;
        dmx_labels[i] = lbl;
    }

    LayoutDMXFaderControls();
    
    UpdateDMXFaderDisplay();
}
//---------------------------------------------------------------------------

void TFormSigNetTx::LayoutDMXFaderControls()
{
    if (!PanelTrackbars) {
        return;
    }

    const int LEFT_MARGIN = 8;
    const int RIGHT_MARGIN = 8;
    const int TOP_MARGIN = 4;
    const int SLOT_GAP = 2;
    const int LABEL_GAP = 4;
    const int LABEL_HEIGHT = 14;
    const int BOTTOM_MARGIN = 4;

    int available_width = PanelTrackbars->ClientWidth - LEFT_MARGIN - RIGHT_MARGIN - ((DMX_VISIBLE_COUNT - 1) * SLOT_GAP);
    if (available_width < DMX_VISIBLE_COUNT) {
        available_width = DMX_VISIBLE_COUNT;
    }

    int trackbar_height = PanelTrackbars->ClientHeight - TOP_MARGIN - LABEL_GAP - LABEL_HEIGHT - BOTTOM_MARGIN;
    if (trackbar_height < 40) {
        trackbar_height = 40;
    }

    int base_width = available_width / DMX_VISIBLE_COUNT;
    int extra_pixels = available_width % DMX_VISIBLE_COUNT;
    int x = LEFT_MARGIN;

    for (int i = 0; i < DMX_VISIBLE_COUNT; i++) {
        int width = base_width;
        if (i < extra_pixels) {
            width++;
        }

        if (dmx_trackbars[i]) {
            dmx_trackbars[i]->SetBounds(x, TOP_MARGIN, width, trackbar_height);
        }

        if (dmx_labels[i]) {
            dmx_labels[i]->SetBounds(x, TOP_MARGIN + trackbar_height + LABEL_GAP, width, LABEL_HEIGHT);
        }

        x += width + SLOT_GAP;
    }
}
//---------------------------------------------------------------------------

void __fastcall TFormSigNetTx::PanelTrackbarsResize(TObject *Sender)
{
    LayoutDMXFaderControls();
}
//---------------------------------------------------------------------------

// Update all 32 trackbar values and labels from the buffer at current offset
void TFormSigNetTx::UpdateDMXFaderDisplay()
{
    for (int i = 0; i < DMX_VISIBLE_COUNT; i++) {
        int channel = dmx_scroll_position + i;  // 0-based buffer index
        // Suppress OnChange while reloading values
        dmx_trackbars[i]->OnChange = NULL;
        dmx_trackbars[i]->Position = 255 - dmx_buffer[channel];
        dmx_trackbars[i]->OnChange = TrackBarDMXChange;
        dmx_labels[i]->Caption = IntToStr(channel + 1);  // 1-based display
    }
}
//---------------------------------------------------------------------------

// Handle scrollbar change � update internal offset and reload the 32 trackbars
void __fastcall TFormSigNetTx::ScrollBarDMXChange(TObject *Sender)
{
    dmx_scroll_position = ScrollBarDMX->Position;
    UpdateDMXFaderDisplay();
}
//---------------------------------------------------------------------------

// Handle trackbar change � Tag is slot 0-31; actual channel = slot + scroll offset
void __fastcall TFormSigNetTx::TrackBarDMXChange(TObject *Sender)
{
    if (ComboBoxDmxMode->ItemIndex != 0) {
        return;
    }

    TTrackBar* tb = dynamic_cast<TTrackBar*>(Sender);
    if (tb) {
        int channel = tb->Tag + dmx_scroll_position;
        if (channel >= 0 && channel < 512) {
            // Inverted UI mapping: 255 on slider equals 0 in DMX buffer
            dmx_buffer[channel] = static_cast<uint8_t>(255 - tb->Position);
            SendPacket();
        }
    }
}
//---------------------------------------------------------------------------

// Reload the 32 visible trackbars after a pattern change
void TFormSigNetTx::SyncTrackbarsFromBuffer()
{
    UpdateDMXFaderDisplay();
}
//---------------------------------------------------------------------------

void TFormSigNetTx::UpdateK0DependentControls()
{
    ButtonSendAnnounce->Enabled = k0_set;
    ButtonSendLevelPacket->Enabled = k0_set;
    ButtonDeprovision->Enabled = true;
    GroupBoxTransmit->Enabled = k0_set;
    GroupBoxDMXFaders->Enabled = k0_set;
    // Disarm keep-alive if K0 is no longer valid
    if (!k0_set) {
        TimerKeepAlive->Enabled = false;
        CheckKeepAlive->Checked = false;
        CheckInsertBadFrames->Checked = false;
        good_frames_since_bad = 0;
    }
}
//---------------------------------------------------------------------------
