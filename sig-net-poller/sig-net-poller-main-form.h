//==============================================================================
// Sig-Net Protocol Framework - Transmitter Application Main Form
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
// Description:  Main form header for Sig-Net TIDLevel transmitter application.
//               VCL form with controls for K0 entry, key derivation, universe
//               selection, DMX test patterns, and packet transmission.
//==============================================================================

//---------------------------------------------------------------------------

#ifndef SigNetExamplePollerMainFormH
#define SigNetExamplePollerMainFormH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.ComCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.ExtCtrls.hpp>
#include <Vcl.Samples.Spin.hpp>
#include <winsock2.h>
#include <ws2tcpip.h>

// IPWorks UDP component
// Note: Include your IPWorks header here when available
// #include "ipwudp.h"

// Sig-Net library
#include "sig-net.hpp"

// K0 Entry Dialog
#include "..\sig-net-passcode\K0EntryDialog.h"

// Self-Test Results Dialog
#include "..\sig-net-self-test-dialog\SelfTestResultsForm.h"

// NIC Selection Dialog
#include "..\sig-net-nic\NicSelectDialog.h"

//---------------------------------------------------------------------------
class TFormSigNetPoller : public TForm
{
__published:	// IDE-managed Components
    TPanel *PanelMain;
    TGroupBox *FroupBoxConfig;
    TButton *ButtonSelectK0;
    TButton *ButtonDeprovision;
    TLabel *LabelNicIP;
    TEdit *EditNicIP;
    TButton *ButtonSelectNic;

    TGroupBox *GroupBoxAnnounce;
    TLabel *LabelAnnounceVersionNum;
    TEdit *EditAnnounceVersionNum;
    TLabel *LabelAnnounceVersionString;
    TEdit *EditAnnounceVersionString;
    TLabel *LabelAnnounceMfgCode;
    TEdit *EditAnnounceMfgCode;
    TLabel *LabelAnnounceProductVariant;
    TEdit *EditAnnounceProductVariant;
    TButton *ButtonSendAnnounce;
    
    TGroupBox *GroupBoxDevice;
    TLabel *LabelTUID;
    TEdit *EditTUID;
    TLabel *LabelEndpoint;
    TSpinEdit *SpinEndpoint;
    TLabel *LabelUniverse;
    TSpinEdit *SpinUniverse;
    
    TGroupBox *GroupBoxSession;
    TLabel *LabelSessionID;
    TEdit *EditSessionID;
    TLabel *LabelSequence;
    TEdit *EditSequence;
    TLabel *LabelMessageID;
    TEdit *EditMessageID;
    
    TGroupBox *GroupBoxTransmit;
    TLabel *LabelPollRepeatMs;
    TLabel *LabelPollJitterMs;
    TLabel *LabelPollTuidLo;
    TLabel *LabelPollTuidHi;
    TLabel *LabelPollEndpoint;
    TLabel *LabelPollQueryLevel;
    TSpinEdit *SpinPollRepeatMs;
    TSpinEdit *SpinPollJitterMs;
    TEdit *EditPollTuidLo;
    TEdit *EditPollTuidHi;
    TEdit *EditPollEndpoint;
    TComboBox *ComboPollQueryLevel;
    TButton *ButtonSendPoll;
    TCheckBox *CheckPollRepeat;
    TCheckBox *CheckPollEnableJitter;
    TTimer *TimerPollRepeat;
    
    TGroupBox *GroupBoxStatus;
    TMemo *MemoStatus;
	TButton *ButtonSelfTest;
    TLabel *LabelScope;
    TEdit *EditScope;

    // IPWorks UDP component (placeholder - add when component available)
    // TipwUDPPort *UDPPort;
    
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall FormDestroy(TObject *Sender);
    void __fastcall ButtonSelectK0Click(TObject *Sender);
    void __fastcall ButtonSendPollClick(TObject *Sender);
    void __fastcall ButtonSendAnnounceClick(TObject *Sender);
    void __fastcall CheckPollRepeatClick(TObject *Sender);
    void __fastcall TimerPollRepeatTimer(TObject *Sender);
    void __fastcall ButtonSelfTestClick(TObject *Sender);
    void __fastcall ButtonSelectNicClick(TObject *Sender);
    void __fastcall ButtonDeprovisionClick(TObject *Sender);
    void __fastcall EditScopeChange(TObject *Sender);

private:	// User declarations
    // Cryptographic keys
    uint8_t k0_key[32];
    uint8_t sender_key[32];
    uint8_t citizen_key[32];
    uint8_t manager_global_key[32];
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
    AnsiString selected_nic_ip;  // Source IP for multicast interface binding

    // Private methods
    void UpdateStatusDisplay();
    void LogMessage(const String& msg);
    void LogError(const String& msg);
    bool ApplyScopeFromUI();
    bool ParseK0FromHex(const String& hex_string);
    bool ParseTUIDFromHex(const String& hex_string);
    bool ParseHexTUIDField(const String& hex_string, uint8_t out_tuid[6]);
    bool ParseEndpointField(const String& text, uint16_t& endpoint_out);
    uint16_t GetPollRepeatMs();
    uint16_t GetPollJitterMs();
    uint8_t GetSelectedQueryLevel();
    uint16_t ParseMfgCodeFromUI(bool& ok_out);
    uint16_t ParseProductVariantFromUI(bool& ok_out);
    uint16_t ComputeNextPollIntervalMs();
    void RearmPollTimer();
    bool EnsureSocketInitialized();
    void ShutdownSocket();
    bool SendRawPacket(const uint8_t* packet, uint16_t packet_len, const char* destination_ip, const String& context_label);
    bool SendPollPacket();
    bool SendAnnouncePacket();
    void WarnIfLoopbackSelected();
    void UpdateK0DependentControls();
    
public:		// User declarations
    __fastcall TFormSigNetPoller(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TFormSigNetPoller *FormSigNetPoller;
//---------------------------------------------------------------------------
#endif
