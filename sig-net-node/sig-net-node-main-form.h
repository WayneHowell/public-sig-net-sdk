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
#include <Vcl.CheckLst.hpp>
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

    // -------------------------------------------------------------------------
    // GroupBoxAnnounce - On-boot announce packet test
    // -------------------------------------------------------------------------
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

    // -------------------------------------------------------------------------
    // GroupBoxDevice - Device / TUID parameters
    // -------------------------------------------------------------------------
    TGroupBox *GroupBoxDevice;
    TLabel *LabelTUID;
    TEdit *EditTUID;
    TLabel *LabelEndpoint;
    TSpinEdit *SpinEndpoint;
    TLabel *LabelUniverse;
    TSpinEdit *SpinUniverse;

    // -------------------------------------------------------------------------
    // GroupBoxSession - Session / sequence counters
    // -------------------------------------------------------------------------
    TGroupBox *GroupBoxSession;
    TLabel *LabelSessionID;
    TEdit *EditSessionID;
    TLabel *LabelSequence;
    TEdit *EditSequence;
    TLabel *LabelMessageID;
    TEdit *EditMessageID;

    // -------------------------------------------------------------------------
    // PageControlNode - Tab 1: Root EP (Mandated), Tab 2: Root EP (Optional),
    // Tab 3: EP1 (Virtual)
    // -------------------------------------------------------------------------
    TPageControl *PageControlNode;

    // --- Tab: Root EP (Mandated) ---------------------------------------------
    TTabSheet *TabSheetRoot;

    TGroupBox *GroupBoxRootIdentity;
    TLabel *LabelRootDeviceLabel;
    TEdit *EditRootDeviceLabel;
    TButton *ButtonSetDeviceLabel;
    TLabel *LabelRootSoemCode;
    TEdit *EditRootSoemCode;
    TLabel *LabelRootProtVersion;
    TEdit *EditRootProtVersion;
    TLabel *LabelRootFirmware;
    TEdit *EditRootFirmwareID;
    TEdit *EditRootFirmwareStr;
    TLabel *LabelRootModelName;
    TEdit *EditRootModelName;

    TGroupBox *GroupBoxRootState;
    TLabel *LabelRootIdentify;
    TComboBox *ComboRootIdentify;
    TLabel *LabelRootStatus;
    TCheckBox *CBStatusHwFault;
    TCheckBox *CBStatusFactoryBoot;
    TCheckBox *CBStatusConfigLock;
    TLabel *LabelRootEndpCount;
    TEdit *EditRootEndpCount;
    TLabel *LabelRootRoles;
    TCheckBox *CBRoleNode;
    TCheckBox *CBRoleSender;
    TCheckBox *CBRoleManager;

    TGroupBox *GroupBoxRootMulticast;
    TLabel *LabelRootMultState;
    TEdit *EditRootMultState;
    TLabel *LabelRootSupportedTids;
    TButton *ButtonSupportedTidsNone;
    TButton *ButtonSupportedTidsMandated;
    TButton *ButtonSupportedTidsAll;
    TCheckListBox *CheckListRootSupportedTids;

    // --- Tab: Root EP (Optional) ---------------------------------------------
    TTabSheet *TabSheetRootOptional;
    TGroupBox *GroupBoxRootOptional;

    TGroupBox *GroupBoxRootIPv4;
    TLabel *LabelRootMac;
    TEdit *EditRootMac;
    TLabel *LabelRootIpv4Mode;
    TComboBox *ComboRootIpv4Mode;
    TLabel *LabelRootIpv4Addr;
    TEdit *EditRootIpv4Addr;
    TLabel *LabelRootIpv4Mask;
    TEdit *EditRootIpv4Mask;
    TLabel *LabelRootIpv4Gateway;
    TEdit *EditRootIpv4Gateway;
    TLabel *LabelRootIpv4Current;
    TEdit *EditRootIpv4Current;

    TGroupBox *GroupBoxRootIPv6;
    TLabel *LabelRootIpv6Mode;
    TComboBox *ComboRootIpv6Mode;
    TLabel *LabelRootIpv6Addr;
    TEdit *EditRootIpv6Addr;
    TLabel *LabelRootIpv6Prefix;
    TSpinEdit *SpinRootIpv6Prefix;
    TLabel *LabelRootIpv6Gateway;
    TEdit *EditRootIpv6Gateway;
    TLabel *LabelRootIpv6Current;
    TEdit *EditRootIpv6Current;

    // --- Tab: EP1 (Virtual) --------------------------------------------------
    TTabSheet *TabSheetEP1;
    TTabSheet *TabSheetEP1RDM;

    TGroupBox *GroupBoxEP1TIDs;
    TLabel *LabelEP1Universe;
    TSpinEdit *SpinEP1Universe;
    TLabel *LabelEP1Label;
    TEdit *EditEP1Label;
    TLabel *LabelEP1Direction;
    TComboBox *ComboEP1Direction;
    TCheckBox *CBEp1RdmEnable;
    TLabel *LabelEP1Capability;
    TCheckBox *CBCapConsumeLevel;
    TCheckBox *CBCapSupplyLevel;
    TCheckBox *CBCapConsumeRDM;
    TCheckBox *CBCapSupplyRDM;
    TCheckBox *CBCapVirtual;
    TLabel *LabelEP1Status;
    TEdit *EditEP1Status;
    TLabel *LabelEP1Failover;
    TComboBox *ComboEP1Failover;
    TLabel *LabelEP1FailoverScene;
    TSpinEdit *SpinEP1FailoverScene;
    TLabel *LabelEP1MultOverride;
    TEdit *EditEP1MultOverride;
    TLabel *LabelEP1RefreshCap;
    TEdit *EditEP1RefreshCap;
    TLabel *LabelEP1DmxTiming;
    TComboBox *ComboEP1DmxTransMode;
    TLabel *LabelEP1DmxOutput;
    TComboBox *ComboEP1DmxOutputTiming;

    TGroupBox *GroupBoxEP1RDM;
    TLabel *LabelRdmDevLabel;
    TEdit *EditRdmDevLabel;
    TLabel *LabelRdmStartAddr;
    TSpinEdit *SpinRdmStartAddr;
    TLabel *LabelRdmPersonality;
    TSpinEdit *SpinRdmPersonality;

    TGroupBox *GroupBoxEP1DMX;
    TPaintBox *PaintBoxEP1Levels;

    // -------------------------------------------------------------------------
    // Status log (docked to bottom of form)
    // -------------------------------------------------------------------------
    TGroupBox *GroupBoxStatus;
    TMemo *MemoStatus;

    // -------------------------------------------------------------------------
    // Event handlers
    // -------------------------------------------------------------------------
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall FormDestroy(TObject *Sender);
    void __fastcall ButtonSelectK0Click(TObject *Sender);
    void __fastcall ButtonSendAnnounceClick(TObject *Sender);
    void __fastcall ButtonSelfTestClick(TObject *Sender);
    void __fastcall ButtonSelectNicClick(TObject *Sender);
    void __fastcall ButtonDeprovisionClick(TObject *Sender);
    void __fastcall ButtonSetDeviceLabelClick(TObject *Sender);
    void __fastcall EditRootDeviceLabelExit(TObject *Sender);
    void __fastcall EditRootDeviceLabelKeyPress(TObject *Sender, wchar_t &Key);
    void __fastcall EditEP1LabelExit(TObject *Sender);
    void __fastcall EditEP1LabelKeyPress(TObject *Sender, wchar_t &Key);
    void __fastcall EditRootIpv4AddrExit(TObject *Sender);
    void __fastcall EditRootIpv4AddrKeyPress(TObject *Sender, wchar_t &Key);
    void __fastcall ComboEP1FailoverChange(TObject *Sender);
    void __fastcall GenericEditExit(TObject *Sender);
    void __fastcall GenericEditKeyPress(TObject *Sender, wchar_t &Key);
    void __fastcall GenericComboChange(TObject *Sender);
    void __fastcall GenericCheckBoxClick(TObject *Sender);
    void __fastcall GenericSpinChange(TObject *Sender);
    void __fastcall SupportedTidsClickCheck(TObject *Sender);
    void __fastcall ButtonSupportedTidsNoneClick(TObject *Sender);
    void __fastcall ButtonSupportedTidsMandatedClick(TObject *Sender);
    void __fastcall ButtonSupportedTidsAllClick(TObject *Sender);
    void __fastcall PaintBoxEP1LevelsPaint(TObject *Sender);

private:    // User declarations
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
    uint8_t level_preview_frame[SigNet::MAX_DMX_SLOTS];
    bool level_preview_frame_valid;
    TBitmap* level_preview_bitmap;

    // Phase 2 shared user data model
    SigNet::NodeUserData node_user_data;

    // Identity/session config (non-TID fields used by BuildNodeQueryPayload)
    SigNet::Node::NodeConfig node_config;

    // Private methods
    void UpdateStatusDisplay();
    void LogMessage(const String& msg);
    void LogError(const String& msg);
    bool ParseK0FromHex(const String& hex_string);
    bool ParseTUIDFromHex(const String& hex_string);
    bool ParseHexTUIDField(const String& hex_string, uint8_t out_tuid[6]);
    bool ParseEndpointField(const String& text, uint16_t& endpoint_out);
    uint16_t ParseMfgCodeFromUI(bool& ok_out);
    uint16_t ParseProductVariantFromUI(bool& ok_out);
    static void UdpLogThunk(const char* message, bool is_error, void* user_context);
    bool EnsureSocketInitialized();
    void ShutdownSocket();
    bool SendRawPacket(const uint8_t* packet, uint16_t packet_len, const char* destination_ip, const String& context_label);
    bool SendAnnouncePacket();
    void RefreshReceiverGroups();
    void WarnIfLoopbackSelected();
    void __fastcall ReceiveTimerTick(TObject *Sender);
    static void UdpPacketThunk(const uint8_t* packet, uint16_t packet_len, const sockaddr_in& source_addr, void* user_context);
    void PollReceiveSocket();
    void ProcessIncomingPacket(const uint8_t* packet, uint16_t packet_len, const sockaddr_in& source_addr);
    SigNet::TidDataBlob* FindTidBlob(uint16_t tid);
    bool StoreBlobFromBytes(SigNet::TidDataBlob& blob, uint16_t tid, const uint8_t* value, uint16_t length, uint8_t value_type);
    void MarkBlobStale(SigNet::TidDataBlob& blob);
    void ClearAllManagerStaleFlags();
    void ClearAllUIStaleFlags();
    void InitializeNodeUserDataFromUI();
    bool HandlePollTLV(const SigNet::TLVBlock& tlv);
    void HandleGetRequest(uint16_t tid);
    void HandleSetRequest(uint16_t tid, const uint8_t* value, uint16_t length, bool from_manager);
    bool SendProactiveResponse(const String& reason);
    bool SendPollReplyWithQueryLevel(uint8_t query_level, uint16_t reply_endpoint, const String& reason);
    bool SendStaleResponseForEndpoint(uint16_t reply_endpoint, const String& reason);
    int32_t AppendTLVRaw(SigNet::PacketBuffer& payload, uint16_t tid, const uint8_t* value, uint16_t len);
    int32_t BuildQueryLevelPayload(uint8_t query_level, uint16_t reply_endpoint, SigNet::PacketBuffer& payload);
    void SyncUIFromStaleBlobs();
    void SendStaleTIDsToManager();
    void UpdateEP1LevelPreview(const uint8_t* level_data, uint16_t slot_count);
    void UpdateK0DependentControls();
    void UpdateFailoverSceneVisibility();
    void CommitControlFromUI(TObject* sender, const String& trigger_source);
    void CommitRootDeviceLabelFromUI(const String& trigger_source);
    void CommitEP1LabelFromUI(const String& trigger_source);
    void CommitRootIpv4AddrFromUI(const String& trigger_source);

public:     // User declarations
    __fastcall TFormSigNetNode(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TFormSigNetNode *FormSigNetNode;
//---------------------------------------------------------------------------
#endif
