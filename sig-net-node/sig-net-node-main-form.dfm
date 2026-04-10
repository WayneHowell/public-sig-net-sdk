object FormSigNetNode: TFormSigNetNode
  Left = 0
  Top = 0
  BorderStyle = bsToolWindow
  Caption = '--------------------------------????'
  ClientHeight = 929
  ClientWidth = 1156
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = True
  Position = poScreenCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object PanelMain: TPanel
    Left = 0
    Top = 0
    Width = 1156
    Height = 798
    Align = alClient
    BevelOuter = bvNone
    TabOrder = 0
    object FroupBoxConfig: TGroupBox
      Left = 8
      Top = 8
      Width = 1137
      Height = 48
      Caption = ' Config '
      TabOrder = 0
      object LabelNicIP: TLabel
        Left = 274
        Top = 22
        Width = 35
        Height = 13
        Caption = 'NIC IP:'
      end
      object EditNicIP: TEdit
        Left = 308
        Top = 16
        Width = 200
        Height = 22
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Courier New'
        Font.Style = []
        ParentFont = False
        ReadOnly = True
        TabOrder = 0
      end
      object ButtonSelectNic: TButton
        Left = 516
        Top = 16
        Width = 100
        Height = 25
        Caption = 'Select NIC...'
        TabOrder = 1
        OnClick = ButtonSelectNicClick
      end
      object ButtonDeprovision: TButton
        Left = 142
        Top = 16
        Width = 120
        Height = 25
        Caption = 'De-provision'
        TabOrder = 4
        OnClick = ButtonDeprovisionClick
      end
      object ButtonSelectK0: TButton
        Left = 16
        Top = 16
        Width = 120
        Height = 25
        Caption = 'Select K0...'
        TabOrder = 2
        OnClick = ButtonSelectK0Click
      end
      object ButtonSelfTest: TButton
        Left = 1035
        Top = 16
        Width = 82
        Height = 25
        Caption = 'Self-Test'
        TabOrder = 3
        OnClick = ButtonSelfTestClick
      end
    end
    object GroupBoxAnnounce: TGroupBox
      Left = 8
      Top = 62
      Width = 1137
      Height = 93
      Caption = ' On-Boot Announce (Manual Test) '
      TabOrder = 1
      object LabelAnnounceVersionNum: TLabel
        Left = 16
        Top = 24
        Width = 118
        Height = 13
        Caption = 'Version Number (16-bit):'
      end
      object LabelAnnounceVersionString: TLabel
        Left = 290
        Top = 24
        Width = 95
        Height = 13
        Caption = 'Version String Text:'
      end
      object LabelAnnounceMfgCode: TLabel
        Left = 16
        Top = 56
        Width = 110
        Height = 13
        Caption = 'ManID (ESTA) (16-bit):'
      end
      object LabelAnnounceProductVariant: TLabel
        Left = 290
        Top = 56
        Width = 91
        Height = 13
        Caption = 'ProductID (16-bit):'
      end
      object EditAnnounceVersionNum: TEdit
        Left = 142
        Top = 21
        Width = 100
        Height = 21
        TabOrder = 0
        Text = '4'
      end
      object EditAnnounceVersionString: TEdit
        Left = 394
        Top = 21
        Width = 250
        Height = 21
        TabOrder = 1
        Text = 'v0.15-test'
      end
      object EditAnnounceMfgCode: TEdit
        Left = 142
        Top = 53
        Width = 100
        Height = 21
        MaxLength = 6
        TabOrder = 2
        Text = '0x534c'
      end
      object EditAnnounceProductVariant: TEdit
        Left = 394
        Top = 53
        Width = 100
        Height = 21
        MaxLength = 6
        TabOrder = 3
        Text = '0x0001'
      end
      object ButtonSendAnnounce: TButton
        Left = 917
        Top = 14
        Width = 200
        Height = 35
        Caption = 'Send On-Boot Announce'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        TabOrder = 4
        OnClick = ButtonSendAnnounceClick
      end
    end
    object GroupBoxDevice: TGroupBox
      Left = 8
      Top = 161
      Width = 569
      Height = 56
      Caption = ' Device Parameters '
      TabOrder = 2
      object LabelTUID: TLabel
        Left = 16
        Top = 24
        Width = 72
        Height = 13
        Caption = 'TUID (12 hex):'
      end
      object LabelEndpoint: TLabel
        Left = 282
        Top = 24
        Width = 46
        Height = 13
        Caption = 'Endpoint:'
      end
      object LabelUniverse: TLabel
        Left = 434
        Top = 24
        Width = 46
        Height = 13
        Caption = 'Universe:'
      end
      object EditTUID: TEdit
        Left = 96
        Top = 21
        Width = 160
        Height = 22
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Courier New'
        Font.Style = []
        MaxLength = 14
        ParentFont = False
        TabOrder = 0
        Text = '0x534c00000001'
      end
      object SpinEndpoint: TSpinEdit
        Left = 334
        Top = 21
        Width = 80
        Height = 22
        MaxValue = 65535
        MinValue = 1
        TabOrder = 1
        Value = 1
      end
      object SpinUniverse: TSpinEdit
        Left = 486
        Top = 21
        Width = 80
        Height = 22
        MaxValue = 63999
        MinValue = 1
        TabOrder = 2
        Value = 1
      end
    end
    object GroupBoxSession: TGroupBox
      Left = 604
      Top = 161
      Width = 541
      Height = 56
      Caption = ' Session / Sequence Tracking '
      TabOrder = 3
      object LabelSessionID: TLabel
        Left = 16
        Top = 24
        Width = 54
        Height = 13
        Caption = 'Session ID:'
      end
      object LabelSequence: TLabel
        Left = 368
        Top = 24
        Width = 51
        Height = 13
        Caption = 'Sequence:'
      end
      object LabelMessageID: TLabel
        Left = 182
        Top = 24
        Width = 60
        Height = 13
        Caption = 'Message ID:'
      end
      object EditSessionID: TEdit
        Left = 76
        Top = 21
        Width = 100
        Height = 21
        ReadOnly = True
        TabOrder = 0
      end
      object EditSequence: TEdit
        Left = 425
        Top = 21
        Width = 100
        Height = 21
        ReadOnly = True
        TabOrder = 1
      end
      object EditMessageID: TEdit
        Left = 248
        Top = 21
        Width = 100
        Height = 21
        ReadOnly = True
        TabOrder = 2
      end
    end
    object PageControlNode: TPageControl
      Left = 8
      Top = 223
      Width = 1137
      Height = 578
      ActivePage = TabSheetEP1
      TabOrder = 4
      object TabSheetRoot: TTabSheet
        Caption = 'Root EP (Mandated)'
        object GroupBoxRootIdentity: TGroupBox
          Left = 8
          Top = 8
          Width = 510
          Height = 185
          Caption = ' Root Identity TIDs '
          TabOrder = 0
          object LabelRootDeviceLabel: TLabel
            Left = 16
            Top = 24
            Width = 117
            Height = 13
            Caption = 'TID_RT_DEVICE_LABEL:'
          end
          object LabelRootSoemCode: TLabel
            Left = 16
            Top = 54
            Width = 55
            Height = 13
            Caption = 'SoemCode:'
          end
          object LabelRootProtVersion: TLabel
            Left = 16
            Top = 84
            Width = 151
            Height = 13
            Caption = 'TID_RT_PROTOCOL_VERSION:'
          end
          object LabelRootFirmware: TLabel
            Left = 16
            Top = 114
            Width = 151
            Height = 13
            Caption = 'TID_RT_FIRMWARE_VERSION:'
          end
          object LabelRootModelName: TLabel
            Left = 16
            Top = 145
            Width = 114
            Height = 13
            Caption = 'TID_RT_MODEL_NAME:'
          end
          object EditRootDeviceLabel: TEdit
            Left = 190
            Top = 21
            Width = 192
            Height = 21
            MaxLength = 64
            TabOrder = 0
          end
          object ButtonSetDeviceLabel: TButton
            Left = 388
            Top = 20
            Width = 96
            Height = 24
            Caption = 'Set Label...'
            TabOrder = 1
            OnClick = ButtonSetDeviceLabelClick
          end
          object EditRootSoemCode: TEdit
            Left = 190
            Top = 51
            Width = 120
            Height = 22
            Font.Charset = DEFAULT_CHARSET
            Font.Color = clWindowText
            Font.Height = -11
            Font.Name = 'Courier New'
            Font.Style = []
            ParentFont = False
            ReadOnly = True
            TabOrder = 2
          end
          object EditRootProtVersion: TEdit
            Left = 190
            Top = 81
            Width = 60
            Height = 21
            ReadOnly = True
            TabOrder = 3
          end
          object EditRootFirmwareID: TEdit
            Left = 190
            Top = 111
            Width = 60
            Height = 21
            ReadOnly = True
            TabOrder = 4
          end
          object EditRootFirmwareStr: TEdit
            Left = 258
            Top = 111
            Width = 124
            Height = 21
            ReadOnly = True
            TabOrder = 5
          end
          object EditRootModelName: TEdit
            Left = 190
            Top = 142
            Width = 192
            Height = 21
            TabOrder = 6
          end
        end
        object GroupBoxRootState: TGroupBox
          Left = 524
          Top = 8
          Width = 349
          Height = 185
          Caption = ' Root State TIDs '
          TabOrder = 1
          object LabelRootIdentify: TLabel
            Left = 16
            Top = 24
            Width = 92
            Height = 13
            Caption = 'TID_RT_IDENTIFY:'
          end
          object LabelRootStatus: TLabel
            Left = 16
            Top = 78
            Width = 84
            Height = 13
            Caption = 'TID_RT_STATUS:'
          end
          object LabelRootEndpCount: TLabel
            Left = 16
            Top = 52
            Width = 138
            Height = 13
            Caption = 'TID_RT_ENDPOINT_COUNT:'
          end
          object LabelRootRoles: TLabel
            Left = 192
            Top = 78
            Width = 136
            Height = 13
            Caption = 'TID_RT_ROLE_CAPABILITY:'
          end
          object ComboRootIdentify: TComboBox
            Left = 192
            Top = 21
            Width = 134
            Height = 21
            Style = csDropDownList
            TabOrder = 0
            Items.Strings = (
              '0x00 - Off'
              '0x01 - Subtle'
              '0x02 - Full'
              '0x03 - Mute (dark-sky)')
          end
          object CBStatusHwFault: TCheckBox
            Left = 30
            Top = 97
            Width = 120
            Height = 17
            Caption = 'HW Fault (Bit 0)'
            TabOrder = 1
          end
          object CBStatusFactoryBoot: TCheckBox
            Left = 30
            Top = 120
            Width = 160
            Height = 17
            Caption = 'Factory Boot (Bit 1)'
            TabOrder = 2
          end
          object CBStatusConfigLock: TCheckBox
            Left = 30
            Top = 143
            Width = 140
            Height = 17
            Caption = 'Config Lock (Bit 2)'
            TabOrder = 3
          end
          object EditRootEndpCount: TEdit
            Left = 192
            Top = 48
            Width = 56
            Height = 21
            TabOrder = 4
          end
          object CBRoleNode: TCheckBox
            Left = 200
            Top = 97
            Width = 60
            Height = 17
            Caption = 'Node'
            Checked = True
            State = cbChecked
            TabOrder = 5
          end
          object CBRoleSender: TCheckBox
            Left = 200
            Top = 120
            Width = 65
            Height = 17
            Caption = 'Sender'
            TabOrder = 6
          end
          object CBRoleManager: TCheckBox
            Left = 200
            Top = 143
            Width = 72
            Height = 17
            Caption = 'Manager'
            TabOrder = 7
          end
        end
        object GroupBoxRootMulticast: TGroupBox
          Left = 8
          Top = 199
          Width = 860
          Height = 242
          Caption = ' Root Routing + Capability '
          TabOrder = 2
          object LabelRootMultState: TLabel
            Left = 16
            Top = 22
            Width = 72
            Height = 13
            Caption = 'TID_RT_MULT:'
          end
          object LabelRootSupportedTids: TLabel
            Left = 16
            Top = 54
            Width = 134
            Height = 13
            Caption = 'TID_RT_SUPPORTED_TIDS:'
          end
          object ButtonSupportedTidsNone: TButton
            Left = 194
            Top = 51
            Width = 60
            Height = 21
            Caption = 'None'
            TabOrder = 1
          end
          object ButtonSupportedTidsMandated: TButton
            Left = 260
            Top = 51
            Width = 75
            Height = 21
            Caption = 'Mandated'
            TabOrder = 2
          end
          object ButtonSupportedTidsAll: TButton
            Left = 341
            Top = 51
            Width = 50
            Height = 21
            Caption = 'All'
            TabOrder = 3
          end
          object EditRootMultState: TEdit
            Left = 154
            Top = 19
            Width = 170
            Height = 22
            Font.Charset = DEFAULT_CHARSET
            Font.Color = clWindowText
            Font.Height = -11
            Font.Name = 'Courier New'
            Font.Style = []
            ParentFont = False
            ReadOnly = True
            TabOrder = 0
          end
          object CheckListRootSupportedTids: TCheckListBox
            Left = 194
            Top = 78
            Width = 646
            Height = 149
            ItemHeight = 13
            Items.Strings = (
              'TID_RT_ENDPOINT_COUNT (0x0602) - mandated'
              'TID_RT_PROTOCOL_VERSION (0x0603) - mandated'
              'TID_RT_FIRMWARE_VERSION (0x0604) - mandated'
              'TID_RT_DEVICE_LABEL (0x0605) - mandated'
              'TID_RT_MULT (0x0606) - mandated'
              'TID_RT_IDENTIFY (0x0607) - mandated'
              'TID_RT_STATUS (0x0608) - mandated'
              'TID_RT_ROLE_CAPABILITY (0x0609) - mandated'
              'TID_RT_MODEL_NAME (0x060B) - optional'
              'TID_RT_REBOOT (0x060A) - optional'
              'TID_RT_UNPROVISION (0x0401) - optional'
              'TID_NW_MAC_ADDRESS (0x0501) - optional'
              'TID_NW_IPV4_MODE (0x0502) - optional'
              'TID_NW_IPV4_ADDRESS (0x0503) - optional'
              'TID_NW_IPV4_NETMASK (0x0504) - optional'
              'TID_NW_IPV4_GATEWAY (0x0505) - optional'
              'TID_NW_IPV4_CURRENT (0x0506) - optional'
              'TID_NW_IPV6_MODE (0x0581) - optional'
              'TID_NW_IPV6_ADDRESS (0x0582) - optional'
              'TID_NW_IPV6_PREFIX (0x0583) - optional'
              'TID_NW_IPV6_GATEWAY (0x0584) - optional'
              'TID_NW_IPV6_CURRENT (0x0585) - optional')
            TabOrder = 4
          end
        end
      end
      object TabSheetRootOptional: TTabSheet
        Caption = 'Root EP (Optional)'
        ImageIndex = 1
        object GroupBoxRootOptional: TGroupBox
          Left = 8
          Top = 8
          Width = 860
          Height = 445
          Caption = ' Optional Root TIDs '
          TabOrder = 0
          object GroupBoxRootIPv4: TGroupBox
            Left = 8
            Top = 16
            Width = 844
            Height = 132
            Caption = ' IPv4 Network TIDs '
            TabOrder = 0
            object LabelRootMac: TLabel
              Left = 16
              Top = 24
              Width = 124
              Height = 13
              Caption = 'TID_NW_MAC_ADDRESS:'
            end
            object LabelRootIpv4Mode: TLabel
              Left = 16
              Top = 51
              Width = 107
              Height = 13
              Caption = 'TID_NW_IPV4_MODE:'
            end
            object LabelRootIpv4Addr: TLabel
              Left = 16
              Top = 78
              Width = 124
              Height = 13
              Caption = 'TID_NW_IPV4_ADDRESS:'
            end
            object LabelRootIpv4Mask: TLabel
              Left = 16
              Top = 105
              Width = 124
              Height = 13
              Caption = 'TID_NW_IPV4_NETMASK:'
            end
            object LabelRootIpv4Gateway: TLabel
              Left = 430
              Top = 78
              Width = 127
              Height = 13
              Caption = 'TID_NW_IPV4_GATEWAY:'
            end
            object LabelRootIpv4Current: TLabel
              Left = 430
              Top = 105
              Width = 125
              Height = 13
              Caption = 'TID_NW_IPV4_CURRENT:'
            end
            object EditRootMac: TEdit
              Left = 186
              Top = 21
              Width = 210
              Height = 21
              ReadOnly = True
              TabOrder = 0
              Text = '00:00:00:00:00:00'
            end
            object ComboRootIpv4Mode: TComboBox
              Left = 186
              Top = 48
              Width = 170
              Height = 21
              Style = csDropDownList
              TabOrder = 1
              Items.Strings = (
                '0x00 - Static'
                '0x01 - DHCP')
            end
            object EditRootIpv4Addr: TEdit
              Left = 186
              Top = 75
              Width = 210
              Height = 21
              TabOrder = 2
              Text = '192.168.1.100'
            end
            object EditRootIpv4Mask: TEdit
              Left = 186
              Top = 102
              Width = 210
              Height = 21
              TabOrder = 3
              Text = '255.255.255.0'
            end
            object EditRootIpv4Gateway: TEdit
              Left = 590
              Top = 75
              Width = 230
              Height = 21
              TabOrder = 4
              Text = '192.168.1.1'
            end
            object EditRootIpv4Current: TEdit
              Left = 590
              Top = 102
              Width = 230
              Height = 21
              ReadOnly = True
              TabOrder = 5
              Text = '192.168.1.100/255.255.255.0 gw 192.168.1.1'
            end
          end
          object GroupBoxRootIPv6: TGroupBox
            Left = 8
            Top = 154
            Width = 844
            Height = 140
            Caption = ' IPv6 Network TIDs '
            TabOrder = 1
            object LabelRootIpv6Mode: TLabel
              Left = 16
              Top = 24
              Width = 107
              Height = 13
              Caption = 'TID_NW_IPV6_MODE:'
            end
            object LabelRootIpv6Addr: TLabel
              Left = 16
              Top = 51
              Width = 124
              Height = 13
              Caption = 'TID_NW_IPV6_ADDRESS:'
            end
            object LabelRootIpv6Prefix: TLabel
              Left = 16
              Top = 78
              Width = 113
              Height = 13
              Caption = 'TID_NW_IPV6_PREFIX:'
            end
            object LabelRootIpv6Gateway: TLabel
              Left = 430
              Top = 51
              Width = 127
              Height = 13
              Caption = 'TID_NW_IPV6_GATEWAY:'
            end
            object LabelRootIpv6Current: TLabel
              Left = 430
              Top = 78
              Width = 125
              Height = 13
              Caption = 'TID_NW_IPV6_CURRENT:'
            end
            object ComboRootIpv6Mode: TComboBox
              Left = 186
              Top = 21
              Width = 170
              Height = 21
              Style = csDropDownList
              TabOrder = 0
              Items.Strings = (
                '0x00 - Static'
                '0x01 - SLAAC'
                '0x02 - DHCPv6')
            end
            object EditRootIpv6Addr: TEdit
              Left = 186
              Top = 48
              Width = 210
              Height = 21
              TabOrder = 1
              Text = 'fe80::100'
            end
            object SpinRootIpv6Prefix: TSpinEdit
              Left = 186
              Top = 75
              Width = 80
              Height = 22
              MaxValue = 128
              MinValue = 0
              TabOrder = 2
              Value = 64
            end
            object EditRootIpv6Gateway: TEdit
              Left = 590
              Top = 48
              Width = 230
              Height = 21
              TabOrder = 3
              Text = 'fe80::1'
            end
            object EditRootIpv6Current: TEdit
              Left = 590
              Top = 75
              Width = 230
              Height = 21
              ReadOnly = True
              TabOrder = 4
              Text = 'fe80::100/64 gw fe80::1'
            end
          end
        end
      end
      object TabSheetEP1: TTabSheet
        Caption = 'EP1 (Virtual)'
        ImageIndex = 2
        object GroupBoxEP1TIDs: TGroupBox
          Left = 8
          Top = 8
          Width = 1105
          Height = 200
          Caption = ' EP1 Data Endpoint TIDs '
          TabOrder = 0
          object LabelEP1Universe: TLabel
            Left = 16
            Top = 26
            Width = 94
            Height = 13
            Caption = 'TID_EP_UNIVERSE:'
          end
          object LabelEP1Label: TLabel
            Left = 308
            Top = 26
            Width = 74
            Height = 13
            Caption = 'TID_EP_LABEL:'
          end
          object LabelEP1Direction: TLabel
            Left = 16
            Top = 57
            Width = 101
            Height = 13
            Caption = 'TID_EP_DIRECTION:'
          end
          object LabelEP1Capability: TLabel
            Left = 16
            Top = 89
            Width = 103
            Height = 13
            Caption = 'TID_EP_CAPABILITY:'
          end
          object LabelEP1Status: TLabel
            Left = 16
            Top = 120
            Width = 83
            Height = 13
            Caption = 'TID_EP_STATUS:'
          end
          object LabelEP1Failover: TLabel
            Left = 308
            Top = 120
            Width = 94
            Height = 13
            Caption = 'TID_EP_FAILOVER:'
          end
          object LabelEP1FailoverScene: TLabel
            Left = 440
            Top = 120
            Width = 44
            Height = 13
            Caption = 'Scene #:'
          end
          object LabelEP1MultOverride: TLabel
            Left = 16
            Top = 152
            Width = 128
            Height = 13
            Caption = 'TID_EP_MULT_OVERRIDE:'
          end
          object LabelEP1RefreshCap: TLabel
            Left = 308
            Top = 152
            Width = 154
            Height = 13
            Caption = 'TID_EP_REFRESH_CAPABILITY:'
          end
          object LabelEP1DmxTiming: TLabel
            Left = 16
            Top = 176
            Width = 108
            Height = 13
            Caption = 'TID_EP_DMX_TIMING:'
          end
          object LabelEP1DmxOutput: TLabel
            Left = 290
            Top = 176
            Width = 38
            Height = 13
            Caption = 'Output:'
          end
          object SpinEP1Universe: TSpinEdit
            Left = 166
            Top = 22
            Width = 90
            Height = 22
            MaxValue = 63999
            MinValue = 1
            TabOrder = 0
            Value = 1
          end
          object EditEP1Label: TEdit
            Left = 392
            Top = 22
            Width = 220
            Height = 21
            MaxLength = 64
            TabOrder = 1
          end
          object ComboEP1Direction: TComboBox
            Left = 166
            Top = 53
            Width = 220
            Height = 21
            Style = csDropDownList
            TabOrder = 2
            Items.Strings = (
              '0x00 - Disabled'
              '0x01 - Consumer (receives Sig-Net)'
              '0x02 - Supplier (generates Sig-Net)')
          end
          object CBEp1RdmEnable: TCheckBox
            Left = 402
            Top = 56
            Width = 95
            Height = 17
            Caption = 'RDM Enable'
            Checked = True
            State = cbChecked
            TabOrder = 3
          end
          object CBCapConsumeLevel: TCheckBox
            Left = 166
            Top = 86
            Width = 105
            Height = 17
            Caption = 'Consume Level'
            Checked = True
            State = cbChecked
            TabOrder = 4
          end
          object CBCapSupplyLevel: TCheckBox
            Left = 276
            Top = 86
            Width = 95
            Height = 17
            Caption = 'Supply Level'
            TabOrder = 5
          end
          object CBCapConsumeRDM: TCheckBox
            Left = 382
            Top = 86
            Width = 100
            Height = 17
            Caption = 'Consume RDM'
            Checked = True
            State = cbChecked
            TabOrder = 6
          end
          object CBCapSupplyRDM: TCheckBox
            Left = 488
            Top = 86
            Width = 90
            Height = 17
            Caption = 'Supply RDM'
            TabOrder = 7
          end
          object CBCapVirtual: TCheckBox
            Left = 584
            Top = 86
            Width = 66
            Height = 17
            Caption = 'Virtual'
            Checked = True
            State = cbChecked
            TabOrder = 8
          end
          object EditEP1Status: TEdit
            Left = 166
            Top = 117
            Width = 110
            Height = 22
            Font.Charset = DEFAULT_CHARSET
            Font.Color = clWindowText
            Font.Height = -11
            Font.Name = 'Courier New'
            Font.Style = []
            ParentFont = False
            ReadOnly = True
            TabOrder = 9
            Text = '0x00000000'
          end
          object ComboEP1Failover: TComboBox
            Left = 412
            Top = 117
            Width = 180
            Height = 21
            Style = csDropDownList
            TabOrder = 10
            OnChange = ComboEP1FailoverChange
            Items.Strings = (
              '0x00 - Hold Last State'
              '0x01 - Blackout (all slots 0)'
              '0x02 - Full (all slots 255)'
              '0x03 - Play Scene')
          end
          object SpinEP1FailoverScene: TSpinEdit
            Left = 662
            Top = 116
            Width = 80
            Height = 22
            MaxValue = 60000
            MinValue = 1
            TabOrder = 11
            Value = 1
          end
          object EditEP1MultOverride: TEdit
            Left = 166
            Top = 149
            Width = 130
            Height = 22
            Font.Charset = DEFAULT_CHARSET
            Font.Color = clWindowText
            Font.Height = -11
            Font.Name = 'Courier New'
            Font.Style = []
            ParentFont = False
            TabOrder = 12
            Text = '0.0.0.0'
          end
          object EditEP1RefreshCap: TEdit
            Left = 468
            Top = 149
            Width = 45
            Height = 21
            ReadOnly = True
            TabOrder = 13
            Text = '44'
          end
          object ComboEP1DmxTransMode: TComboBox
            Left = 166
            Top = 172
            Width = 220
            Height = 21
            Style = csDropDownList
            TabOrder = 14
            Items.Strings = (
              '0x00 - Continuous'
              '0x01 - Delta (change-only)')
          end
          object ComboEP1DmxOutputTiming: TComboBox
            Left = 506
            Top = 172
            Width = 180
            Height = 21
            Style = csDropDownList
            TabOrder = 15
            Items.Strings = (
              '0x00 - Maximum rate'
              '0x01 - Medium rate'
              '0x02 - Minimum rate')
          end
        end
        object GroupBoxEP1DMX: TGroupBox
          Left = 0
          Top = 214
          Width = 1113
          Height = 331
          Caption = ' DMX Levels EP1 '
          TabOrder = 1
          object PaintBoxEP1Levels: TPaintBox
            Left = 8
            Top = 15
            Width = 1097
            Height = 306
            Color = clBtnFace
            ParentColor = False
            OnPaint = PaintBoxEP1LevelsPaint
          end
        end
      end
      object TabSheetEP1RDM: TTabSheet
        Caption = 'EP1 (RDM)'
        ImageIndex = 3
        object GroupBoxEP1RDM: TGroupBox
          Left = 8
          Top = 8
          Width = 430
          Height = 115
          Caption = ' RDM Virtual Responder PIDs '
          TabOrder = 0
          object LabelRdmDevLabel: TLabel
            Left = 16
            Top = 24
            Width = 64
            Height = 13
            Caption = 'Device Label:'
          end
          object LabelRdmStartAddr: TLabel
            Left = 16
            Top = 54
            Width = 78
            Height = 13
            Caption = 'DMX Start Addr:'
          end
          object LabelRdmPersonality: TLabel
            Left = 16
            Top = 84
            Width = 57
            Height = 13
            Caption = 'Personality:'
          end
          object EditRdmDevLabel: TEdit
            Left = 90
            Top = 21
            Width = 320
            Height = 21
            MaxLength = 32
            TabOrder = 0
          end
          object SpinRdmStartAddr: TSpinEdit
            Left = 110
            Top = 51
            Width = 80
            Height = 22
            MaxValue = 512
            MinValue = 1
            TabOrder = 1
            Value = 1
          end
          object SpinRdmPersonality: TSpinEdit
            Left = 110
            Top = 81
            Width = 60
            Height = 22
            MaxValue = 255
            MinValue = 1
            TabOrder = 2
            Value = 1
          end
        end
      end
    end
  end
  object GroupBoxStatus: TGroupBox
    Left = 0
    Top = 798
    Width = 1156
    Height = 131
    Align = alBottom
    Caption = ' Status Log '
    TabOrder = 1
    object MemoStatus: TMemo
      Left = 2
      Top = 15
      Width = 1152
      Height = 114
      Align = alClient
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Courier New'
      Font.Style = []
      ParentFont = False
      ReadOnly = True
      ScrollBars = ssVertical
      TabOrder = 0
    end
  end
end
