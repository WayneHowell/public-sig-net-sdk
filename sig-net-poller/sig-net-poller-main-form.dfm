object FormSigNetPoller: TFormSigNetPoller
  Left = 0
  Top = 0
  BorderStyle = bsToolWindow
  Caption = '--------------------------------'
  ClientHeight = 470
  ClientWidth = 900
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
    Width = 900
    Height = 370
    Align = alClient
    BevelOuter = bvNone
    TabOrder = 0
    object FroupBoxConfig: TGroupBox
      Left = 8
      Top = 8
      Width = 884
      Height = 48
      Caption = ' Config '
      TabOrder = 0
      object LabelNicIP: TLabel
        Left = 270
        Top = 25
        Width = 14
        Height = 13
        Caption = 'IP:'
      end
      object LabelScope: TLabel
        Left = 610
        Top = 25
        Width = 33
        Height = 13
        Caption = 'Scope:'
      end
      object ButtonSelectK0: TButton
        Left = 16
        Top = 20
        Width = 105
        Height = 25
        Caption = 'Provision'
        TabOrder = 3
        OnClick = ButtonSelectK0Click
      end
      object EditNicIP: TEdit
        Left = 294
        Top = 22
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
        Text = '127.0.0.1'
      end
      object ButtonSelectNic: TButton
        Left = 502
        Top = 20
        Width = 100
        Height = 25
        Caption = 'Select NIC...'
        TabOrder = 1
        OnClick = ButtonSelectNicClick
      end
      object ButtonDeprovision: TButton
        Left = 128
        Top = 20
        Width = 105
        Height = 25
        Caption = 'De-provision'
        TabOrder = 4
        OnClick = ButtonDeprovisionClick
      end
      object ButtonSelfTest: TButton
        Left = 784
        Top = 19
        Width = 82
        Height = 25
        Caption = 'Self-Test'
        TabOrder = 2
        OnClick = ButtonSelfTestClick
      end
      object EditScope: TEdit
        Left = 652
        Top = 22
        Width = 124
        Height = 21
        MaxLength = 32
        TabOrder = 5
        Text = 'local'
        OnChange = EditScopeChange
      end
    end
    object GroupBoxAnnounce: TGroupBox
      Left = 8
      Top = 62
      Width = 884
      Height = 93
      Caption = ' Startup Announce (Manual Test) '
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
        Width = 94
        Height = 13
        Caption = 'Product ID (16-bit):'
      end
      object EditAnnounceVersionNum: TEdit
        Left = 142
        Top = 21
        Width = 100
        Height = 21
        TabOrder = 0
        Text = '1'
      end
      object EditAnnounceVersionString: TEdit
        Left = 394
        Top = 21
        Width = 250
        Height = 21
        TabOrder = 1
        Text = '??'
      end
      object EditAnnounceMfgCode: TEdit
        Left = 142
        Top = 53
        Width = 100
        Height = 21
        MaxLength = 4
        TabOrder = 2
        Text = '0000'
      end
      object EditAnnounceProductVariant: TEdit
        Left = 394
        Top = 53
        Width = 96
        Height = 21
        MaxLength = 6
        TabOrder = 3
        Text = '0x0001'
      end
      object ButtonSendAnnounce: TButton
        Left = 666
        Top = 22
        Width = 200
        Height = 35
        Caption = 'Send Announce'
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
      Width = 440
      Height = 80
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
        Left = 16
        Top = 51
        Width = 46
        Height = 13
        Caption = 'Endpoint:'
      end
      object LabelUniverse: TLabel
        Left = 232
        Top = 51
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
        Left = 96
        Top = 48
        Width = 80
        Height = 22
        MaxValue = 65535
        MinValue = 1
        TabOrder = 1
        Value = 1
      end
      object SpinUniverse: TSpinEdit
        Left = 288
        Top = 48
        Width = 80
        Height = 22
        MaxValue = 63999
        MinValue = 1
        TabOrder = 2
        Value = 1
      end
    end
    object GroupBoxSession: TGroupBox
      Left = 454
      Top = 161
      Width = 438
      Height = 80
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
        Left = 16
        Top = 51
        Width = 51
        Height = 13
        Caption = 'Sequence:'
      end
      object LabelMessageID: TLabel
        Left = 232
        Top = 24
        Width = 60
        Height = 13
        Caption = 'Message ID:'
      end
      object EditSessionID: TEdit
        Left = 96
        Top = 21
        Width = 100
        Height = 21
        ReadOnly = True
        TabOrder = 0
        Text = '1'
      end
      object EditSequence: TEdit
        Left = 96
        Top = 48
        Width = 100
        Height = 21
        ReadOnly = True
        TabOrder = 1
        Text = '1'
      end
      object EditMessageID: TEdit
        Left = 304
        Top = 21
        Width = 100
        Height = 21
        ReadOnly = True
        TabOrder = 2
        Text = '1'
      end
    end
    object GroupBoxTransmit: TGroupBox
      Left = 8
      Top = 247
      Width = 884
      Height = 120
      Caption = ' TID_POLL Transmission '
      TabOrder = 4
      object LabelPollRepeatMs: TLabel
        Left = 16
        Top = 28
        Width = 55
        Height = 13
        Caption = 'Repeat ms:'
      end
      object LabelPollJitterMs: TLabel
        Left = 16
        Top = 60
        Width = 76
        Height = 13
        Caption = 'Jitter range ms:'
      end
      object LabelPollTuidLo: TLabel
        Left = 242
        Top = 28
        Width = 47
        Height = 13
        Caption = 'TUID_LO:'
      end
      object LabelPollTuidHi: TLabel
        Left = 242
        Top = 60
        Width = 45
        Height = 13
        Caption = 'TUID_HI:'
      end
      object LabelPollEndpoint: TLabel
        Left = 610
        Top = 28
        Width = 46
        Height = 13
        Caption = 'Endpoint:'
      end
      object LabelPollQueryLevel: TLabel
        Left = 610
        Top = 60
        Width = 59
        Height = 13
        Caption = 'Query level:'
      end
      object SpinPollRepeatMs: TSpinEdit
        Left = 112
        Top = 24
        Width = 100
        Height = 22
        Increment = 10
        MaxValue = 10000
        MinValue = 10
        TabOrder = 0
        Value = 3000
      end
      object SpinPollJitterMs: TSpinEdit
        Left = 112
        Top = 56
        Width = 100
        Height = 22
        Increment = 10
        MaxValue = 1000
        MinValue = 0
        TabOrder = 1
        Value = 1000
      end
      object EditPollTuidLo: TEdit
        Left = 296
        Top = 25
        Width = 280
        Height = 22
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Courier New'
        Font.Style = []
        MaxLength = 14
        ParentFont = False
        TabOrder = 2
        Text = '0x000000000000'
      end
      object EditPollTuidHi: TEdit
        Left = 296
        Top = 57
        Width = 280
        Height = 22
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Courier New'
        Font.Style = []
        MaxLength = 14
        ParentFont = False
        TabOrder = 3
        Text = '0xffffffffffff'
      end
      object EditPollEndpoint: TEdit
        Left = 672
        Top = 25
        Width = 90
        Height = 21
        TabOrder = 4
        Text = '65535'
      end
      object ComboPollQueryLevel: TComboBox
        Left = 672
        Top = 57
        Width = 110
        Height = 21
        Style = csDropDownList
        TabOrder = 5
        Items.Strings = (
          'Heartbeat'
          'Config'
          'Full'
          'Extended')
      end
      object CheckPollRepeat: TCheckBox
        Left = 16
        Top = 92
        Width = 104
        Height = 17
        Caption = 'Repeat Send'
        TabOrder = 6
        OnClick = CheckPollRepeatClick
      end
      object CheckPollEnableJitter: TCheckBox
        Left = 136
        Top = 92
        Width = 121
        Height = 17
        Caption = 'Enable Jitter'
        TabOrder = 7
      end
      object ButtonSendPoll: TButton
        Left = 666
        Top = 86
        Width = 200
        Height = 27
        Caption = 'Send TID_POLL'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        TabOrder = 8
        OnClick = ButtonSendPollClick
      end
    end
  end
  object GroupBoxStatus: TGroupBox
    Left = 0
    Top = 370
    Width = 900
    Height = 100
    Align = alBottom
    Caption = ' Status Log '
    TabOrder = 1
    object MemoStatus: TMemo
      Left = 2
      Top = 15
      Width = 896
      Height = 83
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
  object TimerPollRepeat: TTimer
    Enabled = False
    Interval = 3000
    OnTimer = TimerPollRepeatTimer
    Left = 776
    Top = 328
  end
end
