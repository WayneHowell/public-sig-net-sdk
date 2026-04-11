object FormSigNetTx: TFormSigNetTx
  Left = 0
  Top = 0
  BorderStyle = bsToolWindow
  Caption = '--------------------------------'
  ClientHeight = 692
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
    Height = 592
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
      object LabelK0: TLabel
        Left = 16
        Top = 24
        Width = 78
        Height = 13
        Caption = 'K0 set via dialog'
      end
      object LabelNicIP: TLabel
        Left = 336
        Top = 24
        Width = 14
        Height = 13
        Caption = 'IP:'
      end
      object LabelScope: TLabel
        Left = 592
        Top = 24
        Width = 33
        Height = 13
        Caption = 'Scope:'
      end
      object ButtonSelectK0: TButton
        Left = 106
        Top = 19
        Width = 105
        Height = 25
        Caption = 'Provision'
        TabOrder = 3
        OnClick = ButtonSelectK0Click
      end
      object EditNicIP: TEdit
        Left = 360
        Top = 21
        Width = 89
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
        Left = 462
        Top = 19
        Width = 115
        Height = 25
        Caption = 'Select NIC...'
        TabOrder = 1
        OnClick = ButtonSelectNicClick
      end
      object ButtonDeprovision: TButton
        Left = 218
        Top = 19
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
        Left = 631
        Top = 21
        Width = 147
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
        Width = 64
        Height = 13
        Caption = 'Version Text:'
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
        Width = 100
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
      Height = 67
      Caption = ' Packet Transmission '
      TabOrder = 4
      object LabelDmxMode: TLabel
        Left = 16
        Top = 26
        Width = 54
        Height = 13
        Caption = 'DMX Mode:'
      end
      object LabelBadFrameEvery: TLabel
        Left = 500
        Top = 26
        Width = 32
        Height = 13
        Caption = 'Every:'
      end
      object ComboBoxDmxMode: TComboBox
        Left = 80
        Top = 22
        Width = 110
        Height = 21
        Style = csDropDownList
        TabOrder = 0
        OnChange = ComboBoxDmxModeChange
        Items.Strings = (
          'Manual'
          'Dynamic')
      end
      object ButtonSendLevelPacket: TButton
        Left = 666
        Top = 21
        Width = 200
        Height = 27
        Caption = 'Send TID_LEVEL'
        Font.Charset = DEFAULT_CHARSET
        Font.Color = clWindowText
        Font.Height = -11
        Font.Name = 'Tahoma'
        Font.Style = [fsBold]
        ParentFont = False
        TabOrder = 1
        OnClick = ButtonSendLevelPacketClick
      end
      object CheckKeepAlive: TCheckBox
        Left = 216
        Top = 24
        Width = 138
        Height = 17
        Caption = 'Keep-Alive (900 ms)'
        TabOrder = 2
        OnClick = CheckKeepAliveClick
      end
      object CheckInsertBadFrames: TCheckBox
        Left = 360
        Top = 24
        Width = 132
        Height = 17
        Caption = 'Insert Bad Frames'
        TabOrder = 3
        OnClick = CheckInsertBadFramesClick
      end
      object EditBadFrameInterval: TEdit
        Left = 534
        Top = 22
        Width = 56
        Height = 21
        TabOrder = 4
        Text = '50'
      end
    end
    object GroupBoxDMXFaders: TGroupBox
      Left = 8
      Top = 320
      Width = 884
      Height = 270
      Caption = ' DMX Level Faders (512 Channels) '
      TabOrder = 5
      object PanelTrackbars: TPanel
        Left = 0
        Top = 20
        Width = 881
        Height = 214
        BevelOuter = bvNone
        TabOrder = 0
      end
      object ScrollBarDMX: TScrollBar
        Left = 10
        Top = 240
        Width = 865
        Height = 17
        Max = 480
        PageSize = 0
        TabOrder = 1
        OnChange = ScrollBarDMXChange
      end
    end
  end
  object GroupBoxStatus: TGroupBox
    Left = 0
    Top = 592
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
  object TimerKeepAlive: TTimer
    Enabled = False
    Interval = 900
    OnTimer = TimerKeepAliveTimer
    Left = 816
    Top = 632
  end
  object TimerHeartBeat: TTimer
    Enabled = False
    Interval = 10
    OnTimer = TimerHeartBeatTimer
    Left = 744
    Top = 632
  end
end
