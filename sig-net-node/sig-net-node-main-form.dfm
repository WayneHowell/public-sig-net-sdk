object FormSigNetNode: TFormSigNetNode
  Left = 0
  Top = 0
  BorderStyle = bsToolWindow
  Caption = 'SDK Node Device'
  ClientHeight = 372
  ClientWidth = 1099
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
    Width = 1099
    Height = 241
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
        Caption = 'Offboard'
        TabOrder = 4
        OnClick = ButtonDeprovisionClick
      end
      object ButtonSelectK0: TButton
        Left = 16
        Top = 16
        Width = 120
        Height = 25
        Caption = 'Onboard'
        TabOrder = 2
        OnClick = ButtonSelectK0Click
      end
      object ButtonSelfTest: TButton
        Left = 724
        Top = 16
        Width = 96
        Height = 25
        Caption = 'Self-Test'
        TabOrder = 3
        OnClick = ButtonSelfTestClick
      end
      object ButtonGoLive: TButton
        Left = 828
        Top = 16
        Width = 100
        Height = 25
        Caption = 'Go Live'
        TabOrder = 5
        OnClick = ButtonGoLiveClick
      end
    end
    object GroupBoxDevice: TGroupBox
      Left = 8
      Top = 62
      Width = 873
      Height = 56
      Caption = ' Device Parameters '
      TabOrder = 1
      object LabelTUID: TLabel
        Left = 16
        Top = 24
        Width = 72
        Height = 13
        Caption = 'TUID (12 hex):'
      end
      object LabelUniverse: TLabel
        Left = 282
        Top = 24
        Width = 46
        Height = 13
        Caption = 'Universe:'
      end
      object LabelRootDeviceLabel: TLabel
        Left = 436
        Top = 24
        Width = 64
        Height = 13
        Caption = 'Device Label:'
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
        Text = '0x537900000001'
      end
      object SpinUniverse: TSpinEdit
        Left = 334
        Top = 21
        Width = 80
        Height = 22
        MaxValue = 63999
        MinValue = 1
        TabOrder = 1
        Value = 1
      end
      object EditRootDeviceLabel: TEdit
        Left = 516
        Top = 21
        Width = 200
        Height = 21
        MaxLength = 64
        TabOrder = 2
      end
      object ButtonSetDeviceLabel: TButton
        Left = 724
        Top = 20
        Width = 96
        Height = 24
        Caption = 'Set Label...'
        TabOrder = 3
        OnClick = ButtonSetDeviceLabelClick
      end
    end
    object GroupBoxLevelMimic: TGroupBox
      Left = 8
      Top = 124
      Width = 873
      Height = 109
      Caption = ' Level Mimic (EP1 - received TID_LEVEL, slots 1-3) '
      TabOrder = 2
      object LabelLevelCh1: TLabel
        Left = 16
        Top = 26
        Width = 26
        Height = 13
        Caption = 'Ch 1:'
      end
      object LabelLevelCh1Val: TLabel
        Left = 776
        Top = 26
        Width = 6
        Height = 13
        Caption = '0'
      end
      object LabelLevelCh2: TLabel
        Left = 16
        Top = 54
        Width = 26
        Height = 13
        Caption = 'Ch 2:'
      end
      object LabelLevelCh2Val: TLabel
        Left = 776
        Top = 54
        Width = 6
        Height = 13
        Caption = '0'
      end
      object LabelLevelCh3: TLabel
        Left = 16
        Top = 82
        Width = 26
        Height = 13
        Caption = 'Ch 3:'
      end
      object LabelLevelCh3Val: TLabel
        Left = 776
        Top = 82
        Width = 6
        Height = 13
        Caption = '0'
      end
      object TrackLevelCh1: TTrackBar
        Left = 56
        Top = 20
        Width = 710
        Height = 25
        Max = 255
        Frequency = 16
        TabOrder = 0
        TickStyle = tsNone
      end
      object TrackLevelCh2: TTrackBar
        Left = 56
        Top = 48
        Width = 710
        Height = 25
        Max = 255
        Frequency = 16
        TabOrder = 1
        TickStyle = tsNone
      end
      object TrackLevelCh3: TTrackBar
        Left = 56
        Top = 76
        Width = 710
        Height = 25
        Max = 255
        Frequency = 16
        TabOrder = 2
        TickStyle = tsNone
      end
    end
  end
  object GroupBoxStatus: TGroupBox
    Left = 0
    Top = 241
    Width = 1099
    Height = 131
    Align = alBottom
    Caption = ' Status Log '
    TabOrder = 1
    object MemoStatus: TMemo
      Left = 2
      Top = 15
      Width = 1095
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
