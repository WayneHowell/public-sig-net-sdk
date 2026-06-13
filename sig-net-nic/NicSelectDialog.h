//==============================================================================
// Sig-Net Protocol Framework - NIC Selection Dialog
//==============================================================================
//
// Enumerates all network interfaces on the system using GetAdaptersInfo()
// and allows the user to select one as the multicast source interface.
//
// Usage:
//   TNicSelectDialog* dlg = new TNicSelectDialog(Application);
//   dlg->SetCurrentIP("127.0.0.1");  // pre-select current NIC
//   if (dlg->ShowModal() == mrOk)
//       AnsiString ip = dlg->GetSelectedIP();
//   delete dlg;
//==============================================================================

#ifndef NicSelectDialogH
#define NicSelectDialogH
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.ExtCtrls.hpp>
#include <winsock2.h>
#include <iphlpapi.h>

namespace SigNet {
// Selects default startup NIC with preference: 2.x.x.x, then 192.x.x.x,
// then first physical NIC. Falls back to loopback if none are available.
AnsiString SelectDefaultStartupNicIP();
}
//---------------------------------------------------------------------------
class TNicSelectDialog : public TForm
{
__published:
    TListBox  *ListBoxNics;
    TPanel    *PanelButtons;
    TButton   *ButtonOk;
    TButton   *ButtonCancel;
    TLabel    *LabelPrompt;

    void __fastcall ButtonOkClick(TObject *Sender);
    void __fastcall ButtonCancelClick(TObject *Sender);
    void __fastcall ListBoxNicsClick(TObject *Sender);
    void __fastcall FormShow(TObject *Sender);

public:
    __fastcall TNicSelectDialog(TComponent* Owner);

    // Set the IP that should be pre-selected when the dialog opens.
    void SetCurrentIP(const AnsiString& ip);

    // Returns the IP address string of the selected adapter.
    // Returns "127.0.0.1" if nothing was selected.
    AnsiString GetSelectedIP() const;

private:
    AnsiString FSelectedIP;
    AnsiString FCurrentIP;

    void PopulateList();
};
//---------------------------------------------------------------------------
extern PACKAGE TNicSelectDialog *NicSelectDialog;
//---------------------------------------------------------------------------
#endif
