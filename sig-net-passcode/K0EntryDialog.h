//==============================================================================
// Sig-Net Protocol Framework - K0 Entry Dialog Header
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
// Description:  Common K0 entry dialog for Sig-Net applications.
//               Provides three methods for establishing K0:
//               1) Passphrase entry with real-time validation
//               2) Random K0 generation
//               3) Test K0 selection (development only)
//==============================================================================

#ifndef K0EntryDialogH
#define K0EntryDialogH

//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.ExtCtrls.hpp>
#include "../sig-net.hpp"

//---------------------------------------------------------------------------
class TK0EntryDialog : public TForm
{
__published:	// IDE-managed Components
    TLabel *LabelInstructions;
    TLabel *LabelValidation;
    TLabel *Label1;
    TLabel *Label2;
    TLabel *Label3;
    TLabel *Label4;
    TLabel *Label5;
    TLabel *Label6;
    TLabel *Label7;
    TRadioGroup *RadioGroupMode;
    TPanel *PanelPassphrase;
    TEdit *EditPassphrase;
    TButton *ButtonPassphraseToK0;
    TButton *ButtonGenerateRandomPassphrase;
    TButton *ButtonUseTestPassphrase;
    TButton *ButtonGenerateRandomK0;
    TButton *ButtonUseTestK0;
    TPanel *PanelValidationChecks;
    TLabel *EditCheckLength;
    TLabel *EditCheckClasses;
    TLabel *EditCheckIdentical;
    TLabel *EditCheckSequential;
    TEdit *EditK0Display;
    TEdit *EditSenderKey;
    TEdit *EditCitizenKey;
    TEdit *EditManagerGlobalKey;
    TEdit *EditManagerLocalKey;
    TButton *ButtonOK;
    TButton *ButtonCancel;
    
    void __fastcall RadioGroupModeClick(TObject *Sender);
    void __fastcall EditPassphraseChange(TObject *Sender);
    void __fastcall ButtonPassphraseToK0Click(TObject *Sender);
    void __fastcall ButtonGenerateRandomPassphraseClick(TObject *Sender);
    void __fastcall ButtonUseTestPassphraseClick(TObject *Sender);
    void __fastcall ButtonGenerateRandomK0Click(TObject *Sender);
    void __fastcall ButtonUseTestK0Click(TObject *Sender);
    void __fastcall ButtonOKClick(TObject *Sender);
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall FormDestroy(TObject *Sender);
    
private:	// User declarations
    uint8_t FinalK0[32];          // Derived K0 (output)
    uint8_t CurrentK0[32];        // Working K0 during entry
    uint8_t TUID[6];              // Device TUID for Manager Local key
    bool K0Valid;                 // Whether current K0 is valid
    
    void ClearDerivedDisplays();
    void UpdateEntryModeUI();
    bool LoadHexK0(const char* k0_hex);
    void UpdateValidationDisplay();
    void UpdatePassphraseCheckEdits(const SigNet::Crypto::PassphraseChecks& checks);
    void ClearPassphraseCheckEdits();
    void DeriveAndDisplayKeys();
    void ClearSensitiveState();
    String BytesToHex(const uint8_t* data, int length);
    
public:		// User declarations
    __fastcall TK0EntryDialog(TComponent* Owner);
    
    // Set the TUID before showing dialog (required for Manager Local key)
    void SetTUID(const uint8_t* tuid);
    
    // Get the derived K0 (call after ShowModal returns mrOk)
    void GetK0(uint8_t* k0_output);
};

//---------------------------------------------------------------------------
extern PACKAGE TK0EntryDialog *K0EntryDialog;
//---------------------------------------------------------------------------
#endif
