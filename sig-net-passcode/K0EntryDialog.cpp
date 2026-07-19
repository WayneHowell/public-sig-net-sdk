//==============================================================================
// Sig-Net Protocol Framework - K0 Entry Dialog Implementation
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
// Description:  Implementation of K0 entry dialog with passphrase validation.
//==============================================================================

//---------------------------------------------------------------------------
#include <vcl.h>
#pragma hdrstop

#include "K0EntryDialog.h"
#include <stdio.h>
#include <string.h>

static void SecureZeroBuffer(void* ptr, size_t len)
{
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len > 0) {
        *p++ = 0;
        --len;
    }
}
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TK0EntryDialog *K0EntryDialog;

//---------------------------------------------------------------------------
__fastcall TK0EntryDialog::TK0EntryDialog(TComponent* Owner)
    : TForm(Owner)
{
    K0Valid = false;
    memset(FinalK0, 0, 32);
    memset(CurrentK0, 0, 32);
    memset(TUID, 0, 6);
}

//---------------------------------------------------------------------------
void TK0EntryDialog::ClearDerivedDisplays()
{
    EditK0Display->Text = "";
    EditSenderKey->Text = "";
    EditCitizenKey->Text = "";
    EditManagerGlobalKey->Text = "";
    EditManagerLocalKey->Text = "";
}

//---------------------------------------------------------------------------
void TK0EntryDialog::ClearSensitiveState()
{
    SecureZeroBuffer(CurrentK0, sizeof(CurrentK0));
    SecureZeroBuffer(FinalK0, sizeof(FinalK0));
    SecureZeroBuffer(TUID, sizeof(TUID));
    K0Valid = false;

    if (EditPassphrase) { EditPassphrase->Text = ""; }
    if (EditK0Display) { EditK0Display->Text = ""; }
    if (EditSenderKey) { EditSenderKey->Text = ""; }
    if (EditCitizenKey) { EditCitizenKey->Text = ""; }
    if (EditManagerGlobalKey) { EditManagerGlobalKey->Text = ""; }
    if (EditManagerLocalKey) { EditManagerLocalKey->Text = ""; }
}

//---------------------------------------------------------------------------
bool TK0EntryDialog::LoadHexK0(const char* k0_hex)
{
    if (!k0_hex) {
        return false;
    }

    for (int i = 0; i < 32; i++) {
        unsigned int value;
        if (sscanf(k0_hex + (i * 2), "%2x", &value) != 1) {
            return false;
        }
        CurrentK0[i] = (uint8_t)value;
    }

    return true;
}

//---------------------------------------------------------------------------
void TK0EntryDialog::UpdateEntryModeUI()
{
    const int mode = RadioGroupMode->ItemIndex;
    const bool passphrase_mode = (mode == 0);
    const bool root_key_mode = (mode == 1);

    EditPassphrase->Enabled = passphrase_mode;
    ButtonGenerateRandomPassphrase->Enabled = passphrase_mode;
    ButtonUseTestPassphrase->Enabled = passphrase_mode;
    ButtonPassphraseToK0->Enabled = false;
    ButtonGenerateRandomK0->Enabled = root_key_mode;
    ButtonUseTestK0->Enabled = root_key_mode;

    EditPassphrase->Color = passphrase_mode ? clWindow : clBtnFace;
    EditPassphrase->ReadOnly = !passphrase_mode;

    if (!passphrase_mode) {
        EditPassphrase->Text = "";
    }

    memset(CurrentK0, 0, 32);
    K0Valid = false;
    ButtonOK->Enabled = false;
    ClearDerivedDisplays();

    const bool show_checks = passphrase_mode;
    LabelValidation->Visible = !show_checks;
    PanelValidationChecks->Visible = show_checks;

    if (show_checks) {
        ClearPassphraseCheckEdits();
        if (passphrase_mode && Visible) {
            EditPassphrase->SetFocus();
        }
    } else if (root_key_mode) {
        LabelValidation->Caption = "Choose either 'Generate Random K0' or 'Generate Test K0'";
        LabelValidation->Font->Color = clWindowText;
    }
}

//---------------------------------------------------------------------------
void TK0EntryDialog::UpdateValidationDisplay()
{
    if (RadioGroupMode->ItemIndex != 0) {
        return;
    }

    String passphrase = EditPassphrase->Text;

    if (passphrase.IsEmpty()) {
        ClearPassphraseCheckEdits();
        ButtonPassphraseToK0->Enabled = false;
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
        return;
    }

    AnsiString utf8Pass = AnsiString(passphrase);
    SigNet::Crypto::PassphraseChecks checks;
    int32_t result = SigNet::Crypto::AnalysePassphrase(
        utf8Pass.c_str(),
        utf8Pass.Length(),
        &checks
    );

    UpdatePassphraseCheckEdits(checks);

    ButtonPassphraseToK0->Enabled = (result == SigNet::SIGNET_PASSPHRASE_VALID);
    K0Valid = false;
    ButtonOK->Enabled = false;
    ClearDerivedDisplays();
}

//---------------------------------------------------------------------------
void TK0EntryDialog::ClearPassphraseCheckEdits()
{
    EditCheckLength->Caption  = "Length: -";
    EditCheckLength->Font->Color = clWindowText;
    EditCheckClasses->Caption = "Character classes: -";
    EditCheckClasses->Font->Color = clWindowText;
    EditCheckIdentical->Caption = "No triple identical characters: -";
    EditCheckIdentical->Font->Color = clWindowText;
    EditCheckSequential->Caption = "No 4-character sequential run: -";
    EditCheckSequential->Font->Color = clWindowText;
}

//---------------------------------------------------------------------------
void TK0EntryDialog::UpdatePassphraseCheckEdits(const SigNet::Crypto::PassphraseChecks& ch)
{
    char buf[200];

    sprintf(buf, "Length: %d of 10-64 characters", (int)ch.length);
    EditCheckLength->Caption = String(buf);
    EditCheckLength->Font->Color = ch.length_ok ? clGreen : clRed;
    EditCheckLength->Invalidate();

    sprintf(buf, "Character classes: %d of 4 (min 3)  |  Upper: %s  Lower: %s  Digits: %s  Symbols: %s",
        ch.class_count,
        ch.has_upper ? "Yes" : "No",
        ch.has_lower ? "Yes" : "No",
        ch.has_digit ? "Yes" : "No",
        ch.has_symbol ? "Yes" : "No");
    EditCheckClasses->Caption = String(buf);
    EditCheckClasses->Font->Color = ch.classes_ok ? clGreen : clRed;
    EditCheckClasses->Invalidate();

    EditCheckIdentical->Caption = ch.no_identical
        ? "No triple identical characters  (OK)"
        : "FAIL: Triple identical characters found";
    EditCheckIdentical->Font->Color = ch.no_identical ? clGreen : clRed;
    EditCheckIdentical->Invalidate();

    EditCheckSequential->Caption = ch.no_sequential
        ? "No 4-character sequential run  (OK)"
        : "FAIL: 4-character sequential run found";
    EditCheckSequential->Font->Color = ch.no_sequential ? clGreen : clRed;
    EditCheckSequential->Invalidate();
}

//---------------------------------------------------------------------------
void TK0EntryDialog::SetTUID(const uint8_t* tuid)
{
    if (tuid) {
        memcpy(TUID, tuid, 6);
    }
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::FormCreate(TObject *Sender)
{
    // Set up radio group options
    RadioGroupMode->Items->Clear();
    RadioGroupMode->Items->Add("Passcode");
    RadioGroupMode->Items->Add("Root Key (K0)");
    RadioGroupMode->ItemIndex = 0;
    
    // Initialize UI state
    EditPassphrase->Text = "";
    EditK0Display->ReadOnly = true;
    EditK0Display->Text = "";
    
    // Derived keys display
    EditSenderKey->ReadOnly = true;
    EditCitizenKey->ReadOnly = true;
    EditManagerGlobalKey->ReadOnly = true;
    EditManagerLocalKey->ReadOnly = true;
    
    ButtonOK->Enabled = false;
    K0Valid = false;

    LabelInstructions->Caption = 
        "Select an entry method above. K0 is the Root Key for your Sig-Net network.\n"
        "Use passphrase entry or random K0 generation for production. Test K0 is for development only.";

    UpdateEntryModeUI();
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::FormDestroy(TObject *Sender)
{
    ClearSensitiveState();
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::RadioGroupModeClick(TObject *Sender)
{
    UpdateEntryModeUI();
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::ButtonPassphraseToK0Click(TObject *Sender)
{
    if (RadioGroupMode->ItemIndex != 0) {
        return;
    }

    AnsiString utf8Pass = AnsiString(EditPassphrase->Text);
    SigNet::Crypto::PassphraseChecks checks;
    int32_t validation_result = SigNet::Crypto::AnalysePassphrase(
        utf8Pass.c_str(),
        utf8Pass.Length(),
        &checks
    );

    UpdatePassphraseCheckEdits(checks);

    if (validation_result != SigNet::SIGNET_PASSPHRASE_VALID) {
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
        return;
    }

    int32_t result = SigNet::Crypto::DeriveK0FromPassphrase(
        utf8Pass.c_str(),
        utf8Pass.Length(),
        CurrentK0
    );

    if (result == SigNet::SIGNET_SUCCESS) {
        K0Valid = true;
        ButtonOK->Enabled = true;
        DeriveAndDisplayKeys();
    } else {
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
        EditCheckLength->Caption = "Error deriving K0 from passphrase";
        EditCheckLength->Font->Color = clRed;
        EditCheckLength->Invalidate();
    }
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::ButtonGenerateRandomPassphraseClick(TObject *Sender)
{
    if (RadioGroupMode->ItemIndex != 0) {
        return;
    }

    char generated_passphrase[11];  // 10 chars + null terminator

    int32_t result = SigNet::Crypto::GenerateRandomPassphrase(
        generated_passphrase,
        sizeof(generated_passphrase)
    );

    if (result != SigNet::SIGNET_SUCCESS) {
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
        EditCheckLength->Caption = "Error generating random passphrase";
        EditCheckLength->Font->Color = clRed;
        EditCheckLength->Invalidate();
        SecureZeroBuffer(generated_passphrase, sizeof(generated_passphrase));
        return;
    }

    EditPassphrase->Text = String(generated_passphrase);

    // Show per-test validation results for the generated passphrase
    SigNet::Crypto::PassphraseChecks checks;
    SigNet::Crypto::AnalysePassphrase(generated_passphrase, strlen(generated_passphrase), &checks);
    UpdatePassphraseCheckEdits(checks);

    result = SigNet::Crypto::DeriveK0FromPassphrase(
        generated_passphrase,
        strlen(generated_passphrase),
        CurrentK0
    );

    if (result == SigNet::SIGNET_SUCCESS) {
        K0Valid = true;
        ButtonOK->Enabled = true;
        DeriveAndDisplayKeys();
    } else {
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
    }

    SecureZeroBuffer(generated_passphrase, sizeof(generated_passphrase));
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::ButtonUseTestPassphraseClick(TObject *Sender)
{
    if (RadioGroupMode->ItemIndex != 0) {
        return;
    }

    EditPassphrase->Text = String(SigNet::TEST_PASSPHRASE);
    UpdateValidationDisplay();
    if (ButtonPassphraseToK0->Enabled) {
        ButtonPassphraseToK0Click(Sender);
    }
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::ButtonGenerateRandomK0Click(TObject *Sender)
{
    int32_t result = SigNet::Crypto::GenerateRandomK0(CurrentK0);

    if (result == SigNet::SIGNET_SUCCESS) {
        K0Valid = true;
        ButtonOK->Enabled = true;
        LabelValidation->Caption = "Random K0 generated successfully";
        LabelValidation->Font->Color = clGreen;
        DeriveAndDisplayKeys();
    } else {
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
        LabelValidation->Caption = "Error generating random K0";
        LabelValidation->Font->Color = clRed;
    }
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::ButtonUseTestK0Click(TObject *Sender)
{
    if (LoadHexK0(SigNet::TEST_K0)) {
        K0Valid = true;
        ButtonOK->Enabled = true;
        LabelValidation->Caption = "Built-in Test K0 loaded";
        LabelValidation->Font->Color = clGreen;
        DeriveAndDisplayKeys();
    } else {
        K0Valid = false;
        ButtonOK->Enabled = false;
        ClearDerivedDisplays();
        LabelValidation->Caption = "Error loading built-in Test K0";
        LabelValidation->Font->Color = clRed;
    }
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::EditPassphraseChange(TObject *Sender)
{
    if (RadioGroupMode->ItemIndex != 0) {
        return;  // Only validate in passphrase mode
    }

    UpdateValidationDisplay();
}

//---------------------------------------------------------------------------
void TK0EntryDialog::DeriveAndDisplayKeys()
{
    if (!K0Valid) {
        return;
    }
    
    // Display K0 in hex (read-only)
    EditK0Display->Text = BytesToHex(CurrentK0, 32);
    
    // Derive and display all role keys
    uint8_t sender_key[32];
    uint8_t citizen_key[32];
    uint8_t manager_global_key[32];
    uint8_t manager_local_key[32];
    
    SigNet::Crypto::DeriveSenderKey(CurrentK0, sender_key);
    SigNet::Crypto::DeriveCitizenKey(CurrentK0, citizen_key);
    SigNet::Crypto::DeriveManagerGlobalKey(CurrentK0, manager_global_key);
    SigNet::Crypto::DeriveManagerLocalKey(CurrentK0, TUID, manager_local_key);
    
    EditSenderKey->Text = BytesToHex(sender_key, 32);
    EditCitizenKey->Text = BytesToHex(citizen_key, 32);
    EditManagerGlobalKey->Text = BytesToHex(manager_global_key, 32);
    EditManagerLocalKey->Text = BytesToHex(manager_local_key, 32);
    
    // Secure erase the derived keys from stack
    memset(sender_key, 0, 32);
    memset(citizen_key, 0, 32);
    memset(manager_global_key, 0, 32);
    memset(manager_local_key, 0, 32);
}

//---------------------------------------------------------------------------
String TK0EntryDialog::BytesToHex(const uint8_t* data, int length)
{
    String hex = "";
    char buffer[3];
    
    for (int i = 0; i < length; i++) {
        sprintf(buffer, "%02x", data[i]);
        hex += String(buffer);
    }
    
    return hex;
}

//---------------------------------------------------------------------------
void __fastcall TK0EntryDialog::ButtonOKClick(TObject *Sender)
{
    if (K0Valid) {
        memcpy(FinalK0, CurrentK0, 32);
        ModalResult = mrOk;
    }
}

//---------------------------------------------------------------------------
void TK0EntryDialog::GetK0(uint8_t* k0_output)
{
    if (k0_output) {
        memcpy(k0_output, FinalK0, 32);
    }
}
//---------------------------------------------------------------------------
