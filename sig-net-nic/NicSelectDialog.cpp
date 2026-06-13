//==============================================================================
// Sig-Net Protocol Framework - NIC Selection Dialog Implementation
//==============================================================================

#include <vcl.h>
#pragma hdrstop
#include "NicSelectDialog.h"
#pragma link "iphlpapi.lib"
//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.dfm"
TNicSelectDialog *NicSelectDialog;
//---------------------------------------------------------------------------

namespace {

#ifndef IF_TYPE_IEEE80211
#define IF_TYPE_IEEE80211 71
#endif

bool IsPhysicalAdapter(const IP_ADAPTER_INFO* adapter)
{
    if (!adapter) {
        return false;
    }

    const UINT type = adapter->Type;
    return (type == MIB_IF_TYPE_ETHERNET || type == IF_TYPE_IEEE80211);
}

bool IsUnusableIPv4(const AnsiString& ip)
{
    return ip.IsEmpty() || ip == "0.0.0.0" || ip == "127.0.0.1";
}

} // namespace

namespace SigNet {

AnsiString SelectDefaultStartupNicIP()
{
    AnsiString preferred_2;
    AnsiString preferred_192;
    AnsiString first_physical;

    ULONG buf_len = sizeof(IP_ADAPTER_INFO) * 32;
    IP_ADAPTER_INFO* adapter_buf = (IP_ADAPTER_INFO*)malloc(buf_len);
    if (!adapter_buf) {
        return "127.0.0.1";
    }

    DWORD ret = GetAdaptersInfo(adapter_buf, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(adapter_buf);
        adapter_buf = (IP_ADAPTER_INFO*)malloc(buf_len);
        if (!adapter_buf) {
            return "127.0.0.1";
        }
        ret = GetAdaptersInfo(adapter_buf, &buf_len);
    }

    if (ret == NO_ERROR) {
        IP_ADAPTER_INFO* adapter = adapter_buf;
        while (adapter) {
            if (IsPhysicalAdapter(adapter)) {
                IP_ADDR_STRING* addr = &adapter->IpAddressList;
                while (addr) {
                    AnsiString ip = AnsiString(addr->IpAddress.String).Trim();
                    if (!IsUnusableIPv4(ip)) {
                        if (first_physical.IsEmpty()) {
                            first_physical = ip;
                        }
                        if (preferred_2.IsEmpty() && ip.Pos("2.") == 1) {
                            preferred_2 = ip;
                        }
                        if (preferred_192.IsEmpty() && ip.Pos("192.") == 1) {
                            preferred_192 = ip;
                        }
                    }
                    addr = addr->Next;
                }
            }
            adapter = adapter->Next;
        }
    }

    free(adapter_buf);

    if (!preferred_2.IsEmpty()) {
        return preferred_2;
    }
    if (!preferred_192.IsEmpty()) {
        return preferred_192;
    }
    if (!first_physical.IsEmpty()) {
        return first_physical;
    }
    return "127.0.0.1";
}

} // namespace SigNet

//---------------------------------------------------------------------------
__fastcall TNicSelectDialog::TNicSelectDialog(TComponent* Owner)
    : TForm(Owner), FSelectedIP("127.0.0.1"), FCurrentIP("127.0.0.1")
{
}
//---------------------------------------------------------------------------
void TNicSelectDialog::SetCurrentIP(const AnsiString& ip)
{
    FCurrentIP  = ip;
    FSelectedIP = ip;
}
//---------------------------------------------------------------------------
AnsiString TNicSelectDialog::GetSelectedIP() const
{
    return FSelectedIP;
}
//---------------------------------------------------------------------------
void TNicSelectDialog::PopulateList()
{
    ListBoxNics->Clear();
    int preselect = -1;

    // Always offer loopback as the first entry
    AnsiString loopback = "127.0.0.1  -  Loopback";
    ListBoxNics->Items->AddObject(loopback, (TObject*)0);
    if (FCurrentIP == "127.0.0.1")
        preselect = 0;

    // Enumerate adapters using GetAdaptersInfo (IPv4, works on XP+)
    ULONG buf_len = sizeof(IP_ADAPTER_INFO) * 32;
    IP_ADAPTER_INFO* adapter_buf = (IP_ADAPTER_INFO*)malloc(buf_len);
    if (!adapter_buf)
    {
        if (preselect >= 0) ListBoxNics->ItemIndex = preselect;
        ButtonOk->Enabled = (ListBoxNics->ItemIndex >= 0);
        return;
    }

    DWORD ret = GetAdaptersInfo(adapter_buf, &buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW)
    {
        free(adapter_buf);
        adapter_buf = (IP_ADAPTER_INFO*)malloc(buf_len);
        if (!adapter_buf)
        {
            if (preselect >= 0) ListBoxNics->ItemIndex = preselect;
            ButtonOk->Enabled = (ListBoxNics->ItemIndex >= 0);
            return;
        }
        ret = GetAdaptersInfo(adapter_buf, &buf_len);
    }

    if (ret == NO_ERROR)
    {
        IP_ADAPTER_INFO* adapter = adapter_buf;
        while (adapter)
        {
            IP_ADDR_STRING* addr = &adapter->IpAddressList;
            while (addr)
            {
                AnsiString ip = AnsiString(addr->IpAddress.String);
                // Skip unassigned / loopback (already listed)
                if (ip != "0.0.0.0" && ip != "127.0.0.1")
                {
                    AnsiString desc = AnsiString(adapter->Description);
                    AnsiString entry = ip + "  -  " + desc;
                    // Truncate very long descriptions for readability
                    if (entry.Length() > 80)
                        entry = entry.SubString(1, 80) + "...";
                    int idx = ListBoxNics->Items->Add(entry);
                    if (ip == FCurrentIP)
                        preselect = idx;
                }
                addr = addr->Next;
            }
            adapter = adapter->Next;
        }
    }

    free(adapter_buf);

    if (preselect >= 0)
        ListBoxNics->ItemIndex = preselect;
    else if (ListBoxNics->Count > 0)
        ListBoxNics->ItemIndex = 0;

    ButtonOk->Enabled = (ListBoxNics->ItemIndex >= 0);
}
//---------------------------------------------------------------------------
void __fastcall TNicSelectDialog::FormShow(TObject* /*Sender*/)
{
    PopulateList();
}
//---------------------------------------------------------------------------
void __fastcall TNicSelectDialog::ListBoxNicsClick(TObject* /*Sender*/)
{
    ButtonOk->Enabled = (ListBoxNics->ItemIndex >= 0);
}
//---------------------------------------------------------------------------
void __fastcall TNicSelectDialog::ButtonOkClick(TObject* /*Sender*/)
{
    int idx = ListBoxNics->ItemIndex;
    if (idx >= 0)
    {
        // Extract the IP from the entry (everything before "  -  ")
        AnsiString entry = ListBoxNics->Items->Strings[idx];
        int sep = entry.Pos("  -  ");
        if (sep > 0)
            FSelectedIP = entry.SubString(1, sep - 1).Trim();
        else
            FSelectedIP = entry.Trim();
    }
    ModalResult = mrOk;
}
//---------------------------------------------------------------------------
void __fastcall TNicSelectDialog::ButtonCancelClick(TObject* /*Sender*/)
{
    ModalResult = mrCancel;
}
//---------------------------------------------------------------------------
