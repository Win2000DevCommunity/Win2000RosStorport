/*
 * PROJECT:     ReactOS Compatibility Layer Shell Extension
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     CLayerUIPropPage implementation
 * COPYRIGHT:   Copyright 2015-2017 Mark Jansen (mark.jansen@reactos.org)
 */

#include "precomp.h"

#include <shlwapi.h>
#include <shellapi.h>
#include <shellutils.h>
#include <strsafe.h>
#include <apphelp.h>
#include <windowsx.h>
#include <sfc.h>

const GUID CLSID_CLayerUIPropPage = { 0x513D916F, 0x2A8E, 0x4F51, { 0xAE, 0xAB, 0x0C, 0xBC, 0x76, 0xFB, 0x1A, 0xF8 } };
#define ACP_WNDPROP L"{513D916F-2A8E-4F51-AEAB-0CBC76FB1AF8}.Prop"

#define GPLK_USER 1
#define GPLK_MACHINE 2
#define MAX_LAYER_LENGTH 256

static struct {
    const PCWSTR Display;
    const PCWSTR Name;
} g_CompatModes[] = {
    { L"Windows 95", L"WIN95" },
    { L"Windows 98/ME", L"WIN98" },
    { L"Windows NT 4.0 (SP5)", L"NT4SP5" },
    { L"Windows 2000", L"WIN2000" },
    { L"Windows XP (SP2)", L"WINXPSP2" },
    { L"Windows XP (SP3)", L"WINXPSP3" },
    { L"Windows Server 2003 (SP1)", L"WINSRV03SP1" },
#if 0
    { L"Windows Server 2008 (SP1)", L"WINSRV08SP1" },
    { L"Windows Vista", L"VISTARTM" },
    { L"Windows Vista (SP1)", L"VISTASP1" },
    { L"Windows Vista (SP2)", L"VISTASP2" },
    { L"Windows 7", L"WIN7RTM" },
#endif
    { NULL, NULL }
};

static struct {
    const PCWSTR Name;
    DWORD Id;
} g_Layers[] = {
    { L"256COLOR", IDC_CHKRUNIN256COLORS },
    { L"640X480", IDC_CHKRUNIN640480RES },
    { L"DISABLETHEMES", IDC_CHKDISABLEVISUALTHEMES },
#if 0
    { L"DISABLEDWM", IDC_??, TRUE },
    { L"HIGHDPIAWARE", IDC_??, TRUE },
    { L"RUNASADMIN", IDC_??, TRUE },
#endif
    { NULL, 0 }
};

static const WCHAR* g_AllowedExtensions[] = {
    L".exe",
    L".msi",
    L".pif",
    L".bat",
    L".cmd",
    0
};

BOOL IsBuiltinLayer(PCWSTR Name)
{
    size_t n;

    for (n = 0; g_Layers[n].Name; ++n)
    {
        if (!wcsicmp(g_Layers[n].Name, Name))
        {
            return TRUE;
        }
    }

    for (n = 0; g_CompatModes[n].Name; ++n)
    {
        if (!wcsicmp(g_CompatModes[n].Name, Name))
        {
            return TRUE;
        }
    }
    return FALSE;
}


void ACDBG_FN(PCSTR FunctionName, PCWSTR Format, ...)
{
    WCHAR Buffer[512];
    WCHAR* Current = Buffer;
    size_t Length = _countof(Buffer);

    StringCchPrintfExW(Current, Length, &Current, &Length, STRSAFE_NULL_ON_FAILURE, L"[%-20S] ", FunctionName);
    va_list ArgList;
    va_start(ArgList, Format);
    StringCchVPrintfExW(Current, Length, &Current, &Length, STRSAFE_NULL_ON_FAILURE, Format, ArgList);
    va_end(ArgList);
    OutputDebugStringW(Buffer);
}

#define ACDBG(fmt, ...)  ACDBG_FN(__FUNCTION__, fmt, ##__VA_ARGS__ )



CLayerUIPropPage::CLayerUIPropPage()
: m_IsSfcProtected(FALSE)
, m_AllowPermLayer(FALSE)
, m_LayerQueryFlags(GPLK_USER)  /* TODO: When do we read from HKLM? */
, m_RegistryOSMode(0)
, m_OSMode(0)
, m_RegistryEnabledLayers(0)
, m_EnabledLayers(0)
{
    CComBSTR title;
    title.LoadString(g_hModule, IDS_COMPAT_TITLE);
    m_psp.pszTitle = title.Detach();
    m_psp.dwFlags |= PSP_USETITLE;
}

CLayerUIPropPage::~CLayerUIPropPage()
{
    CComBSTR title;
    title.Attach((BSTR)m_psp.pszTitle);
}

HRESULT CLayerUIPropPage::InitFile(PCWSTR Filename)
{
    CString ExpandedFilename;
    DWORD dwRequired = ExpandEnvironmentStringsW(Filename, NULL, 0);
    if (dwRequired > 0)
    {
        LPWSTR Buffer = ExpandedFilename.GetBuffer(dwRequired);
        DWORD dwReturned = ExpandEnvironmentStringsW(Filename, Buffer, dwRequired);
        if (dwRequired == dwReturned)
        {
            ExpandedFilename.ReleaseBufferSetLength(dwReturned - 1);
            ACDBG(L"Expanded '%s' => '%s'\r\n", Filename, (PCWSTR)ExpandedFilename);
        }
        else
        {
            ExpandedFilename.ReleaseBufferSetLength(0);
            ExpandedFilename = Filename;
            ACDBG(L"Failed during expansion '%s'\r\n", Filename);
        }
    }
    else
    {
        ACDBG(L"Failed to expand '%s'\r\n", Filename);
        ExpandedFilename = Filename;
    }
    PCWSTR pwszExt = PathFindExtensionW(ExpandedFilename);
    if (!pwszExt)
    {
        ACDBG(L"Failed to find an extension: '%s'\r\n", (PCWSTR)ExpandedFilename);
        return E_FAIL;
    }
    if (!wcsicmp(pwszExt, L".lnk"))
    {
        WCHAR Buffer[MAX_PATH];
        if (!GetExeFromLnk(ExpandedFilename, Buffer, _countof(Buffer)))
        {
            ACDBG(L"Failed to read link target from: '%s'\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
        if (!wcsicmp(Buffer, ExpandedFilename))
        {
            ACDBG(L"Link redirects to itself: '%s'\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
        return InitFile(Buffer);
    }

    CString tmp;
    if (tmp.GetEnvironmentVariable(L"SystemRoot"))
    {
        tmp += L"\\System32";
        if (ExpandedFilename.GetLength() >= tmp.GetLength() &&
            ExpandedFilename.Left(tmp.GetLength()).MakeLower() == tmp.MakeLower())
        {
            ACDBG(L"Ignoring System32: %s\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
        tmp.GetEnvironmentVariable(L"SystemRoot");
        tmp += L"\\WinSxs";
        if (ExpandedFilename.GetLength() >= tmp.GetLength() &&
            ExpandedFilename.Left(tmp.GetLength()).MakeLower() == tmp.MakeLower())
        {
            ACDBG(L"Ignoring WinSxs: %s\r\n", (PCWSTR)ExpandedFilename);
            return E_FAIL;
        }
    }

    for (size_t n = 0; g_AllowedExtensions[n]; ++n)
    {
        if (!wcsicmp(g_AllowedExtensions[n], pwszExt))
        {
            m_Filename = ExpandedFilename;
            ACDBG(L"Got: %s\r\n", (PCWSTR)ExpandedFilename);
            m_IsSfcProtected = SfcIsFileProtected(NULL, m_Filename);
            m_AllowPermLayer = AllowPermLayer(ExpandedFilename);
            return S_OK;
        }
    }
    ACDBG(L"Extension not included: '%s'\r\n", pwszExt);
    return E_FAIL;
}

static BOOL GetLayerInfo(PCWSTR Filename, DWORD QueryFlags, PDWORD OSMode, PDWORD Enabledlayers, CSimpleArray<CString>& customLayers)
{
    WCHAR wszLayers[MAX_LAYER_LENGTH] = { 0 };
    DWORD dwBytes = sizeof(wszLayers);

    *OSMode = *Enabledlayers = 0;
    customLayers.RemoveAll();
    if (!SdbGetPermLayerKeys(Filename, wszLayers, &dwBytes, QueryFlags))
        return FALSE;

    for (PWCHAR Layer = wcstok(wszLayers, L" "); Layer; Layer = wcstok(NULL, L" "))
    {
        size_t n;
        for (n = 0; g_Layers[n].Name; ++n)
        {
            if (!wcsicmp(g_Layers[n].Name, Layer))
            {
                *Enabledlayers |= (1<<n);
                break;
            }
        }
        /* Did we find it? */
        if (g_Layers[n].Name)
            continue;

        for (n = 0; g_CompatModes[n].Name; ++n)
        {
            if (!wcsicmp(g_CompatModes[n].Name, Layer))
            {
                *OSMode = n+1;
                break;
            }
        }
        /* Did we find it? */
        if (g_CompatModes[n].Name)
            continue;

        /* Must be a 'custom' layer */
        customLayers.Add(Layer);
    }
    return TRUE;
}

int CLayerUIPropPage::OnSetActive()
{
    if (!GetLayerInfo(m_Filename, m_LayerQueryFlags, &m_RegistryOSMode, &m_RegistryEnabledLayers, m_RegistryCustomLayers))
        m_RegistryOSMode = m_RegistryEnabledLayers = 0;

    for (size_t n = 0; g_Layers[n].Name; ++n)
        CheckDlgButton(g_Layers[n].Id, (m_RegistryEnabledLayers & (1<<n)) ? BST_CHECKED : BST_UNCHECKED);

    CheckDlgButton(IDC_CHKRUNCOMPATIBILITY, m_RegistryOSMode ? BST_CHECKED : BST_UNCHECKED);

    if (m_RegistryOSMode)
        ComboBox_SetCurSel(GetDlgItem(IDC_COMPATIBILITYMODE), m_RegistryOSMode-1);

    m_CustomLayers = m_RegistryCustomLayers;

    UpdateControls();

    return 0;
}


static BOOL ArrayEquals(const CSimpleArray<CString>& lhs, const CSimpleArray<CString>& rhs)
{
    if (lhs.GetSize() != rhs.GetSize())
        return FALSE;

    for (int n = 0; n < lhs.GetSize(); ++n)
    {
        if (lhs[n] != rhs[n])
            return FALSE;
    }
    return TRUE;
}

BOOL CLayerUIPropPage::HasChanges() const
{
    if (m_RegistryEnabledLayers != m_EnabledLayers)
        return TRUE;

    if (m_RegistryOSMode != m_OSMode)
        return TRUE;

    if (!ArrayEquals(m_RegistryCustomLayers, m_CustomLayers))
        return TRUE;

    return FALSE;
}

int CLayerUIPropPage::OnApply()
{
    if (HasChanges())
    {
        BOOL bMachine = m_LayerQueryFlags == GPLK_MACHINE;

        for (size_t n = 0; g_CompatModes[n].Name; ++n)
            SetPermLayerState(m_Filename, g_CompatModes[n].Name, 0, bMachine, (n+1) == m_OSMode);

        for (size_t n = 0; g_Layers[n].Name; ++n)
        {
            SetPermLayerState(m_Filename, g_Layers[n].Name, 0, bMachine, ((1<<n) & m_EnabledLayers) != 0);
        }

        /* Disable all old values */
        for (int j = 0; j < m_RegistryCustomLayers.GetSize(); j++)
        {
            SetPermLayerState(m_Filename, m_RegistryCustomLayers[j].GetString(), 0, bMachine, FALSE);
        }

        /* Enable all new values */
        for (int j = 0; j < m_CustomLayers.GetSize(); j++)
        {
            SetPermLayerState(m_Filename, m_CustomLayers[j].GetString(), 0, bMachine, TRUE);
        }

        SHChangeNotify(SHCNE_UPDATEITEM, SHCNF_PATHW, (PCWSTR)m_Filename, NULL);
    }

    return PSNRET_NOERROR;
}

LRESULT CLayerUIPropPage::OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL &bHandled)
{
    HWND cboMode = GetDlgItem(IDC_COMPATIBILITYMODE);
    for (size_t n = 0; g_CompatModes[n].Display; ++n)
        ComboBox_AddString(cboMode, g_CompatModes[n].Display);
    ComboBox_SetCurSel(cboMode, 5);

    CComBSTR explanation;
    if (!m_AllowPermLayer)
    {
        explanation.LoadString(g_hModule, IDS_FAILED_NETWORK);
        DisableControls();
        ACDBG(L"AllowPermLayer returned FALSE\r\n");
    }
    else if (m_IsSfcProtected)
    {
        explanation.LoadString(g_hModule, IDS_FAILED_PROTECTED);
        DisableControls();
        ACDBG(L"Protected OS file\r\n");
    }
    else
    {
        return TRUE;
    }
    SetDlgItemTextW(IDC_EXPLANATION, explanation);
    return TRUE;
}

INT_PTR CLayerUIPropPage::DisableControls()
{
    ::EnableWindow(GetDlgItem(IDC_COMPATIBILITYMODE), 0);
    ::EnableWindow(GetDlgItem(IDC_CHKRUNCOMPATIBILITY), 0);
    for (size_t n = 0; g_Layers[n].Name; ++n)
        ::EnableWindow(GetDlgItem(g_Layers[n].Id), 0);
    ::EnableWindow(GetDlgItem(IDC_EDITCOMPATIBILITYMODES), 0);
    return TRUE;
}

void CLayerUIPropPage::UpdateControls()
{
    m_OSMode = 0, m_EnabledLayers = 0;
    BOOL ModeEnabled = IsDlgButtonChecked(IDC_CHKRUNCOMPATIBILITY);
    if (ModeEnabled)
        m_OSMode = ComboBox_GetCurSel(GetDlgItem(IDC_COMPATIBILITYMODE))+1;
    ::EnableWindow(GetDlgItem(IDC_COMPATIBILITYMODE), ModeEnabled);

    for (size_t n = 0; g_Layers[n].Name; ++n)
    {
        m_EnabledLayers |= IsDlgButtonChecked(g_Layers[n].Id) ? (1<<n) : 0;
        ::ShowWindow(GetDlgItem(g_Layers[n].Id), SW_SHOW);
    }

    CStringW customLayers;
    for (int j = 0; j < m_CustomLayers.GetSize(); ++j)
    {
        if (j > 0)
            customLayers += L", ";
        customLayers += m_CustomLayers[j];
    }
    SetDlgItemTextW(IDC_ENABLED_LAYERS, customLayers);

    SetModified(HasChanges());
}

LRESULT CLayerUIPropPage::OnCtrlCommand(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL &bHandled)
{
    UpdateControls();
    return 0;
}

LRESULT CLayerUIPropPage::OnEditModes(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL &bHandled)
{
    if (DialogBoxParamW(g_hModule, MAKEINTRESOURCEW(IDD_EDITCOMPATIBILITYMODES), m_hWnd, EditModesProc, (LPARAM)this) == IDOK)
        UpdateControls();
    return 0;
}

LRESULT CLayerUIPropPage::OnClickNotify(INT uCode, LPNMHDR hdr, BOOL& bHandled)
{
    if (hdr->idFrom == IDC_INFOLINK)
        ShellExecute(NULL, L"open", L"https://www.reactos.org/forum/viewforum.php?f=4", NULL, NULL, SW_SHOW);
    return 0;
}

static void ListboxChanged(HWND hWnd)
{
    int Sel = ListBox_GetCurSel(GetDlgItem(hWnd, IDC_COMPATIBILITYMODE));
    EnableWindow(GetDlgItem(hWnd, IDC_EDIT), Sel >= 0);
    EnableWindow(GetDlgItem(hWnd, IDC_DELETE), Sel >= 0);
}

static void OnAdd(HWND hWnd)
{
    HWND Combo = GetDlgItem(hWnd, IDC_NEWCOMPATIBILITYMODE);
    
    int Length = ComboBox_GetTextLength(Combo);
    CComBSTR Str(Length);
    ComboBox_GetText(Combo, Str, Length+1);
    HWND List = GetDlgItem(hWnd, IDC_COMPATIBILITYMODE);
    int Index = ListBox_FindStringExact(List, -1, Str);
    if (Index == LB_ERR)
        Index = ListBox_AddString(List, Str);
    ListBox_SetCurSel(List, Index);
    ListboxChanged(hWnd);
    ComboBox_SetCurSel(Combo, -1);
    SetFocus(Combo);
}

static BOOL ComboHasData(HWND hWnd)
{
    HWND Combo = GetDlgItem(hWnd, IDC_NEWCOMPATIBILITYMODE);
    if (ComboBox_GetCurSel(Combo) >= 0)
        return TRUE;
    ULONG Len = ComboBox_GetTextLength(Combo);
    return Len > 0;
}

INT_PTR CALLBACK CLayerUIPropPage::EditModesProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    CLayerUIPropPage* page = NULL;

    switch (uMsg)
    {
    case WM_INITDIALOG:
        page = (CLayerUIPropPage*)lParam;
        page->AddRef();
        ::SetProp(hWnd, ACP_WNDPROP, page);
        {
            HWND Combo = ::GetDlgItem(hWnd, IDC_NEWCOMPATIBILITYMODE);
            CComObject<CLayerStringList> pList;

            while (TRUE)
            {
                CComHeapPtr<OLECHAR> str;
                HRESULT hr = pList.Next(1, &str, NULL);
                if (hr != S_OK)
                    break;
                ComboBox_AddString(Combo, str);
            }

            HWND List = ::GetDlgItem(hWnd, IDC_COMPATIBILITYMODE);
            for (int n = 0; n < page->m_CustomLayers.GetSize(); ++n)
            {
                const WCHAR* Str = page->m_CustomLayers[n].GetString();
                int Index = ListBox_FindStringExact(List, -1, Str);
                if (Index == LB_ERR)
                    Index = ListBox_AddString(List, Str);
            }
        }
        break;
    case WM_ENDSESSION:
    case WM_DESTROY:
        page = (CLayerUIPropPage*)::GetProp(hWnd, ACP_WNDPROP);
        ::RemoveProp(hWnd, ACP_WNDPROP);
        page->Release();
        break;

    case WM_COMMAND:
        switch(LOWORD(wParam))
        {
        case IDC_ADD:
            OnAdd(hWnd);
            break;
        case IDC_EDIT:
        {
            HWND List = ::GetDlgItem(hWnd, IDC_COMPATIBILITYMODE);
            int Cur = ListBox_GetCurSel(List);
            int Length = ListBox_GetTextLen(List, Cur);
            CComBSTR Str(Length);
            ListBox_GetText(List, Cur, Str);
            ListBox_DeleteString(List, Cur);
            HWND Combo = ::GetDlgItem(hWnd, IDC_NEWCOMPATIBILITYMODE);
            ComboBox_SetCurSel(Combo, -1);
            ::SetWindowText(Combo,Str);
            ListboxChanged(hWnd);
            ComboBox_SetEditSel(Combo, 30000, 30000);
            ::SetFocus(Combo);
        }
            break;
        case IDC_DELETE:
        {
            HWND List = ::GetDlgItem(hWnd, IDC_COMPATIBILITYMODE);
            ListBox_DeleteString(List, ListBox_GetCurSel(List));
            ListboxChanged(hWnd);
        }
            break;
        case IDC_COMPATIBILITYMODE:
            ListboxChanged(hWnd);
            break;
        case IDC_NEWCOMPATIBILITYMODE:
        {
            ::EnableWindow(::GetDlgItem(hWnd, IDC_ADD), ComboHasData(hWnd));
        }
            break;
        case IDOK:
            /* Copy from list! */
        {
            if (ComboHasData(hWnd))
            {
                CComBSTR question, title;
                title.LoadString(g_hModule, IDS_COMPAT_TITLE);
                question.LoadString(g_hModule, IDS_YOU_DID_NOT_ADD);
                int result = ::MessageBoxW(hWnd, question, title, MB_YESNOCANCEL | MB_ICONQUESTION);
                switch (result)
                {
                case IDYES:
                    OnAdd(hWnd);
                    break;
                case IDNO:
                    break;
                case IDCANCEL:
                    return FALSE;
                }
            }

            page = (CLayerUIPropPage*)::GetProp(hWnd, ACP_WNDPROP);

            HWND List = ::GetDlgItem(hWnd, IDC_COMPATIBILITYMODE);
            int Count = ListBox_GetCount(List);
            page->m_CustomLayers.RemoveAll();
            for (int Cur = 0; Cur < Count; ++Cur)
            {
                int Length = ListBox_GetTextLen(List, Cur);
                CString Str;
                LPWSTR Buffer = Str.GetBuffer(Length + 1);
                ListBox_GetText(List, Cur, Buffer);
                Str.ReleaseBuffer(Length);
                page->m_CustomLayers.Add(Str);
            }
        }
        /* Fall trough */
        case IDCANCEL:
            ::EndDialog(hWnd, LOWORD(wParam));
            break;
        }
        break;
    case WM_CLOSE:
        ::EndDialog(hWnd, IDCANCEL);
        break;
    }
    return FALSE;
}

static BOOL DisableShellext()
{
    HKEY hkey;
    LSTATUS ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat", 0, KEY_QUERY_VALUE, &hkey);
    BOOL Disable = FALSE;
    if (ret == ERROR_SUCCESS)
    {
        DWORD dwValue = 0;
        DWORD type, size = sizeof(dwValue);
        ret = RegQueryValueExW(hkey, L"DisableEngine", NULL, &type, (PBYTE)&dwValue, &size);
        if (ret == ERROR_SUCCESS && type == REG_DWORD)
        {
            Disable = !!dwValue;
        }
        if (!Disable)
        {
            size = sizeof(dwValue);
            ret = RegQueryValueExW(hkey, L"DisablePropPage", NULL, &type, (PBYTE)&dwValue, &size);
            if (ret == ERROR_SUCCESS && type == REG_DWORD)
            {
                Disable = !!dwValue;
            }
        }

        RegCloseKey(hkey);
    }
    return Disable;
}

STDMETHODIMP CLayerUIPropPage::Initialize(LPCITEMIDLIST pidlFolder, LPDATAOBJECT pDataObj, HKEY hkeyProgID)
{
    FORMATETC etc = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM stg;

    if (DisableShellext())
        return E_ACCESSDENIED;

    HRESULT hr = pDataObj->GetData(&etc, &stg);
    if (FAILED(hr))
    {
        ACDBG(L"Failed to retrieve Data from pDataObj.\r\n");
        return E_INVALIDARG;
    }
    hr = E_FAIL;
    HDROP hdrop = (HDROP)GlobalLock(stg.hGlobal);
    if (hdrop)
    {
        UINT uNumFiles = DragQueryFileW(hdrop, 0xFFFFFFFF, NULL, 0);
        if (uNumFiles == 1)
        {
            WCHAR szFile[MAX_PATH * 2];
            if (DragQueryFileW(hdrop, 0, szFile, _countof(szFile)))
            {
                this->AddRef();
                hr = InitFile(szFile);
            }
            else
            {
                ACDBG(L"Failed to query the file.\r\n");
            }
        }
        else
        {
            ACDBG(L"Invalid number of files: %d\r\n", uNumFiles);
        }
        GlobalUnlock(stg.hGlobal);
    }
    else
    {
        ACDBG(L"Could not lock stg.hGlobal\r\n");
    }
    ReleaseStgMedium(&stg);
    return hr;
}
