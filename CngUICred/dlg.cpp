#include "stdafx.h"
#include "UiContext.h"
#include "resource.h"
_NT_BEGIN
#include "../log/log.h"
#include "../QI/dump.h"
#include "../QI/helpers.h"
#include "WrappedCred.h"
#include "miniwnd.h"

struct GUDT 
{
	CWrapperCredential* pMycpc;
	ICredentialProviderCredentialEvents4* pEvent;
	BOOLEAN bSet;
};

class CredDlg : public YDlg
{
	HICON m_hi[2]={};
	HWND m_hwnd;
	CWrapperCredential* m_pMycpc;
	ICredentialProviderCredentialEvents4* m_pEvent;
	BOOLEAN m_bSet;

	virtual BOOL OnInitDialog(HWND hwnd)
	{
		ShowWindow(m_hwnd, SW_HIDE);
		SetWindowTextW(hwnd, m_bSet ? L"Set Password" : L"Get Password");
		HICON hi;
		static const ULONG ic[] = { ICON_BIG, ICON_SMALL };
		static const ULONG smx[] = { SM_CXICON, SM_CXSMICON };
		static const ULONG smy[] = { SM_CYICON, SM_CYSMICON };
		ULONG n = _countof(ic) - 1;
		do 
		{
			if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(1), 
				GetSystemMetrics(smx[n]), GetSystemMetrics(smy[n]), &hi))
			{
				SendMessageW(hwnd, WM_SETICON, ic[n], (LPARAM)hi);
				m_hi[n] = hi;
			}
		} while (n--);

		return TRUE;
	}

	virtual INT_PTR DlgProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM /*lParam*/)
	{
		switch (umsg)
		{
		case WM_COMMAND:
			switch(wParam)
			{
			case IDOK:
				m_pMycpc->Set(new((PBYTE)L"0", sizeof(WCHAR)) CNG_CRED_UI_DATA(
					CNG_CREDUI_SCENARIO::Get, FALSE, CNG_KEY_PROTECTION_LEVEL::RequirePassword));
				m_pEvent->RequestSerialization();
				break;
			}
			break;

		case WM_NCDESTROY:
			umsg = _countof(m_hi);
			do 
			{
				if (HICON hi = m_hi[--umsg])
				{
					DestroyIcon(hi);
				}
			} while (umsg);
			OnDestroy();
			break;

		case WM_CLOSE:
			DestroyWindow(hwnd);
			PostMessageW(m_hwnd, WM_CLOSE, 0, 0);
			//DestroyWindow(m_hwnd);
			break;
		}
		return 0;
	}

	virtual ~CredDlg()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		m_pMycpc->Release();
		m_pEvent->Release();
	}
public:

	CredDlg(HWND hwnd, CWrapperCredential* pMycpc, ICredentialProviderCredentialEvents4* pEvent, BOOLEAN bSet) 
		: m_pMycpc(pMycpc), m_pEvent(pEvent), m_hwnd(hwnd), m_bSet(bSet)
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		pEvent->AddRef();
		pMycpc->AddRef();
	}
};

PVOID WINAPI uicb(HWND hwnd, GUDT* ctx)
{
	DbgPrint("%x> %hs\r\n", GetCurrentThreadId(), __FUNCTION__);

	if (CredDlg* Dlg = new CredDlg(hwnd, ctx->pMycpc, ctx->pEvent, ctx->bSet))
	{
		hwnd = Dlg->Show((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0);
		Dlg->Release();

		return hwnd;
	}
	return 0;
}

HWND ShowMyDlg(CWrapperCredential* pMycpc, ICredentialProviderCredentialEvents4* pEvent, BOOLEAN bSet)
{
	HWND hwnd;
	if (0 <= pEvent->OnCreatingWindow(&hwnd))
	{
		GUDT ff = { pMycpc, pEvent, bSet };
		return (HWND)invoke_in_ui(hwnd, (UI_CB)uicb, &ff);
	}

	return 0;
}

_NT_END