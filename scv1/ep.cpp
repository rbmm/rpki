#include "stdafx.h"
#include "resource.h"

_NT_BEGIN
#include "../inc/initterm.h"
#include "../log/log.h"
#include "decode.h"
#include "wnd.h"
#include "pem.h"
#include "disk.h"
#include "dns.h"

extern const WCHAR MyId[];

#define GET_WPARAM(wp, lp)                      (wp)
#define GET_LPARAM(wp, lp)                      (lp)

#define GET_X_LPARAM(lp)                        ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)                        ((int)(short)HIWORD(lp))

#define MD5_HASH_SIZE 16

#define IDC_IP_LIST IDC_COMBO2

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType);
void ShowCert(HWND hwnd, PCCERT_CONTEXT pCertContext, PCWSTR szTitle);

HRESULT StartRequest(
	PSOCKADDR_INET psi,
	HWND hwnd,
	BCRYPT_KEY_HANDLE* phServerPubKey,
	ULONG DeviceNumber,
	PCSTR pcszPin,
	PBYTE SerialMD5);

BOOL IsReaderRun();
HRESULT InstallReader();
HRESULT DeleteReader();

HRESULT ReLaunch(_In_ HWND hwnd, _In_ WCHAR Action)
{
	WCHAR lpParameters[32];

	if (0 >= swprintf_s(lpParameters, _countof(lpParameters), L"\n%x\n%c", (ULONG)(ULONG_PTR)hwnd, Action))
	{
		return HRESULT_FROM_WIN32(ERROR_INTERNAL_ERROR);
	}

	SHELLEXECUTEINFOW ExecInfo = { 
		sizeof(ExecInfo), 0, 0, L"RunAs", 0, lpParameters, 0, SW_SHOWDEFAULT
	};

	ULONG dwError = ERROR_OUTOFMEMORY;

	if (ExecInfo.lpFile = new WCHAR[MAXSHORT + 1])
	{
		if (NOERROR == (dwError = BOOL_TO_ERROR(GetModuleFileNameW(0, const_cast<PWSTR>(ExecInfo.lpFile), MAXSHORT + 1))))
		{
			dwError = BOOL_TO_ERROR(ShellExecuteExW(&ExecInfo));

		}
		delete [] ExecInfo.lpFile;
	}

	if (dwError)
	{
		ShowErrorBox(0, dwError, 0, MB_ICONHAND);
	}

	return HRESULT_FROM_WIN32(dwError);
}

void Uninstall(HWND hwnd)
{
	if (MessageBoxW(0, L"You want uninstall reader ?", L"Unistall", MB_ICONQUESTION|MB_YESNO) == IDYES)
	{
		BOOL bAdmin = IsUserAnAdmin();
		if (ULONG dwError = bAdmin ? DeleteReader() : ReLaunch(hwnd, 'u'))
		{
			ShowErrorBox(0, dwError, L"Uninstall", MB_ICONINFORMATION);
		}

		if (bAdmin)
		{
			EndDialog(hwnd, 0);
		}
	}
}

PCWSTR NullToEmpty(PCWSTR pcsz)
{
	return pcsz ? pcsz : L"";
}

class PfxDlg : public SimpDlg, DiskList
{
	HDEVNOTIFY _M_HandleV = 0;
	BCRYPT_KEY_HANDLE m_hServerPubKey = 0;
	HICON _M_hi = 0;
	SOCKADDR_INET* m_psi = 0;
	ULONG m_n = 0;
	WCHAR _M_psc;
	BOOLEAN _M_bInstalling = FALSE;

	inline static UINT E_id[] = { IDC_EDIT3, IDC_EDIT4 };

	static void CheckDisk(HWND hwndDlg)
	{
		EnableWindow(GetDlgItem(hwndDlg, IDOK), 0 <= ComboBox_GetCurSel(GetDlgItem(hwndDlg, IDC_COMBO1)));
	}

	static BOOL IsBadPin(PCSTR apin, PCWSTR wpin)
	{
		CHAR pin[0x40];
		return !WideCharToMultiByte(CP_OEMCP, 0, wpin, MAXULONG, pin, _countof(pin), 0, 0) || strcmp(pin, apin);
	}

	void Set(SOCKADDR_INET* psi, ULONG n)
	{
		if (m_psi)
		{
			delete[] m_psi;
		}
		m_psi = psi, m_n = n;
	}

	void OnDnsComplete(HWND hwndDlg, SOCKADDR_INET* psi, ULONG n);

	virtual INT_PTR OnInitDialog(HWND hwndDlg)
	{
		if (HRESULT hr = GetServerParams(hwndDlg))
		{
			ShowErrorBox(0, hr, L"Can not found server certificate", MB_ICONHAND);
			EndDialog(hwndDlg, IDCANCEL);
			return 0;
		}

		HDEVNOTIFY HandleV = Init(GetDlgItem(hwndDlg, IDC_COMBO1), hwndDlg);
		
		if (!HandleV)
		{
			EndDialog(hwndDlg, IDCANCEL);
			return 0;
		}

		_M_HandleV = HandleV;
		CheckDisk(hwndDlg);
		HICON hi;

		if (0 <= LoadIconWithScaleDown((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDI_ICON1), 
			GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hi))
		{
			_M_hi = hi;
			SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)hi);
		}

		static const PCWSTR ss[] = {
			L"Enter PIN",
			L"Confirm PIN"
		};

		ULONG n = _countof(E_id);
		do 
		{
			--n;
			SendDlgItemMessage(hwndDlg, E_id[n], EM_SETCUEBANNER, FALSE, (LPARAM)ss[n]);
		} while (n);

		_M_psc = (WCHAR)SendDlgItemMessage(hwndDlg, IDC_EDIT3, EM_GETPASSWORDCHAR, 0, 0);

		SetFocus(GetDlgItem(hwndDlg, IDC_BUTTON1));

		if (!IsReaderRun())
		{
			if (MessageBoxW(0, L"Install Reader ?", L"You need install reader", MB_ICONQUESTION|MB_OKCANCEL) != IDOK)
			{
				EndDialog(hwndDlg, 0);
				return 0;
			}

			BOOL bAdmin = IsUserAnAdmin();
			switch (ULONG dwError = bAdmin ? InstallReader() : ReLaunch(hwndDlg, 'i'))
			{
			case NOERROR:
			case HRESULT_FROM_NT(STATUS_IMAGE_ALREADY_LOADED):
				break;
			default:
				ShowErrorBox(0, dwError, L"Install", MB_ICONINFORMATION);
				EndDialog(hwndDlg, 0);
				return 0;
			}

			if (!bAdmin)
			{
				_M_bInstalling = TRUE;
				return 0;
			}

			if (!IsReaderRun())
			{
				EndDialog(hwndDlg, 0);
			}
		}

		return 0;
	}

	void OnOk(HWND hwndDlg);

	void TooglePasswordChar(HWND hwndDlg, HWND hwndCheck, UINT id, UINT id2 = 0)
	{
		WCHAR c = SendMessageW(hwndCheck, BM_GETCHECK, 0, 0) == BST_CHECKED ? 0 : _M_psc;

		do 
		{
			if (hwndCheck = GetDlgItem(hwndDlg, id))
			{
				SendMessageW(hwndCheck, EM_SETPASSWORDCHAR, c, 0);
				InvalidateRect(hwndCheck, 0, FALSE);
			}

		} while ((id != id2) && (id = id2));
	}

	HRESULT GetServerParams(HWND hwndDlg);

	virtual INT_PTR DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		switch (uMsg)
		{
		case WM_NULL:
			switch (wParam)
			{
			case 'i':
				_M_bInstalling = FALSE;
				wParam = (WPARAM)L"Install";

				switch ((HRESULT)lParam)
				{
				case S_OK:
				case HRESULT_FROM_NT(STATUS_IMAGE_ALREADY_LOADED):
					if (IsReaderRun())
					{
						return 0;
					}
				default:
					EndDialog(hwndDlg, 0);
				}
				break;
			case 'u':
				wParam = (WPARAM)L"Uninstall";
				EndDialog(hwndDlg, 0);
				break;
			default: return 0;
			}

			if (lParam)
			{
				ShowErrorBox(hwndDlg, (HRESULT)lParam, (PCWSTR)wParam, MB_ICONINFORMATION);
			}
			return 0;

		case WM_COMMAND:
			switch (wParam)
			{
			case IDCANCEL:
				EndDialog(hwndDlg, 0);
				break;
			
			case MAKEWPARAM(IDC_BUTTON2, BN_CLICKED):
				Uninstall(hwndDlg);
				break;

			case MAKEWPARAM(IDOK, BN_CLICKED):
				if (!_M_bInstalling)
				{
					OnOk(hwndDlg);
				}
				break;

			case MAKEWPARAM(IDC_CHECK2, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT3, IDC_EDIT4);
				break;
			}
			return 0;

		case WM_DESTROY:
			if (m_psi) delete[] m_psi;
			if (_M_hi) DestroyIcon(_M_hi);
			if (_M_HandleV) UnregisterDeviceNotification(_M_HandleV);
			if (m_hServerPubKey) BCryptDestroyKey(m_hServerPubKey);

			break;

		case WM_DEVICECHANGE:
			OnInterfaceChange(GetDlgItem(hwndDlg, IDC_COMBO1), wParam, reinterpret_cast<PDEV_BROADCAST_DEVICEINTERFACE>(lParam));
			CheckDisk(hwndDlg);
			return 0;

		case WM_CTLCOLOREDIT:
			SetBkColor((HDC)wParam, GetSysColor(COLOR_WINDOW));
			SetBkMode((HDC)wParam, TRANSPARENT);
			[[fallthrough]];
		case WM_CTLCOLORDLG:
			return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);

		case WM_CTLCOLORSTATIC:
			SetTextColor((HDC)wParam, (INT_PTR)GetSysColor(COLOR_WINDOWTEXT));
			SetBkMode((HDC)wParam, TRANSPARENT);
			return (INT_PTR)GetSysColorBrush(COLOR_WINDOW);

		case WM_CERT:
			if (lParam)
			{
				ShowCert(hwndDlg, (PCCERT_CONTEXT)lParam, L"User Certificate");
				CertFreeCertificateContext((PCCERT_CONTEXT)lParam);
			}
			EndDialog(hwndDlg, 0);
			break;

		case WM_RETURN_KEY:
			m_hServerPubKey = (BCRYPT_KEY_HANDLE)lParam;
			EnableWindow(GetDlgItem(hwndDlg, IDOK), TRUE);
			if ((ULONG)wParam)
			{
				ShowErrorBox(hwndDlg, (ULONG)wParam, 0, MB_ICONHAND);
			}
			break;

		case WM_DNS:
			if (wParam)
			{
				OnDnsComplete(hwndDlg, (SOCKADDR_INET*)wParam, (ULONG)lParam);
			}
			else
			{
				LogError("DNS", (HRESULT)lParam);
				ShowErrorBox(hwndDlg, (HRESULT)lParam, L"dns", MB_ICONHAND);
			}
			break;

		case WM_PAINT:
			PAINTSTRUCT ps;
			if (BeginPaint(hwndDlg, &ps))
			{
				RECT rc;
				GetWindowRect(GetDlgItem(hwndDlg, IDOK), &rc);
				MapWindowRect(0, hwndDlg, &rc);

				GetClientRect(hwndDlg, &ps.rcPaint);
				ps.rcPaint.top = rc.top - (ps.rcPaint.bottom - rc.bottom);
				FillRect(ps.hdc, &ps.rcPaint, GetSysColorBrush(COLOR_MENU));
				EndPaint(hwndDlg, &ps);
			}
			return TRUE;
		}

		return __super::DialogProc(hwndDlg, uMsg, wParam, lParam);
	}
};

void PfxDlg::OnDnsComplete(HWND hwndDlg, SOCKADDR_INET* psi, ULONG n)
{
	Set(psi, n);
	BOOL fOk = FALSE;
	do
	{
		WCHAR sz[64];
		ULONG cch = _countof(sz);
		NTSTATUS status = -1;

		switch (psi->si_family)
		{
		case AF_INET://
			status = RtlIpv4AddressToStringExW(&psi->Ipv4.sin_addr, psi->Ipv4.sin_port, sz, &cch);
			break;
		case AF_INET6://
			status = RtlIpv6AddressToStringExW(&psi->Ipv6.sin6_addr,
				psi->Ipv6.sin6_scope_id, psi->Ipv6.sin6_port, sz, &cch);
			break;
		}

		if (0 <= status)
		{
			LONG_PTR i = SendDlgItemMessageW(hwndDlg, IDC_IP_LIST, CB_ADDSTRING, 0, (LPARAM)sz);
			if (0 <= i)
			{
				SendDlgItemMessageW(hwndDlg, IDC_IP_LIST, CB_SETITEMDATA, i, psi->si_family);

				fOk++;
			}
		}
	} while (psi++, --n);

	if (fOk)
	{
		SendDlgItemMessageW(hwndDlg, IDC_IP_LIST, CB_SETCURSEL, 0, 0);
		EnableWindow(GetDlgItem(hwndDlg, IDOK), TRUE);
		EnableWindow(GetDlgItem(hwndDlg, IDC_IP_LIST), TRUE);
	}
}

void PfxDlg::OnOk(HWND hwndDlg)
{
	UCHAR SerialMD5[MD5_HASH_SIZE];
	int iDisk, DeviceNumber = -1;

	if (0 > (iDisk = ComboBox_GetCurSel(GetDlgItem(hwndDlg, IDC_COMBO1))) ||
		0 > (DeviceNumber = GetDeviceNumber(iDisk, SerialMD5)))
	{
		ShowErrorBox(hwndDlg, STATUS_VOLMGR_DISK_MISSING, L"Select Disk Drive", MB_ICONWARNING);
		return;
	}

	PWSTR psz[_countof(E_id)]{};

	ULONG i = _countof(E_id);

	HWND hwndEdit;

	do
	{
		if (ULONG len = GetWindowTextLengthW(hwndEdit = GetDlgItem(hwndDlg, E_id[--i])))
		{
			if (len - 1 < 0x40)
			{
				++len;
				GetWindowTextW(hwndEdit, psz[i] = (PWSTR)alloca(len * sizeof(WCHAR)), len);
			}
		}
	} while (i);

	if (!psz[0])
	{
		ShowErrorBox(hwndDlg, STATUS_PWD_TOO_SHORT, L"Empty PIN", MB_ICONWARNING);
		return;
	}

	if (wcslen(psz[0]) >= 0x3f)
	{
		ShowErrorBox(hwndDlg, STATUS_PWD_TOO_LONG, L"Too long PIN", MB_ICONWARNING);
		return;
	}

	CHAR pin[0x40];
	if (!WideCharToMultiByte(CP_UTF8, 0, psz[0], MAXULONG, pin, _countof(pin), 0, 0))
	{
		ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_ILL_FORMED_PASSWORD), L"Invalid PIN", MB_ICONWARNING);
		return;
	}

	if (!psz[1] || wcscmp(psz[0], psz[1]))
	{
		ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_NOT_SAME_OBJECT), L"PINs not match !", MB_ICONWARNING);
		return;
	}

	if (IsBadPin(pin, psz[0]))
	{
		ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_ILL_FORMED_PASSWORD), L"Invalid PIN", MB_ICONWARNING);
		return;
	}

	NTSTATUS status = STATUS_INTERNAL_ERROR;

	if (0 <= (iDisk = (int)SendDlgItemMessageW(hwndDlg, IDC_IP_LIST, CB_GETCURSEL, 0, 0)))
	{
		WCHAR szip[64];
		if (GetWindowTextW(GetDlgItem(hwndDlg, IDC_IP_LIST), szip, _countof(szip)))
		{
			SOCKADDR_INET si;
			switch (si.si_family = (ADDRESS_FAMILY)SendDlgItemMessageW(hwndDlg, IDC_IP_LIST, CB_GETITEMDATA, iDisk, 0))
			{
			case AF_INET:
				status = RtlIpv4StringToAddressExW(szip, TRUE, &si.Ipv4.sin_addr, &si.Ipv4.sin_port);
				break;
			case AF_INET6:
				status = RtlIpv6StringToAddressExW(szip, &si.Ipv6.sin6_addr, &si.Ipv6.sin6_scope_id, &si.Ipv6.sin6_port);
				break;
			}

			if (0 <= status)
			{
				StartRequest(&si, hwndDlg, &m_hServerPubKey, DeviceNumber, pin, SerialMD5);
				return;
			}
		}
	}

	ShowErrorBox(hwndDlg, status, 0, MB_ICONHAND);
}

HRESULT PfxDlg::GetServerParams(HWND hwnd)
{
	PSTR szUsageIdentifier = const_cast<PSTR>(szOID_PKIX_KP_SERVER_AUTH);
	CERT_ENHKEY_USAGE ceku = { 1, &szUsageIdentifier };

	HRESULT hr;
	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE, L"My")))
	{
		PCCERT_CONTEXT pCertContext = 0;
		while (pCertContext = HR(hr, CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING,
			CERT_FIND_VALID_ENHKEY_USAGE_FLAG | CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG,
			CERT_FIND_ENHKEY_USAGE, &ceku, 0)))
		{
			PCERT_INFO pCertInfo = pCertContext->pCertInfo;

			if (PCERT_EXTENSION pExt = CertFindExtension(szOID_CERTIFICATE_TEMPLATE,
				pCertInfo->cExtension, pCertInfo->rgExtension))
			{
				PCERT_TEMPLATE_EXT pcte;
				if (0 <= Decode(X509_CERTIFICATE_TEMPLATE, &pExt->Value, &pcte))
				{
					int i = strcmp(pcte->pszObjId, "1.3.6.1.4.1.311.21.8.3032776714.2974785564.2375659916.1");
					LocalFree(pcte);

					if (!i)
					{
						break;
					}
				}
			}
		}

		CertCloseStore(hCertStore, 0);

		if (pCertContext)
		{
			hr = STATUS_NOT_FOUND;

			PWSTR pwszDNSName = 0;
			PCERT_INFO pCertInfo = pCertContext->pCertInfo;

			if (PCERT_EXTENSION pExt = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
				pCertInfo->cExtension, pCertInfo->rgExtension))
			{
				PCERT_ALT_NAME_INFO pani;
				if (0 <= Decode(szOID_SUBJECT_ALT_NAME2, &pExt->Value, &pani))
				{
					if (DWORD cAltEntry = pani->cAltEntry)
					{
						PCERT_ALT_NAME_ENTRY rgAltEntry = pani->rgAltEntry;
						do
						{
							if (CERT_ALT_NAME_DNS_NAME == rgAltEntry->dwAltNameChoice)
							{
								size_t s = (1 + wcslen(pwszDNSName = rgAltEntry->pwszDNSName)) * sizeof(WCHAR);
								pwszDNSName = (PWSTR)memcpy(alloca(s), pwszDNSName, s);
								break;
							}

						} while (rgAltEntry++, --cAltEntry);
					}
					LocalFree(pani);
				}
			}

			BCRYPT_KEY_HANDLE hKey = 0;
			if (pwszDNSName)
			{
				HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
					&pCertInfo->SubjectPublicKeyInfo, CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, 0, &hKey));
			}

			CertFreeCertificateContext(pCertContext);

			if (0 <= hr)
			{
				if (m_hServerPubKey)
				{
					BCryptDestroyKey(m_hServerPubKey);
				}

				m_hServerPubKey = hKey;

				QueryServer(pwszDNSName, hwnd);
			}
		}
	}

	return hr;
}

HRESULT CheckUserCert();

void CALLBACK ep(HWND hwnd)
{
	if (PWSTR psz = wcschr(GetCommandLineW(), '\n'))
	{
		if ((hwnd = (HWND)(ULONG_PTR)wcstoul(psz + 1, &psz, 16)) && *psz == '\n' && !psz[2])
		{
			HRESULT hr = E_INVALIDARG;
			switch (psz[1])
			{
			case 'i':
				hr = InstallReader();
				break;
			case 'u':
				hr = DeleteReader();
				break;
			}

			PostMessageW(hwnd, WM_NULL, psz[1], hr);
		}

		ExitProcess(0);
	}

	switch (HRESULT hr = CheckUserCert())
	{
	default:
		LogError(L"CheckUserCert", hr);
		ShowErrorBox(0, hr, L"CheckUserCert", MB_ICONHAND);
	case NOERROR:
		break;
	case CRYPT_E_NOT_FOUND:
		if (HANDLE hEvent = CreateEventW(0, 0, 0, MyId + 1))
		{
			if (GetLastError() == NOERROR)
			{
				WSADATA wd;
				if (!WSAStartup(WINSOCK_VERSION, &wd))
				{
					PfxDlg dlg;
					dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0);
					WSACleanup();
				}
			}

			NtClose(hEvent);
		}
		break;
	}

	ExitProcess(0);
}

_NT_END