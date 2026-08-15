#include "stdafx.h"
#include "resource.h"

_NT_BEGIN
#include "../inc/initterm.h"
#include "wnd.h"
#include "disk.h"

NTSTATUS CreateContainerFromPfx(_In_opt_ HWND hwndDlg,
								_In_ BOOL bPem,
								_In_ PBYTE pbSerial, 
								_In_ ULONG cbSerial,
								_In_ PCWSTR VolumeName, 
								_In_ PCSTR pszPIN, 
								_In_ PCWSTR pfxPassword, 
								_In_ PCWSTR pszPFX);

NTSTATUS FormatContainerName(ULONG DeviceNumber, PWSTR szVolume, ULONG cchVolume);

extern const WCHAR MyId[];

UINT _G_uTaskbarRestart;

#define GET_WPARAM(wp, lp)                      (wp)
#define GET_LPARAM(wp, lp)                      (lp)

#define GET_X_LPARAM(lp)                        ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)                        ((int)(short)HIWORD(lp))

#define MD5_HASH_SIZE 16

int ShowErrorBox(HWND hWnd, HRESULT dwError, PCWSTR lpCaption, UINT uType)
{
	int r = 0;
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return 0;
		lpSource = ghnt;
	}

	PWSTR lpText;
	if (FormatMessageW(dwFlags, lpSource, dwError, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBoxW(hWnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}

	return r;
}

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
	HICON _M_hi = 0;
	WCHAR _M_psc;
	BOOLEAN _M_bInstalling = FALSE;

	inline static UINT E_id[] = { IDC_EDIT1, IDC_EDIT2, IDC_EDIT3, IDC_EDIT4 };

	static void CheckDisk(HWND hwndDlg)
	{
		EnableWindow(GetDlgItem(hwndDlg, IDOK), 0 <= ComboBox_GetCurSel(GetDlgItem(hwndDlg, IDC_COMBO1)));
	}

	static BOOL IsBadPin(PCSTR apin, PCWSTR wpin)
	{
		CHAR pin[0x40];

		return !WideCharToMultiByte(CP_OEMCP, 0, wpin, MAXULONG, pin, _countof(pin), 0, 0) || strcmp(pin, apin);
	}

	virtual INT_PTR OnInitDialog(HWND hwndDlg)
	{
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
			L"Specify the file you want to import.",
			L"Type the password for the private key.",
			L"Enter PIN",
			L"Confirm PIN"
		};

		ULONG n = _countof(E_id);
		do 
		{
			--n;
			SendDlgItemMessage(hwndDlg, E_id[n], EM_SETCUEBANNER, FALSE, (LPARAM)ss[n]);
		} while (n);

		_M_psc = (WCHAR)SendDlgItemMessage(hwndDlg, IDC_EDIT2, EM_GETPASSWORDCHAR, 0, 0);

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

	void OnOk(HWND hwndDlg)
	{
		UCHAR Serial[32];
		int iDisk, DeviceNumber = -1;

		if (0 > (iDisk = ComboBox_GetCurSel(GetDlgItem(hwndDlg, IDC_COMBO1))) ||
			0 > (DeviceNumber = GetDeviceNumber(iDisk, Serial)))
		{
			ShowErrorBox(hwndDlg, STATUS_VOLMGR_DISK_MISSING, L"Select Disk Drive", MB_ICONWARNING);
			return ;
		}

		PWSTR psz[_countof(E_id)] {};

		ULONG i = _countof(E_id);

		HWND hwndEdit;

		do 
		{
			if (ULONG len = GetWindowTextLengthW(hwndEdit = GetDlgItem(hwndDlg, E_id[--i])))
			{
				if (len - 1 < MAXSHORT)
				{
					++len;
					GetWindowTextW(hwndEdit, psz[i] = (PWSTR)alloca(len * sizeof(WCHAR)), len);
				}
			}
		} while (i);

		if (!psz[2])
		{
			ShowErrorBox(hwndDlg, STATUS_PWD_TOO_SHORT, L"Empty PIN", MB_ICONWARNING);
			return ;
		}

		if (wcslen(psz[2]) >= 0x3f)
		{
			ShowErrorBox(hwndDlg, STATUS_PWD_TOO_LONG, L"Too long PIN", MB_ICONWARNING);
			return ;
		}

		CHAR pin[0x40];
		if (!WideCharToMultiByte(CP_UTF8, 0, psz[2], MAXULONG, pin, _countof(pin), 0, 0))
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_ILL_FORMED_PASSWORD), L"Invalid PIN", MB_ICONWARNING);
			return ;
		}

		if (!psz[3] || wcscmp(psz[2], psz[3]))
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_NOT_SAME_OBJECT), L"PINs not match !", MB_ICONWARNING);
			return ;
		}

		if (IsBadPin(pin, psz[3]))
		{
			ShowErrorBox(hwndDlg, HRESULT_FROM_NT(STATUS_ILL_FORMED_PASSWORD), L"Invalid PIN", MB_ICONWARNING);
			return ;
		}

		hwndEdit = IsDlgButtonChecked(hwndDlg, IDC_CHECK4) ? hwndDlg : 0;

		WCHAR szVolume[0x200];
		HRESULT hr = FormatContainerName(DeviceNumber, szVolume, _countof(szVolume));
		if (0 <= hr)
		{
			hr = CreateContainerFromPfx(hwndEdit, IsDlgButtonChecked(hwndDlg, IDC_CHECK3),
				Serial, sizeof(Serial), szVolume, pin, NullToEmpty(psz[1]), psz[0]);
		}
		
		ShowErrorBox(hwndDlg, hr, L"Import PFX", MB_ICONINFORMATION);

		if (S_OK == hr)
		{
			EndDialog(hwndDlg, 0);
		}
	}

	static void OnBrowse(HWND hwndDlg)
	{
		IFileOpenDialog *pFileOpen;

		HRESULT hr = CoCreateInstance(__uuidof(FileOpenDialog), NULL, CLSCTX_ALL, IID_PPV(pFileOpen));

		if (SUCCEEDED(hr))
		{
			pFileOpen->SetOptions(FOS_NOVALIDATE|FOS_NOTESTFILECREATE|
				FOS_NODEREFERENCELINKS|FOS_DONTADDTORECENT|FOS_FORCESHOWHIDDEN);

			static const COMDLG_FILTERSPEC rgSpec[] =
			{ 
				{ L"PKCS#12 Files", L"*.pfx;*.p12" },
				{ L"PEM Files", L"*.pem;" },
				{ L"All files", L"*" },
			};

			if (0 <= (hr = pFileOpen->SetFileTypes(_countof(rgSpec), rgSpec)) && 
				0 <= (hr = pFileOpen->SetFileTypeIndex(IsDlgButtonChecked(hwndDlg, IDC_CHECK3) ? 2 : 1)) && 
				0 <= (hr = pFileOpen->Show(hwndDlg)))
			{
				IShellItem *pItem;
				hr = pFileOpen->GetResult(&pItem);

				if (SUCCEEDED(hr))
				{
					PWSTR pszFilePath;
					hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);

					if (SUCCEEDED(hr))
					{
						SetDlgItemTextW(hwndDlg, IDC_EDIT1, pszFilePath);
						CoTaskMemFree(pszFilePath);
					}
					pItem->Release();
				}
			}
			pFileOpen->Release();
		}
	}

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

			case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
				OnBrowse(hwndDlg);
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

			case MAKEWPARAM(IDC_CHECK1, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT2);
				break;

			case MAKEWPARAM(IDC_CHECK2, BN_CLICKED):
				TooglePasswordChar(hwndDlg, (HWND)lParam, IDC_EDIT3, IDC_EDIT4);
				break;
			}
			return 0;

		case WM_DESTROY:
			if (_M_hi) DestroyIcon(_M_hi);
			if (_M_HandleV) UnregisterDeviceNotification(_M_HandleV);
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

HRESULT FromADCS(_In_ PCWSTR pszUserName);

void CALLBACK ep(HWND hwnd)
{
	if (!GetTickCount64())
	{
		FromADCS(L"Harry");
		ExitProcess(0);
	}
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

	if (HANDLE hEvent = CreateEventW(0, 0, 0, MyId + 1))
	{
		if (GetLastError() == NOERROR)
		{
			PfxDlg dlg;
			dlg.DoModal((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0);
		}

		NtClose(hEvent);
	}

	ExitProcess(0);
}

_NT_END