#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../asio/socket.h"
#include "util.h"
#include "pkt.h"
#include "pkcs#10.h"
#include "aik.h"
#include "decode.h"
#include "dns.h"
#include "resource.h"

class CAIKClient : public CTcpEndpoint
{
	HWND m_hwnd;
	PCWSTR m_pszAIKAlgId;
	PCWSTR m_pszKeyEncryptAlgId;
	PCWSTR m_pszKeySignAlgId;
	BCRYPT_KEY_HANDLE m_hKey = 0;
	BCRYPT_KEY_HANDLE m_hServerPubKey;
	NCRYPT_KEY_HANDLE m_hAIK = 0;
	HANDLE m_hToken;
	ULONG m_cbNeed;
	BOOL m_bWaitCert = FALSE;
	HRESULT m_hr = E_FAIL;
	WCHAR m_pszKeyName[32];
	UCHAR m_nonce[SHA1_DIGEST_SIZE];

	virtual BOOL OnConnect(ULONG dwError)
	{
		DbgPrint("%hs<%p>(%u)\r\n", __FUNCTION__, this, dwError);
		m_cbNeed = SHA1_DIGEST_SIZE;

		if (dwError)
		{
			m_hr = dwError;
			return FALSE;
		}

		return TRUE;
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}

	BOOL OnEncryptedData(UH_PACKET* ph)
	{
		PBYTE pbSecret = 0, pbCertEncoded;
		ULONG cbSecret = 0, cbCertEncoded;
		HRESULT hr = STATUS_BAD_DATA;
		int line = __LINE__;
		BOOL fOk = FALSE;
		PCCERT_CONTEXT pCertContext = 0;
		if (m_hAIK)
		{
			if (ph->getTpmSize(&cbSecret, &cbCertEncoded, &pbSecret, &pbCertEncoded))
			{
				line = __LINE__;
				DbgPrint("%hs<%p>(cbSecret=%x cbCertEncoded=%x)\r\n", __FUNCTION__, this, cbSecret, cbCertEncoded);
				if (NOERROR == (hr = DecryptSecret(m_hAIK, pbSecret, cbSecret, &cbSecret)))
				{
					line = __LINE__;
					UCHAR aes[32];
					ULONG cb = sizeof(aes);

					if (HR(hr, CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbSecret, cbSecret, aes, &cb)) &&
						0 <= (hr = CFBXcrypt(aes, cb, pbCertEncoded, cbCertEncoded, pbCertEncoded, TRUE)))
					{
						line = __LINE__;
						if (!(hr = AddEncodedCertificateToStore(&pCertContext, 
							m_hToken, pbCertEncoded, cbCertEncoded, m_pszKeyName)))
						{
							fOk = TRUE;
						}
					}
				}
			}
		}
		else
		{
			line = __LINE__;
			if (0 <= (hr = ph->Decode(m_hKey, &pbCertEncoded, &cbCertEncoded)))
			{
				line = __LINE__;
				if (!(hr = AddEncodedCertificateToStore(&pCertContext,
					m_hToken, pbCertEncoded, cbCertEncoded, m_pszKeyName, m_hKey)))
				{
					pbSecret = m_nonce, cbSecret = sizeof(m_nonce);
					fOk = TRUE;
				}
			}
		}
		DbgPrint("%hs(%u): %hs = %x\r\n", __FILE__, line, __FUNCTION__, hr);
		
		m_hr = hr;

		if (fOk)
		{
			if (!PostMessageW(m_hwnd, WM_CERT, 0, (LPARAM)pCertContext))
			{
				CertFreeCertificateContext(pCertContext);
			}
			return !Send(pbSecret, cbSecret);
		}
		return FALSE;
	}

	// pszAlgId - encrypt
	HRESULT RequestCert(PCSTR pszPublicKeyObjId, ULONG dwLength)
	{
		HRESULT hr;
		BCRYPT_KEY_HANDLE hSignKey, hEncKey;
		int line = __LINE__;

		if (0 <= (hr = CreateKeyPairKey(&hEncKey, m_pszKeyEncryptAlgId, dwLength)))
		{
			line = __LINE__;
			m_hKey = hEncKey;

			if (0 <= (hr = dwLength ? (hSignKey = hEncKey, 0) : 
				TransformEccKey(&hSignKey, hEncKey, m_pszKeySignAlgId, BCRYPT_PRIVATE_KEY_BLOB)))
			{
				line = __LINE__;
				WCHAR MachineName[25];
				if (NOERROR == (hr = GetMachineUID(MachineName, _countof(MachineName))))
				{
					line = __LINE__;
					DATA_BLOB request;
					if (NOERROR == (hr = BuildPkcs10(&request, B_CRYPT_KEY_HANDLE(hSignKey, pszPublicKeyObjId), 
						m_hToken, MS_KEY_STORAGE_PROVIDER, MachineName)))
					{
						line = __LINE__;
						hr = SendMsg(request.pbData, request.cbData);
						LocalFree(request.pbData);
					}

					if (hSignKey != hEncKey) BCryptDestroyKey(hSignKey);
				}
			}
		}
		DbgPrint("%hs(%u): %hs = %x\r\n", __FILE__, line, __FUNCTION__, hr);

		return hr;
	}

	virtual BOOL OnRecv(PSTR Buffer, ULONG cbTransferred)
	{
		DbgPrint("%hs<%p>(%p %x)\r\n", __FUNCTION__, this, Buffer, cbTransferred);

		ULONG cbNeed;

		union {
			UH_PACKET* ph;
			PSTR pszData;
		};

		pszData = m_packet->getData();

		if (cbNeed = m_cbNeed)
		{
			if (cbTransferred < cbNeed)
			{
				m_cbNeed -= cbTransferred;
__need_more_data:
				m_packet->addData(cbTransferred);
				return TRUE;
			}

			m_cbNeed = 0;

			cbTransferred += m_packet->getDataSize();

			m_packet->setDataSize(0);
			Buffer = pszData;
		}

		if (!m_bWaitCert)
		{
			if (SHA1_DIGEST_SIZE == cbTransferred)
			{
				m_bWaitCert = TRUE;

				PCSTR pszPublicKeyObjId;
				ULONG dwLength;

				if (m_pszKeySignAlgId == m_pszKeyEncryptAlgId)
				{
					pszPublicKeyObjId = szOID_RSA_RSA;
					dwLength = 2048;
				}
				else
				{
					pszPublicKeyObjId = szOID_ECC_PUBLIC_KEY;
					dwLength = 0;
				}

				HRESULT hr;
				DATA_BLOB request;
				BOOL bTpmPresent;
				if (NOERROR == (hr = StartAIKHandshake(m_pszAIKAlgId, m_pszKeyName, m_pszKeySignAlgId, 
					pszPublicKeyObjId, (PBYTE)Buffer, m_hToken, &bTpmPresent, &request, &m_hAIK)))
				{
					hr = SendMsg(request.pbData, request.cbData);
					LocalFree(request.pbData);

					return !hr;
				}

				if (bTpmPresent)
				{
					m_hr = hr;
					return FALSE;
				}
				
				memcpy(m_nonce, Buffer, sizeof(m_nonce));

				if (hr = RequestCert(pszPublicKeyObjId, dwLength))
				{
					m_hr = hr;
					return FALSE;
				}
				
				return TRUE;
			}

			return FALSE;
		}

		if (sizeof(UH_PACKET) > cbTransferred)
		{
			m_cbNeed = sizeof(UH_PACKET) - cbTransferred;
			goto __need_more_data;
		}

		ULONG PacketSize = ph->getPacketSize();
		if (0x10000 < PacketSize || cbTransferred > PacketSize)
		{
			return FALSE;
		}

		if (cbTransferred < PacketSize)
		{
			m_cbNeed = PacketSize - cbTransferred;
			goto __need_more_data;
		}

		return OnEncryptedData(ph);
	}

	NTSTATUS SendMsg(PBYTE pb, ULONG cb)
	{
		NTSTATUS status;
		CDataPacket* packet;
		if (0 <= (status = UH_PACKET::Encode(m_hServerPubKey, pb, cb, &packet)))
		{
			status = Send(packet);
			packet->Release();
		}

		return status;
	}

	~CAIKClient()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		if (m_hKey)
		{
			BCryptDestroyKey(m_hKey);
		}

		if (m_hAIK)
		{
			NCryptFreeObject(m_hAIK);
		}

		if (m_hwnd)
		{
			if (!PostMessageW(m_hwnd, WM_RETURN_KEY, m_hr, (LPARAM)m_hServerPubKey))
			{
				BCryptDestroyKey(m_hServerPubKey);
			}
		}
	}

public:
	CAIKClient(HANDLE hToken, HWND hwnd, BCRYPT_KEY_HANDLE hServerPubKey, PCWSTR pszAIKAlgId, PCWSTR pszKeyEncryptAlgId, 
		PCWSTR pszKeySignAlgId, PCWSTR pszKeyName) : m_hServerPubKey(hServerPubKey), m_pszAIKAlgId(pszAIKAlgId), 
		m_pszKeyEncryptAlgId(pszKeyEncryptAlgId), m_pszKeySignAlgId(pszKeySignAlgId), m_hwnd(hwnd), m_hToken(hToken)
	{
		wcscpy_s(m_pszKeyName, _countof(m_pszKeyName), pszKeyName);
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};

#include "resource.h"
#include "../inc/idcres.h"

#define IDC_AIK_RSA IDC_RADIO1
#define IDC_AIK_ECC IDC_RADIO2
#define IDC_KEY_RSA IDC_RADIO3
#define IDC_KEY_ECC IDC_RADIO4

#define IDC_AIK_CURVE IDC_COMBO1
#define IDC_KEY_CURVE IDC_COMBO2
#define IDC_IP_LIST IDC_COMBO3

static const PCWSTR s_SAAlgId[] = { 
	BCRYPT_ECDSA_P256_ALGORITHM, BCRYPT_ECDSA_P384_ALGORITHM, BCRYPT_ECDSA_P521_ALGORITHM
};
static const PCWSTR s_HAlgId[] = { 
	BCRYPT_ECDH_P256_ALGORITHM, BCRYPT_ECDH_P384_ALGORITHM, BCRYPT_ECDH_P521_ALGORITHM
};

struct DLG_CONTEXT 
{
	HICON m_hIcon = 0;
	HANDLE m_hToken;
	BCRYPT_KEY_HANDLE m_hServerPubKey = 0;
	SOCKADDR_INET* m_psi = 0;
	ULONG m_n = 0;

	void Set(SOCKADDR_INET* psi, ULONG n)
	{
		if (m_psi)
		{
			delete [] m_psi;
		}
		m_psi = psi, m_n = n;
	}

	~DLG_CONTEXT()
	{
		if (m_psi)
		{
			delete [] m_psi;
		}

		if (m_hServerPubKey)
		{
			BCryptDestroyKey(m_hServerPubKey);
		}

		if (m_hIcon)
		{
			DestroyIcon(m_hIcon);
		}
	}

	DLG_CONTEXT(HANDLE hToken) : m_hToken(hToken)
	{
	}

	HRESULT GetServerParams(HWND hwnd);
};

HRESULT DLG_CONTEXT::GetServerParams(HWND hwnd)
{
	PSTR szUsageIdentifier = const_cast<PSTR>(szOID_PKIX_KP_SERVER_AUTH);
	CERT_ENHKEY_USAGE ceku = { 1, &szUsageIdentifier };

	HRESULT hr;
	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
		CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|CERT_SYSTEM_STORE_LOCAL_MACHINE, L"My")))
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

void OnInitDialog(HWND hwnd, LPARAM lParam)
{
	static const UINT s_k[] = { IDC_AIK_ECC, IDC_KEY_ECC };
	static const UINT s_m[] = { IDC_AIK_CURVE, IDC_KEY_CURVE };

	SetWindowLongPtrW(hwnd, DWLP_USER, lParam);
 	ULONG i = _countof(s_k);
	do 
	{
		CheckDlgButton(hwnd, s_k[--i], BST_CHECKED);
		UINT id = s_m[i];
		ULONG j  = _countof(s_SAAlgId);
		do 
		{
			SendDlgItemMessageW(hwnd, id, CB_ADDSTRING, 0, (LPARAM)s_SAAlgId[_countof(s_SAAlgId) - j]);
		} while (--j);
		SendDlgItemMessageW(hwnd, id, CB_SETCURSEL, 0, 0);
	} while (i);

	HICON hIcon;
	if (0 <= LoadIconWithScaleDown(0, IDI_INFORMATION,
		GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), &hIcon))
	{
		reinterpret_cast<DLG_CONTEXT*>(lParam)->m_hIcon = hIcon;
		SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
	}

	reinterpret_cast<DLG_CONTEXT*>(lParam)->GetServerParams(hwnd);
}

void EnableCurve(HWND hwnd, UINT id, BOOL bEnable)
{
	EnableWindow(GetDlgItem(hwnd, id), bEnable);
}

void OnOk(HWND hwnd)
{
	PCWSTR pszAIKAlgId = 0, pszKeyEncryptAlgId = 0, pszKeySignAlgId = 0;
	SIZE_T i;
	LONG_PTR j = 2;
	WCHAR szKeyName[32];

	if (IsDlgButtonChecked(hwnd, IDC_AIK_ECC))
	{
		if (_countof(s_SAAlgId) > (i = SendDlgItemMessageW(hwnd, IDC_AIK_CURVE, CB_GETCURSEL, 0, 0)))
		{
			pszAIKAlgId = s_SAAlgId[i];
			j--;
		}
	}
	else
	{
		//pszAIKAlgId = 0;//BCRYPT_RSA_ALGORITHM
		j--;
	}

	if (IsDlgButtonChecked(hwnd, IDC_KEY_ECC))
	{
		if (_countof(s_HAlgId) > (i = SendDlgItemMessageW(hwnd, IDC_KEY_CURVE, CB_GETCURSEL, 0, 0)))
		{
			pszKeyEncryptAlgId = s_HAlgId[i], pszKeySignAlgId = s_SAAlgId[i];
			j--;
			
			swprintf_s(szKeyName, _countof(szKeyName), L"SPIAlert-ECC-%ws", s_HAlgId[i]+_countof("ECDH"));
		}
	}
	else
	{
		pszKeyEncryptAlgId = BCRYPT_RSA_ALGORITHM, pszKeySignAlgId = BCRYPT_RSA_ALGORITHM;
		j--;
		wcscpy_s(szKeyName, _countof(szKeyName), L"SPIAlert-RSA");
	}

	if (!j && 0 <= (j = SendDlgItemMessageW(hwnd, IDC_IP_LIST, CB_GETCURSEL, 0, 0)))
	{
		WCHAR szip[64];
		if (GetWindowTextW(GetDlgItem(hwnd, IDC_IP_LIST), szip, _countof(szip)))
		{
			NTSTATUS status = -1;
			SOCKADDR_INET si;
			switch (si.si_family = (ADDRESS_FAMILY)SendDlgItemMessageW(hwnd, IDC_IP_LIST, CB_GETITEMDATA, j, 0))
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
				DLG_CONTEXT* ctx = (DLG_CONTEXT*)GetWindowLongPtrW(hwnd, DWLP_USER);
				if (CAIKClient* p = new CAIKClient(ctx->m_hToken, hwnd, ctx->m_hServerPubKey, 
					pszAIKAlgId, pszKeyEncryptAlgId, pszKeySignAlgId, szKeyName))
				{
					ctx->m_hServerPubKey = 0;
					if (!(status = p->Create(0x10000, si.si_family)))
					{
						if (!(status = p->Connect(&si)))
						{
							EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
						}
					}
					p->Release();
				}
			}
		}
	}
}

#include "msgbox.h"
void ShowCert(HWND hwnd, PCCERT_CONTEXT pCertContext, PCWSTR szTitle);

INT_PTR CALLBACK DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		OnInitDialog(hwnd, lParam);
		break;

	case WM_CERT:
		ShowCert(hwnd, (PCCERT_CONTEXT)lParam, L"User Certificate");
		CertFreeCertificateContext((PCCERT_CONTEXT)lParam);
		EndDialog(hwnd, 0);
		break;

	case WM_RETURN_KEY:
		reinterpret_cast<DLG_CONTEXT*>(GetWindowLongPtrW(hwnd, DWLP_USER))->m_hServerPubKey = (BCRYPT_KEY_HANDLE)lParam;
		EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
		if ((ULONG)wParam)
		{
			ShowErrorBox(hwnd, (ULONG)wParam, 0);
		}
		break;

	case WM_DNS:
		if (SOCKADDR_INET* psi = (SOCKADDR_INET*)wParam)
		{
			reinterpret_cast<DLG_CONTEXT*>(GetWindowLongPtrW(hwnd, DWLP_USER))->Set(psi, (ULONG)lParam);
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
					LONG_PTR i = SendDlgItemMessageW(hwnd, IDC_IP_LIST, CB_ADDSTRING, 0, (LPARAM)sz);
					if (0 <= i)
					{
						SendDlgItemMessageW(hwnd, IDC_IP_LIST, CB_SETITEMDATA, i, psi->si_family);

						fOk++;
					}
				}
			} while (psi++, --lParam);

			if (fOk)
			{
				SendDlgItemMessageW(hwnd, IDC_IP_LIST, CB_SETCURSEL, 0, 0);
				EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
				EnableWindow(GetDlgItem(hwnd, IDC_IP_LIST), TRUE);
			}
		}
		else
		{
			LogError("DNS", (HRESULT)lParam);
			ShowErrorBox(hwnd, (HRESULT)lParam, L"dns");
		}
		break;

	case WM_COMMAND:
		switch (wParam)
		{
		case MAKEWPARAM(IDC_AIK_ECC, BN_CLICKED):
			EnableCurve(hwnd, IDC_AIK_CURVE, TRUE);
			break;
		case MAKEWPARAM(IDC_AIK_RSA, BN_CLICKED):
			EnableCurve(hwnd, IDC_AIK_CURVE, FALSE);
			break;
		case MAKEWPARAM(IDC_KEY_ECC, BN_CLICKED):
			EnableCurve(hwnd, IDC_KEY_CURVE, TRUE);
			break;
		case MAKEWPARAM(IDC_KEY_RSA, BN_CLICKED):
			EnableCurve(hwnd, IDC_KEY_CURVE, FALSE);
			break;
		case IDCANCEL:
			EndDialog(hwnd, 0);
			break;
		case IDOK:
			OnOk( hwnd);
			break;
		}
		break;
	}
	return 0;
}

void RunElevated(HANDLE hToken)
{
	WSADATA wd;
	if (!WSAStartup(WINSOCK_VERSION, &wd))
	{
		if (HDESK hDesk = OpenInputDesktop(0, 0, DESKTOP_SWITCHDESKTOP))
		{
			if (SwitchDesktop(GetThreadDesktop(GetCurrentThreadId())))
			{
				DLG_CONTEXT ctx(hToken);
				DialogBoxParamW((HINSTANCE)&__ImageBase, MAKEINTRESOURCEW(IDD_DIALOG1), 0, DlgProc, (LPARAM)&ctx);

				SwitchDesktop(hDesk);
			}
			CloseDesktop(hDesk);
		}
		WSACleanup();
	}
}

_NT_END