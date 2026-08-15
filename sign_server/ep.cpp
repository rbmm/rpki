#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../asio/port.h"
#include "pkt.h"
#include "util.h"
#include "decode.h"

HRESULT CreateCert(_Out_ CDataPacket** ppacket,
				   _In_ PBYTE pbPKCS, 
				   _In_ ULONG cbPKCS,
				   _Inout_updates_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
				   _Out_writes_bytes_(16) PBYTE pbMachine,
				   _In_ PCERT_INFO IssuerCert,
				   _In_ BCRYPT_KEY_HANDLE hSignKey,
				   _In_ PCWSTR pwszCaURL,
				   _In_ PCWSTR pwszOcspURL,
				   _In_ ULONG nDays);

class CServerContext : public PortContext
{
	friend class CServerEndpoint;

	PCWSTR m_pwszCaURL;
	PCWSTR m_pwszOcspURL;
	BCRYPT_ALG_HANDLE m_hAlgorithm = 0; // AES
	PCCERT_CONTEXT m_pCertContext = 0;
	BCRYPT_KEY_HANDLE m_hSignKey = 0; //
	BCRYPT_KEY_HANDLE m_hEncKey = 0; //

	virtual CTcpEndpoint* getEndpoint(ENDPOINT_ENTRY* p);

	virtual ENDPOINT_ENTRY* CreateEntry(CSocketObject* pAddress);

	virtual ULONG GetReceiveDataLength()
	{
		return 0;
	}

	~CServerContext()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);

		if (m_pCertContext)
		{
			CertFreeCertificateContext(m_pCertContext);
		}

		if (m_hSignKey)
		{
			BCryptDestroyKey(m_hSignKey);
		}

		if (m_hEncKey)
		{
			BCryptDestroyKey(m_hEncKey);
		}

		if (m_hAlgorithm)
		{
			BCryptCloseAlgorithmProvider(m_hAlgorithm, 0);
		}
	}

	NTSTATUS Init(BOOL bSign, PCWSTR szHash, _Out_ BCRYPT_KEY_HANDLE* phKey, _In_opt_ PCCERT_CONTEXT* ppCertContext)
	{
		HRESULT hr;

		UCHAR hash[SHA1_DIGEST_SIZE];
		DATA_BLOB db = { sizeof(hash), hash };

		if (HR(hr, CryptStringToBinaryW(szHash, 0, CRYPT_STRING_HEXRAW, hash, &db.cbData, 0, 0)))
		{
			if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
				CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|CERT_SYSTEM_STORE_CURRENT_USER, L"My")))
			{
				if (PCCERT_CONTEXT pCertContext = HR(hr, CertFindCertificateInStore(
					hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &db, 0)))
				{
					if (!(hr = GetPrivateKeyFromCert(bSign, pCertContext, phKey)))
					{
						if (ppCertContext)
						{
							*ppCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, 
								pCertContext->pbCertEncoded, pCertContext->cbCertEncoded));
						}
					}

					CertFreeCertificateContext(pCertContext);
				}

				CertCloseStore(hCertStore, 0);
			}
		}

		return hr;
	}

public:

	CServerContext(_In_ PCWSTR pwszCaURL, _In_ PCWSTR pwszOcspURL) : m_pwszCaURL(pwszCaURL), m_pwszOcspURL(pwszOcspURL)
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}

	NTSTATUS InitCommon()
	{
		return BCryptOpenAlgorithmProvider(&m_hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0);
	}

	NTSTATUS Init(PCWSTR name, PCWSTR pszPassword, BOOL bSign)
	{
		HRESULT hr;

		BCRYPT_KEY_HANDLE* phKey;
		PCCERT_CONTEXT* ppCertContext;

		if (bSign)
		{
			phKey = &m_hSignKey;
			ppCertContext = &m_pCertContext;
		}
		else
		{
			phKey = &m_hEncKey;
			ppCertContext = 0;
		}

		hr = pszPassword ? PFXImport(bSign, name, pszPassword, phKey, ppCertContext) : Init(bSign, name, phKey, ppCertContext);

		return LogError(__FUNCTION__, hr);
	}
};

void PrintIP(PSOCKADDR_INET from)
{
	CHAR sz[64];
	ULONG cch = _countof(sz);
	NTSTATUS status = -1;

	switch (from->si_family)
	{
	case AF_INET:
		status = RtlIpv4AddressToStringExA(&from->Ipv4.sin_addr, from->Ipv4.sin_port, sz, &cch);
		break;
	case AF_INET6:
		status = RtlIpv6AddressToStringExA(&from->Ipv6.sin6_addr, 
			from->Ipv6.sin6_scope_id ,from->Ipv6.sin6_port, sz, &cch);
		break;
	}

	if (0 <= status)
	{
		DbgPrint("connect from %hs\r\n", sz);
	}
}

class CServerEndpoint : public CTcpEndpoint, public ENDPOINT_ENTRY
{
	CServerContext* m_pCtx;
	ULONG m_cbNeed;
	UCHAR m_bNonce[SHA1_DIGEST_SIZE];
	UCHAR m_bMachineGuid[16];
	BOOLEAN m_bWaitNonce;

	virtual BOOL OnConnect(ULONG dwError)
	{
		PSOCKADDR_INET from = (PSOCKADDR_INET)m_addr;
		CHAR sz[64];
		ULONG cch = _countof(sz);
		NTSTATUS status = -1;

		if (!dwError)
		{
			switch (from->si_family)
			{
			case AF_INET:
				status = RtlIpv4AddressToStringExA(&from->Ipv4.sin_addr, from->Ipv4.sin_port, sz, &cch);
				break;
			case AF_INET6:
				status = RtlIpv6AddressToStringExA(&from->Ipv6.sin6_addr, 
					from->Ipv6.sin6_scope_id ,from->Ipv6.sin6_port, sz, &cch);
				break;
			}
		}
		if (0 > status)
		{
			*sz = 0;
		}

		DbgPrint("%hs<%p>(%u) from %hs\r\n", __FUNCTION__, this, dwError, sz);

		m_cbNeed = 0, m_bWaitNonce = FALSE;
		_Port->OnConnect(dwError);
		if (dwError)
		{
			return !dwError;
		}
		BCryptGenRandom(0, m_bNonce, sizeof(m_bNonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
		//memcpy(m_bNonce, "12345678901234567890", sizeof(m_bNonce));// $$$
		return !Send(m_bNonce, sizeof(m_bNonce));
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		_Port->OnDisconnect(this);
	}

	BOOL OnEncryptedData(UH_PACKET* ph)
	{
		PBYTE pb;
		ULONG cb;
		HRESULT hr;
		if (NOERROR == (hr = ph->Decode(m_pCtx->m_hEncKey, &pb, &cb)))
		{
			CDataPacket* packet;

			if (NOERROR == (hr = CreateCert(&packet, pb, cb, m_bNonce, m_bMachineGuid,
				m_pCtx->m_pCertContext->pCertInfo, m_pCtx->m_hSignKey, 
				m_pCtx->m_pwszCaURL, m_pCtx->m_pwszOcspURL, 365*10)))
			{
				m_cbNeed = sizeof(m_bNonce), m_bWaitNonce = TRUE;
				hr = Send(packet);
				packet->Release();
			}
		}

		DbgPrint("%hs<%p>(%u)=%x\r\n", __FUNCTION__, this, cb, hr);
		return !hr;
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

		if (m_bWaitNonce)
		{
			if (memcmp(Buffer, m_bNonce, sizeof(m_bNonce)))
			{
				DbgPrint("<%p>!!!!! wrong enroll !!!!!\r\n", this);
			}
			else
			{
				char sz[25];
				cbTransferred = _countof(sz);
				CryptBinaryToStringA(m_bMachineGuid, sizeof(m_bMachineGuid), 
					CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, sz, &cbTransferred);
				DbgPrint("<%p>----- cert enrolled for %hs -----\r\n", this, sz);
			}
			return FALSE;
		}

		if (sizeof(UH_PACKET) > cbTransferred)
		{
			m_cbNeed = sizeof(UH_PACKET) - cbTransferred;
			goto __need_more_data;
		}

		ULONG PacketSize = ph->getPacketSize();
		if (0x100000 < PacketSize || cbTransferred > PacketSize)
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

	~CServerEndpoint()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		m_pCtx->Release();
	}

public:

	CServerEndpoint(CSocketObject* pAddress, CServerContext* pCtx) : CTcpEndpoint(pAddress), m_pCtx(pCtx)
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		pCtx->AddRef();
	}
};

//////////////////////////////////////////////////////////////////////////

CTcpEndpoint* CServerContext::getEndpoint(ENDPOINT_ENTRY* p)
{
	return static_cast<CServerEndpoint*>(p);
}

ENDPOINT_ENTRY* CServerContext::CreateEntry(CSocketObject* pAddress)
{
	if (CServerEndpoint* p = new CServerEndpoint(pAddress, this))
	{
		if (!p->Create(0x10000))
		{
			return p;
		}

		p->Release();
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////

#include "../inc/initterm.h"

#include "AlertByThreadId.h"

TIDFA g_tid;

void IO_RUNDOWN::RundownCompleted()
{
	g_tid.Alert();
}

void LocalTest()
{
	BCRYPT_KEY_HANDLE hKey;
	PCCERT_CONTEXT pCertContext;
	//release\\C\\certificates\\OEM_Intermediate_Cert_2017.pfx //OEM_Intermediate_Cert_2017.cer
	if (!PFXImport(TRUE, L"O:\\vc\\x64\\PFX\\DESKTOP-2N5ODLB.pfx", L"0", &hKey, &pCertContext))
	{
		PBYTE pbPKCS, pbNonce;
		ULONG cbPKCS, cbNonce;
		if (!ReadFromFile(L"nonce", &pbNonce, &cbNonce))
		{
			if (20 == cbNonce && !ReadFromFile(L"pkcs#10", &pbPKCS, &cbPKCS))
			{
				CDataPacket* packet;
				UCHAR mguid[16];
				if (!CreateCert(&packet, pbPKCS + 16, cbPKCS - 16, pbNonce, mguid,
					pCertContext->pCertInfo, hKey,
					L"http://DESKTOP-2N5ODLB/file/C/DESKTOP-2N5ODLB.cer",
					L"http://DESKTOP-2N5ODLB:28018/ocsp",
					365 * 10))
				{
					packet->Release();
				}
				LocalFree(pbPKCS);
			}
		}

		CertFreeCertificateContext(pCertContext);
		BCryptDestroyKey(hKey);
	}
}

void Run(_In_ PCWSTR pwszCaURL, 
		 _In_ PCWSTR pwszOcspURL,
		 _In_ USHORT PortNumber,
		 _In_ PCWSTR enc_name, 
		 _In_ PCWSTR sign_name, 
		 _In_opt_ PCWSTR pszPassword = 0)
{
	DbgPrint("%hs(%u, \"%ws\", \"%ws\", \"%ws\")\r\n", __FUNCTION__, PortNumber, sign_name, enc_name, pszPassword);
	initterm();

	WSADATA wd;
	if (!WSAStartup(WINSOCK_VERSION, &wd))
	{
		if (PortList* pl = new PortList)
		{
			if (CServerContext* ctx = new CServerContext(pwszCaURL, pwszOcspURL))
			{
				if (!ctx->InitCommon() &&
					!ctx->Init(sign_name, pszPassword, TRUE) &&
					!ctx->Init(enc_name, pszPassword, FALSE))
				{
					Port* port;
					SOCKADDR_INET sa {};

					sa.si_family = AF_INET;
					sa.Ipv4.sin_port = _byteswap_ushort(PortNumber);
					if (!pl->CreatePort(&port, ctx, (sockaddr*)&sa, sizeof(sa.Ipv4)))
					{
						port->Start(2, 4);
						port->Release();
					}

					sa.si_family = AF_INET6;
					sa.Ipv6.sin6_port = _byteswap_ushort(PortNumber);
					if (!pl->CreatePort(&port, ctx, (sockaddr*)&sa, sizeof(sa.Ipv6)))
					{
						port->Start(1, 3);
						port->Release();
					}
				}

				ctx->Release();
			}

			pl->Release();
		}

		//Sleep(4000);
		MessageBoxW(0, 0, L"server running...", MB_ICONINFORMATION);
		IO_RUNDOWN::g_IoRundown.BeginRundown();
		WSACleanup();
	}

	g_tid.WaitForAlert();
	destroyterm();
}

void cstry();
void TPM20Test();


void WINAPI ep(PWSTR pszCommandLine)
{
	InitLog(L"PKCS#10.log");
	LocalTest();

	//TestP1();
	//SetPrivKey(L"e165a64c6e0ae82fa1d085d794fd9b0a8ca89b83");

	// *http://DESKTOP-2N5ODLB/file/C/OEM_Intermediate_Cert_2017.cer*http://DESKTOP-2N5ODLB:28018/ocsp*33333*f6ad3b9c703cf7b18febfe214bc21dbadbab047d
	// *http://DESKTOP-2N5ODLB/file/C/OEM_Intermediate_Cert_2017.cer*http://DESKTOP-2N5ODLB:28018/ocsp*33333?O:\vc\x64\release\C\certificates\OEM_Intermediate_Cert_2017.pfx*

	// *pwszCaURL*pwszOcspURL*file*port?file*password
	// *pwszCaURL*pwszOcspURL*cert-hash*port*cert-hash

	if (PWSTR pwszCaURL = wcschr(GetCommandLineW(), '*'))
	{
		if (PWSTR pwszOcspURL = wcschr(++pwszCaURL, '*'))
		{
			*pwszOcspURL++ = 0;

			if (PWSTR enc_name = wcschr(pwszOcspURL, '*'))
			{
				*enc_name++ = 0;

				if (pszCommandLine = wcschr(enc_name, '*'))
				{
					*pszCommandLine++ = 0;

					if (ULONG Port = wcstoul(pszCommandLine, &pszCommandLine, 10))
					{
						if (Port < MAXUSHORT)
						{
							switch (*pszCommandLine++)
							{
							case '*':
								Run(pwszCaURL, pwszOcspURL, (USHORT)Port, enc_name, pszCommandLine);
								break;
							case '?':
								PWSTR sign_name = pszCommandLine;
								if (pszCommandLine = wcschr(pszCommandLine, '*'))
								{
									*pszCommandLine++ = 0;
									Run(pwszCaURL, pwszOcspURL, (USHORT)Port, enc_name, sign_name, pszCommandLine);
								}
								break;
							}
						}
					}
				}
			}
		}
	}
	else
	{
		cstry();
		TPM20Test();
		LocalTest();
	}

	DestroyLog();
	ExitProcess(0);
}

_NT_END