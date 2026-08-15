#include "stdafx.h"
_NT_BEGIN
#include <schannel.h>
#include "../winZ/str.h"

#include "../asio/port.h"
#include "../asio/SSL.h"
#include "../log/log.h"
#include "util.h"
#include "..\EnrollHlp\EnrollHlp.h"

struct ServerContextSSL : PortContext
{
	enum {
		cbBuffer = 0x8000
	};

	PCWSTR m_pwszCaURL;
	PCWSTR m_pwszOcspURL;
	PCCERT_CONTEXT m_pCertContext = 0;
	BCRYPT_KEY_HANDLE m_hSignKey = 0; //
	SharedCred* _M_pCred = 0;

	virtual CTcpEndpoint* getEndpoint(ENDPOINT_ENTRY* Entry);

	virtual ENDPOINT_ENTRY* CreateEntry(CSocketObject* pAddress);

	virtual ULONG GetReceiveDataLength()
	{
		return 0;
	}

	NTSTATUS InitTLS(_In_ PCCERT_CONTEXT pCertContext)
	{
		HRESULT hr;
		if (SharedCred* pCred = HR(hr, new SharedCred))
		{
			hr = pCred->Acquire(SECPKG_CRED_INBOUND, pCertContext, 
				SCH_CRED_MANUAL_CRED_VALIDATION|SCH_CRED_NO_DEFAULT_CREDS , 
				SP_PROT_TLS1_1PLUS_SERVER);

			_M_pCred = pCred;
		}

		return hr;
	}

	NTSTATUS InitSign(_In_ PCWSTR lpFileName, _In_ PCWSTR pszPassword)
	{
		return PFXImport(TRUE, lpFileName, pszPassword, &m_hSignKey, &m_pCertContext);
	}

	NTSTATUS InitTLS(PCWSTR szHash)
	{
		HRESULT hr;

		UCHAR hash[SHA1_DIGEST_SIZE];
		DATA_BLOB db = { sizeof(hash), hash };

		if (HR(hr, CryptStringToBinaryW(szHash, 0, CRYPT_STRING_HEXRAW, hash, &db.cbData, 0, 0)))
		{
			if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
				CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|CERT_SYSTEM_STORE_LOCAL_MACHINE, L"My")))
			{
				if (PCCERT_CONTEXT pCertContext = HR(hr, CertFindCertificateInStore(
					hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &db, 0)))
				{
					hr = InitTLS(pCertContext);
					CertFreeCertificateContext(pCertContext);
				}

				CertCloseStore(hCertStore, 0);
			}
		}

		return hr;
	}

	~ServerContextSSL()
	{
		if (_M_pCred)
		{
			_M_pCred->Release();
		}

		if (m_pCertContext)
		{
			CertFreeCertificateContext(m_pCertContext);
		}

		if (m_hSignKey)
		{
			BCryptDestroyKey(m_hSignKey);
		}
	}

	ServerContextSSL(_In_ PCWSTR pwszCaURL, _In_ PCWSTR pwszOcspURL) : m_pwszCaURL(pwszCaURL), m_pwszOcspURL(pwszOcspURL)
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};

BOOL CreateTLSContext(_Out_ PortContext** ppctx,
					  _In_ PCWSTR pwszCaURL, 
					  _In_ PCWSTR pwszOcspURL,
					  _In_ PCWSTR lpFileName, 
					  _In_ PCWSTR szPassword, 
					  _In_ PCWSTR pcszTlsHash)
{
	if (ServerContextSSL* ctx = new ServerContextSSL(pwszCaURL, pwszOcspURL))
	{
		if (NOERROR == ctx->InitSign(lpFileName, szPassword) &&
			NOERROR == ctx->InitTLS(pcszTlsHash))
		{
			*ppctx = ctx;
			return TRUE;
		}

		ctx->Release();
	}

	return FALSE;
}

#define MAX_FILE_CHUNK 4000
#define PL(str) str, _countof(str) - 1

#include "set.h"

#define DB_KEY_SIZE 16

struct KAN 
{
	UCHAR m_bKey[DB_KEY_SIZE];
	UCHAR m_bNonce[SHA1_DIGEST_SIZE];
};

class ClientContext : public MElement
{
public:
	ULONG64 m_time = GetTickCount64() + 60000;// 1min
	WCHAR m_UserName[(2 + 4 + 15 + (11 * 5) + 2)];
	KAN m_k;
	UCHAR m_bMachineGuid[16] = {};

	virtual const void* key() const
	{
		return m_k.m_bKey;
	}

	~ClientContext()
	{
		DbgPrint("%hs<%p>(%ws) [%d]\r\n", __FUNCTION__, this, m_UserName, GetTickCount64() - m_time);
	}

	ClientContext()
	{
		*m_UserName = 0;
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};

class CCIr : public InsertRemove
{
	virtual const void* key() const
	{
		return reinterpret_cast<const KAN*>(__super::key())->m_bKey;
	}

	virtual void OnInsert(ElementBase* p) const
	{
		memcpy(&(new(p) ClientContext)->m_k, __super::key(), sizeof(KAN));
	}

	using InsertRemove::InsertRemove;
};

class SDB : public SetBase
{
	virtual RTL_GENERIC_COMPARE_RESULTS KeyCompare(_In_ const void* p, _In_ const void* q)
	{
		int i = memcmp(p, q, DB_KEY_SIZE);
		if (0 > i) return GenericLessThan;
		if (0 < i) return GenericGreaterThan;
		return GenericEqual;
	}
};

bool WINAPI NeedRemove(void* time, MElement* p)
{
	return static_cast<ClientContext*>(p)->m_time < (ULONG_PTR)time;
}

static SDB g_db;

void CheckDB()
{
	g_db.MultiRemove(NeedRemove, (PVOID)(ULONG_PTR)GetTickCount64());
}

NTSTATUS InsertContext(_Out_ KAN* p)
{
	if (NTSTATUS status = BCryptGenRandom(0, (PBYTE)p, sizeof(KAN), BCRYPT_USE_SYSTEM_PREFERRED_RNG))
	{
		return status;
	}
	return g_db.Insert(CCIr(p), sizeof(ClientContext));
}

class ServerEndpointSsl : public CSSLEndpoint, public ENDPOINT_ENTRY
{
	LARGE_INTEGER m_NumberOfBytesToWrite;
	PBYTE m_buf;
	ServerContextSSL* m_pCtx;
	PSTR _m_buf, _M_PostData = 0;
	ULONG m_cbData, m_cbNeed, m_type;
	BOOLEAN m_bnotFirst, m_bReadFile, m_bFinal, m_bLog;

	virtual void LogError(DWORD opCode, DWORD dwError)
	{
		ULONG64 u = _byteswap_ulong(opCode);
		DbgPrint("!! [%hs]<%p>: %u\n", &u, this, dwError);
	}

	void LogEvent(PCSTR msg)
	{
		char sz[64];
		DWORD cch = sizeof(sz);

		NTSTATUS status = -1;

		switch (m_RemoteAddr.sa_family)
		{
		case AF_INET:
			status = RtlIpv4AddressToStringExA(&m_RemoteSockaddr.sin_addr, m_RemoteSockaddr.sin_port, sz, &cch);
			break;
		case AF_INET6:
			status = RtlIpv6AddressToStringExA(&m_RemoteSockaddr6.sin6_addr, m_RemoteSockaddr6.sin6_scope_id, m_RemoteSockaddr6.sin6_port, sz, &cch);
			break;
		}

		if (0 > status)
		{
			*sz = 0;
		}
		DbgPrint("[%hs<%p>] %hs\r\n", msg, this, sz);
	}

	void InitData()
	{
		SetDisconnectTime(8);
		m_cbData = 0, m_bnotFirst = FALSE, _m_buf = 0, _M_PostData; 
		m_cbNeed = 0, m_bReadFile = FALSE, m_bFinal = FALSE, m_bLog = FALSE;
		m_buf = 0, m_NumberOfBytesToWrite.QuadPart = 0;
	}

	void CleanupData()
	{
		if (_M_PostData)
		{
			delete [] _M_PostData;
			m_cbNeed = 0;
			m_cbData = 0;
		}
	}

	virtual void OnSend(CDataPacket* packet);

	//////////////////////////////////////////////////////////////////////////
	virtual SECURITY_STATUS OnEndHandshake()
	{
		LogEvent(__FUNCTION__);
		return SEC_E_OK;
	}

	virtual void OnShutdown()
	{
		LogEvent(__FUNCTION__);
	}

	virtual BOOL OnUserData(PSTR buf, ULONG cb);

	virtual BOOL IsServer(PBOOLEAN pbMutualAuth = 0)
	{
		if (pbMutualAuth)
		{
			*pbMutualAuth = FALSE;//
		}
		return TRUE;
	}

	BOOL OnConnect(ULONG dwError)
	{
		_Port->OnConnect(dwError);

		if (!dwError)
		{
			LogEvent(__FUNCTION__);
			InitData();
			SetDisconnectTime(8);
		}
		else if (ERROR_OPERATION_ABORTED != dwError)
		{
			DbgPrint("!!! OnConnect(%u)\r\n", dwError);
		}

		return dwError ? FALSE : StartSSL();
	}

	void OnDisconnect()
	{
		LogEvent(__FUNCTION__);

		StopSSL();
		CleanupData();

		_Port->OnDisconnect(this);
	}

	BOOL SendXXXPacket(LPCVOID body, DWORD cbBody);

	BOOL OnPost(ULONG type, PBYTE pb, ULONG cb);

	BOOL OnHandshake();
	BOOL OnPKCS10(PBYTE pb, ULONG cb);
	BOOL OnSecret(PBYTE pb, ULONG cb);

	//////////////////////////////////////////////////////////////////////////

	~ServerEndpointSsl()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		m_pCtx->Release();
	}
public:
	ServerEndpointSsl(CSocketObject* pAddress, ServerContextSSL* pCtx) : CSSLEndpoint(pCtx->_M_pCred, pAddress), m_pCtx(pCtx)
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		pCtx->AddRef();
	}
};

void ServerEndpointSsl::OnSend(CDataPacket* packet)
{
	if (ULONG dwBytes = min(MAX_FILE_CHUNK, (ULONG)m_NumberOfBytesToWrite.QuadPart))
	{
		DbgPrint("%hs<%p>(%x/%I64x)\r\n", __FUNCTION__, this, dwBytes, m_NumberOfBytesToWrite.QuadPart);

		memcpy(_m_buf, m_buf, dwBytes);

		m_buf += dwBytes;
		if (!(m_NumberOfBytesToWrite.QuadPart -= dwBytes))
		{
			m_buf = 0;
		}
		SendUserData(dwBytes, packet);
	}
}

BOOL ServerEndpointSsl::SendXXXPacket(LPCVOID body, DWORD cbBody)
{
	STATIC_ASTRING(head,
		"HTTP/1.1 200\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n"
		"Pragma: no-cache\r\n"
		"Cache-Control: no-cache, no-store\r\n"
		"Connection: close\r\n"
		"\r\n"
		);

	PSTR buf = 0;
	int len = 0;
	CDataPacket* packet = 0;
	BOOL fOk = FALSE;
	ULONG cbSend = cbBody;

	while (0 < (len = _snprintf(buf, len, head, cbBody)))
	{
		if (buf)
		{
			memcpy(buf + len, body, cbSend);
			if (cbSend != cbBody)
			{
				_m_buf = buf;
				DbgPrint("%hs<%p>(%x/%x)\r\n", __FUNCTION__, this, cbSend, cbBody);
			}
			//LOG(write(buf, len + cbBody));
			//LOG(write("\r\n>>>>\r\n", 8));
			fOk = !SendUserData(len + cbSend, packet);

			break;
		}

		if (len + cbBody > MAX_FILE_CHUNK)
		{
			m_NumberOfBytesToWrite.QuadPart = cbBody - (cbSend = MAX_FILE_CHUNK - len);
			m_buf = (PBYTE)body + cbSend;// body must be valid until post end !!
		}

		if (!(packet = AllocPacket(len + cbSend, buf)))
		{
			break;
		}
	}

	if (packet) packet->Release();

	return fOk;
}

BOOL ServerEndpointSsl::OnHandshake()
{
	KAN kan;

	if (0 <= InsertContext(&kan))
	{
		SendXXXPacket(&kan, sizeof(kan));
	}

	return FALSE;
}

BOOL ServerEndpointSsl::OnPKCS10(PBYTE pb, ULONG cb)
{
	if (cb <= DB_KEY_SIZE)
	{
		return FALSE;
	}

	if (ClientContext* ctx = static_cast<ClientContext*>(g_db.Get(pb)))
	{
		enum { cbPacket = 0x4000 };
		PSTR buf;
		if (CDataPacket* packet = AllocPacket(cbPacket, buf))
		{
			STATIC_ASTRING(head,
				"HTTP/1.1 200\r\n"
				"Content-Type: application/octet-stream\r\n"
				"Content-Length: *****\r\n"
				"Pragma: no-cache\r\n"
				"Cache-Control: no-cache, no-store\r\n"
				"Connection: close\r\n"
				"\r\n"
				);

			memcpy(buf, head, sizeof(head) - 1);

			if (0 <= CreateCert((PBYTE)buf + sizeof(head) - 1, cbPacket - sizeof(head) + 1, &cb, 
				pb + DB_KEY_SIZE, cb - DB_KEY_SIZE, 
				ctx->m_k.m_bNonce, ctx->m_bMachineGuid, ctx->m_UserName, _countof(ctx->m_UserName),
				m_pCtx->m_pCertContext->pCertInfo, m_pCtx->m_hSignKey, 
				m_pCtx->m_pwszCaURL, m_pCtx->m_pwszOcspURL, 365*10))
			{
				char cc[6];
				sprintf_s(cc, _countof(cc), "%5u", cb);
				memcpy(strchr(buf, '*'), cc, 5);
				m_cbNeed = SHA1_DIGEST_SIZE;
				SendUserData(sizeof(head) - 1 + cb, packet);
			}
			packet->Release();

		}
		ctx->Release();
	}

	return FALSE;
}

BOOL ServerEndpointSsl::OnSecret(PBYTE pb, ULONG cb)
{
	if (cb != DB_KEY_SIZE+SHA1_DIGEST_SIZE)
	{
		return FALSE;
	}

	MElement* mctx;
	if (g_db.Erase(pb, &mctx))
	{
		ClientContext* ctx = static_cast<ClientContext*>(mctx);
		BOOLEAN b = !memcmp(ctx->m_k.m_bNonce, pb + DB_KEY_SIZE, SHA1_DIGEST_SIZE);
		char sz[25];
		CryptBinaryToStringA(ctx->m_bMachineGuid, sizeof(ctx->m_bMachineGuid), 
			CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, sz, &(cb = _countof(sz)));

		LogOutputNT(~0, b ? L"<%p>----- cert enrolled for %hs:%ws -----\r\n" : L"<%p>!!!!! wrong enroll for %hs:%ws !!!!!\r\n", 
			this, sz, ctx->m_UserName);

		SendXXXPacket(&b, sizeof(b));

		mctx->Release();
	}

	return FALSE;
}

BOOL ServerEndpointSsl::OnPost(ULONG type, PBYTE pb, ULONG cb)
{
	switch (type)
	{
	case 0xade2f5c4: // "api/v1/nonce"
		return OnSecret(pb, cb);

	case 0x5fb985c8: // "api/v1/handshake/register-session"
		return OnHandshake();

	case 0xe1cb9b95: // "api/v1/pkcs10"
		return OnPKCS10(pb, cb);
	}

	return FALSE;
}

BOOL ServerEndpointSsl::OnUserData(PSTR Buffer, ULONG cbTransferred)
{
	LogEvent(__FUNCTION__);

	DbgPrint("m_cbNeed: %x %x/%x %p\r\n", cbTransferred, m_cbData, m_cbNeed, _M_PostData);

	if (m_cbNeed)
	{
		if (cbTransferred > m_cbNeed)
		{
			return FALSE;
		}

		memcpy(_M_PostData + m_cbData, Buffer, cbTransferred);

		if (m_cbData += cbTransferred, m_cbNeed -= cbTransferred)
		{
			return TRUE;
		}

		DbgPrint("********* post end ****\r\n\r\n");

		BOOL b = OnPost(m_type, (PBYTE)_M_PostData, m_cbData);

		delete [] _M_PostData;
		_M_PostData = 0;
		m_cbData = 0;
		m_cbNeed = 0;

		return b;
	}

	PSTR body = strnstr(cbTransferred, Buffer, LP("\r\n\r\n"));

	if (!body) return FALSE;

	PSTR UA = _strnstr(Buffer, body, "\r\nUser-Agent: ");

	if (UA)
	{
		_strnchr(UA, body, '\r')[-1] = 0;
	}

	PSTR end = strnchr(cbTransferred, Buffer, '\r');

	end[-1] = 0;

	if (!(end = strchr(Buffer + 5, ' '))) return FALSE;

	*end = 0;

	cbTransferred = RtlPointerToOffset(body, end = Buffer + cbTransferred);

	ULONG Content_Length = 0;

	PSTR c = _strnstr(Buffer, body, "\nContent-Length: ");

	if (c)
	{
		Content_Length = strtoul(c, &c, 10);

		if (*c != '\r')
		{
			Content_Length = 0;
		}
	}

	if (!memcmp(Buffer, PL("POST /")))
	{
		Buffer += sizeof("POST /") - 1;

		m_type = RtlCrc32(Buffer, strlen(Buffer), 0);

		DbgPrint("\"%hs\" [%x] %x/%x\r\n", Buffer, m_type, cbTransferred, Content_Length);

		if (cbTransferred > Content_Length || Content_Length > 0x4000)
		{
			return FALSE;
		}

		if (cbTransferred < Content_Length)
		{
			if (_M_PostData = new char[Content_Length])
			{
				memcpy(_M_PostData, body, cbTransferred);
				m_cbNeed = Content_Length - cbTransferred;
				m_cbData = cbTransferred;

				return TRUE;
			}

			return FALSE;
		}

		return OnPost(m_type, (PBYTE)body, cbTransferred);
	}

	return FALSE;
}

ENDPOINT_ENTRY* ServerContextSSL::CreateEntry(CSocketObject* pAddress)
{
	if (ServerEndpointSsl* p = new ServerEndpointSsl(pAddress, this))
	{
		if (!p->Create(cbBuffer))
		{
			return p;
		}

		p->Release();
	}

	return 0;
}

CTcpEndpoint* ServerContextSSL::getEndpoint(ENDPOINT_ENTRY* Entry)
{
	return static_cast<ServerEndpointSsl*>(Entry);
}

_NT_END