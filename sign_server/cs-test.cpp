#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../asio/packet.h"
#include "util.h"
#include "decode.h"
#include "cs-test-w.h"

BOOL ExportPublicKeyInfoB(_In_ PVOID hKey, _Out_ PCERT_PUBLIC_KEY_INFO pInfo, _Inout_ DWORD *pcbInfo);

static PVOID pfnAlloc(_In_ size_t cbSize)
{
	if (CDataPacket* packet = new((ULONG)cbSize) CDataPacket)
	{
		return packet + 1;
	}

	return 0;
};

static void WINAPI pfnFree(_In_ PVOID pv)
{
	((CDataPacket*)pv - 1)->Release();
};

#include "pkt.h"

struct __declspec(novtable) CTEndpoint : public YCS
{
	using YCS::YCS;
	BCRYPT_KEY_HANDLE m_hAesKey = 0; 
	ULONG m_nMsg = 2;

	void OnUserData(PBYTE pb, ULONG cb)
	{
		DbgPrint("%hs:%.*hs\r\n", m_name, min(cb, 0x100), pb);
	}

	virtual void OnDisconnect()
	{
		if (m_hAesKey)
		{
			BCryptDestroyKey(m_hAesKey);
		}
	}

	BOOL SendMsg()
	{
		if (!m_nMsg)
		{
			return FALSE;
		}
		ULONG nMsg = --m_nMsg;
		PBYTE psz = 0;
		ULONG len = 0;
		CDataPacket* packet = 0;
		UH_PACKET* ph = 0;

		while (0 < (int)(len = _snprintf((PSTR)psz, len, "message:#%u from [%hs]", nMsg, m_name)))
		{
			if (psz)
			{
				if (0 <= ph->AES_Encode(m_hAesKey, psz, len))
				{
					packet->setDataSize(ph->getPacketSize());
					return post(packet);
				}
				break;
			}

			if (!(ph = UH_PACKET::AES_Allocate(len, &psz, &packet)))
			{
				return FALSE;
			}
		}

		if (packet)
		{
			packet->Release();
		}

		return FALSE;
	}

	virtual BOOL OnFirstPacket(PBYTE pb, ULONG cb) = 0;

	virtual BOOL OnData(PBYTE pb, ULONG cb)
	{
		if (m_hAesKey)
		{
			if (UH_PACKET::MinPacketSize() < cb)
			{
				if (0 <= reinterpret_cast<UH_PACKET*>(pb)->AES_Decode(m_hAesKey, &pb, &cb))
				{
					OnUserData(pb, cb);

					return SendMsg();
				}
			}
			return FALSE;
		}

		return OnFirstPacket(pb, cb);
	}
};

struct CTestServer : public CTEndpoint 
{
	using CTEndpoint::CTEndpoint;

	ULONG m_cbData;

	BOOL OnData(PCERT_PUBLIC_KEY_INFO pInfo)
	{
		BOOL f = FALSE;
		PCWSTR pszEccAlgId = 0;
		HRESULT hr;

		BCRYPT_KEY_HANDLE hPubKey;
		if (IsSupportedAlg(&pInfo->Algorithm, &pszEccAlgId) &&
			HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pInfo, CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, 0, &hPubKey)))
		{
			if (PBYTE pbData = new BYTE[m_cbData])
			{
				RtlFillMemoryUlong(pbData, m_cbData, 'ATAD');

				CDataPacket* packet;

				if (NOERROR == (pszEccAlgId 
					? UH_PACKET::DH_Encode(hPubKey, pszEccAlgId, pbData, m_cbData, &packet, &m_hAesKey)
					: UH_PACKET::RSA_Encode(hPubKey, pbData, m_cbData, &packet, &m_hAesKey)))
				{
					f = post(packet);
					packet->Release();
				}
				delete [] pbData;
			}

			BCryptDestroyKey(hPubKey);
		}

		return f;
	}

	virtual BOOL OnFirstPacket(PBYTE pb, ULONG cb)
	{
		PCERT_PUBLIC_KEY_INFO pInfo;
		if (0 <= Decode(X509_PUBLIC_KEY_INFO, pb, cb, &pInfo))
		{
			BOOL f = OnData(pInfo);
			LocalFree(pInfo);
			return f;
		}

		return FALSE;
	}

	virtual BOOL OnConnect()
	{
		return TRUE;
	}
};

struct CTestClient : CTEndpoint 
{
	using CTEndpoint::CTEndpoint;

	BCRYPT_KEY_HANDLE m_hPrivKey = 0;
	PCWSTR m_pszAlgId;
	ULONG m_dwLength;

	virtual void OnDisconnect()
	{
		if (m_hPrivKey)
		{
			BCryptDestroyKey(m_hPrivKey);
		}
		CTEndpoint::OnDisconnect();
	}

	virtual BOOL OnFirstPacket(PBYTE pb, ULONG cb)
	{
		if (UH_PACKET::MinPacketSize() < cb)
		{
			if (0 <= reinterpret_cast<UH_PACKET*>(pb)->Decode(m_hPrivKey, &pb, &cb, &m_hAesKey))
			{
				OnUserData(pb,  cb);

				return SendMsg();
			}
		}

		return FALSE;
	}

	virtual BOOL OnConnect()
	{
		if (0 <= CreateKeyPairKey(&m_hPrivKey, m_pszAlgId, m_dwLength))
		{
			HRESULT hr;
			PCERT_PUBLIC_KEY_INFO pInfo = 0;
			ULONG cbInfo = 0;

			while (HR(hr, ExportPublicKeyInfoB(m_hPrivKey, pInfo, &cbInfo)))
			{
				if (pInfo)
				{
					CRYPT_ENCODE_PARA EncodePara = { sizeof(EncodePara), pfnAlloc, pfnFree };

					ULONG cb;
					CDataPacket* packet;
					if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, pInfo, 
						CRYPT_ENCODE_ALLOC_FLAG, &EncodePara, &packet, &cb))
					{
						(--packet)->setDataSize(cb);
						return post(packet);
					}

					break;
				}

				pInfo = (PCERT_PUBLIC_KEY_INFO)alloca(cbInfo);
			}
		}

		return FALSE;
	}
};

void cstry(PCWSTR pszAlgId, ULONG dwLength, ULONG DataSize)
{
	LONG r;
	CTestServer s(&r, "server");
	CTestClient c(&r, "client");
	s.m_cbData = DataSize;
	c.m_dwLength = dwLength;
	c.m_pszAlgId = pszAlgId;
	client_server_test(&r, &c, &s);
}

void cstry()
{
	if (YCS::Register())
	{
		cstry(BCRYPT_ECDH_P521_ALGORITHM, 0, 200);
		cstry(BCRYPT_RSA_ALGORITHM, 2048, 163);
		cstry(BCRYPT_RSA_ALGORITHM, 2048, 2000);

		YCS::Unregister();
	}
}

_NT_END