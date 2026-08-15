#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../asio/socket.h"
#include "util.h"
#include "pkt.h"
#include "pkcs#10.h"
#include "machine-uuid.h"
#include "decode.h"
#include "dns.h"
#include "resource.h"

// Windows 8 and above
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4) // NtOpenProcessToken(NtCurrentProcess())
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5) // NtOpenThreadToken(NtCurrentThread())
#define NtCurrentThreadEffectiveToken() ((HANDLE)(LONG_PTR)-6) // NtOpenThreadToken(NtCurrentThread()) + NtOpenProcessToken(NtCurrentProcess())

extern const WCHAR Device[];
extern const WCHAR MyId[];

NTSTATUS CreateSafeBag(
	_Out_ void** ppvBag,
	_Out_ ULONG* pcbBag,
	_In_ PBYTE pbCertEncoded,
	_In_ ULONG cbCertEncoded,
	_In_ BCRYPT_KEY_HANDLE hKey,
	_In_ UCHAR SerialMD5[],
	_In_ PCSTR pin);

NTSTATUS CreateContainer(_Out_ PHANDLE phFile, _In_ ULONG DeviceNumber, _Out_ PWSTR szVolume, _In_ ULONG cchVolume);

class CAIKClient : public CTcpEndpoint
{
	HWND m_hwnd;
	//PCWSTR m_pszAIKAlgId;
	PCWSTR m_pszKeyEncryptAlgId = BCRYPT_RSA_ALGORITHM;
	PCWSTR m_pszKeySignAlgId = BCRYPT_RSA_ALGORITHM;
	BCRYPT_KEY_HANDLE m_hKey = 0;
	BCRYPT_KEY_HANDLE m_hServerPubKey;
	UCHAR m_SerialMD5[16];
	ULONG m_DeviceNumber;
	//NCRYPT_KEY_HANDLE m_hAIK = 0;
	//HANDLE m_hToken;
	ULONG m_cbNeed;
	BOOL m_bWaitCert = FALSE;
	HRESULT m_hr = E_FAIL;
	//WCHAR m_pszKeyName[32];
	UCHAR m_nonce[SHA1_DIGEST_SIZE];
	char m_pin[];

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
		//if (m_hAIK)
		//{
		//	if (ph->getTpmSize(&cbSecret, &cbCertEncoded, &pbSecret, &pbCertEncoded))
		//	{
		//		line = __LINE__;
		//		DbgPrint("%hs<%p>(cbSecret=%x cbCertEncoded=%x)\r\n", __FUNCTION__, this, cbSecret, cbCertEncoded);
		//		//if (NOERROR == (hr = DecryptSecret(m_hAIK, pbSecret, cbSecret, &cbSecret)))
		//		//{
		//		//	line = __LINE__;
		//		//	UCHAR aes[32];
		//		//	ULONG cb = sizeof(aes);

		//		//	if (HR(hr, CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbSecret, cbSecret, aes, &cb)) &&
		//		//		0 <= (hr = CFBXcrypt(aes, cb, pbCertEncoded, cbCertEncoded, pbCertEncoded, TRUE)))
		//		//	{
		//		//		line = __LINE__;
		//		//		if (!(hr = AddEncodedCertificateToStore(&pCertContext, 
		//		//			m_hToken, pbCertEncoded, cbCertEncoded, m_pszKeyName)))
		//		//		{
		//		//			fOk = TRUE;
		//		//		}
		//		//	}
		//		//}
		//	}
		//}
		//else
		{
			line = __LINE__;
			if (0 <= (hr = ph->Decode(m_hKey, &pbCertEncoded, &cbCertEncoded)))
			{
				line = __LINE__;
				PVOID pvBag;
				ULONG cbBag;
				if (!(hr = CreateSafeBag(&pvBag, &cbBag, pbCertEncoded, cbCertEncoded, m_hKey, m_SerialMD5, m_pin)))
				{
					WCHAR buf[0x200];
					int cch = swprintf_s(buf, _countof(buf), L"%ws%ws", Device, MyId);

					if (0 > cch)
					{
						hr = ERROR_INTERNAL_ERROR;
					}
					else
					{
						HANDLE hFile;
						if (0 <= (hr = CreateContainer(&hFile, m_DeviceNumber, buf + cch, _countof(buf) - cch)))
						{
							IO_STATUS_BLOCK iosb;
							hr = NtWriteFile(hFile, 0, 0, 0, &iosb, pvBag, cbBag, 0, 0);
							NtClose(hFile);

							if (0 <= hr)
							{
								pbSecret = m_nonce, cbSecret = sizeof(m_nonce);
								fOk = TRUE;
								UNICODE_STRING ObjectName;
								OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
								RtlInitUnicodeString(&ObjectName, buf);
								if (0 <= NtOpenFile(&oa.RootDirectory, SYNCHRONIZE, &oa, &iosb, 0, FILE_SYNCHRONOUS_IO_ALERT))
								{
									NtClose(oa.RootDirectory);
								}
								pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded);
							}
						}
					}

					LocalFree(pvBag);
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
						NtCurrentProcessToken(), MS_SMART_CARD_KEY_STORAGE_PROVIDER, MachineName)))
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
				//DATA_BLOB request;
				//BOOL bTpmPresent;
				//if (NOERROR == (hr = StartAIKHandshake(m_pszAIKAlgId, m_pszKeyName, m_pszKeySignAlgId, 
				//	pszPublicKeyObjId, (PBYTE)Buffer, m_hToken, &bTpmPresent, &request, &m_hAIK)))
				//{
				//	hr = SendMsg(request.pbData, request.cbData);
				//	LocalFree(request.pbData);

				//	return !hr;
				//}

				//if (bTpmPresent)
				//{
				//	m_hr = hr;
				//	return FALSE;
				//}
				
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

		//if (m_hAIK)
		//{
		//	NCryptFreeObject(m_hAIK);
		//}

		if (m_hwnd)
		{
			if (!PostMessageW(m_hwnd, WM_RETURN_KEY, m_hr, (LPARAM)m_hServerPubKey))
			{
				BCryptDestroyKey(m_hServerPubKey);
			}
		}
	}

public:
	void* operator new(size_t s, size_t len)
	{
		return LocalAlloc(LMEM_FIXED, s + len);
	}

	void operator delete(PVOID pv)
	{
		LocalFree(pv);
	}

	CAIKClient(HWND hwnd, BCRYPT_KEY_HANDLE hServerPubKey, ULONG DeviceNumber, PCSTR pcszPin, PBYTE SerialMD5)
		: m_hServerPubKey(hServerPubKey), m_hwnd(hwnd), m_DeviceNumber(DeviceNumber)
	{
		strcpy(m_pin, pcszPin);
		memcpy(m_SerialMD5, SerialMD5, 16);
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};

HRESULT StartRequest(
	PSOCKADDR_INET psi, 
	HWND hwnd, 
	BCRYPT_KEY_HANDLE* phServerPubKey, 
	ULONG DeviceNumber, 
	PCSTR pcszPin, 
	PBYTE SerialMD5)
{
	HRESULT hr = STATUS_NO_MEMORY;
	if (CAIKClient* p = new(strlen(pcszPin) + 1) CAIKClient(hwnd, *phServerPubKey, DeviceNumber, pcszPin, SerialMD5))
	{
		*phServerPubKey = 0;

		if (!(hr = p->Create(0x10000, psi->si_family)))
		{
			if (!(hr = p->Connect(psi)))
			{
				EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
			}
		}
		p->Release();
	}

	return hr;
}

_NT_END