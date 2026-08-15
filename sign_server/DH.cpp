NTSTATUS CreateECDHKey(_In_ BCRYPT_KEY_HANDLE *phKey, PCWSTR pszAlgId)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;
		status = BCryptGenerateKeyPair(hAlgorithm, &hKey, 0, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			if (0 <= (status = BCryptFinalizeKeyPair(hKey, 0)))
			{
				*phKey = hKey;
				return STATUS_SUCCESS;
			}

			BCryptDestroyKey(hKey);
		}
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey, PBYTE pbSecret, ULONG cbSecret)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;

		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, pbSecret, cbSecret, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			if (0 <= (status = BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE, 
				(PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
			{
				*phKey = hKey;
				return STATUS_SUCCESS;
			}

			BCryptDestroyKey(hKey);
		}
	}

	return status;
}

struct CClientServer
{
	CClientServer* m_pLink = 0;

	BCRYPT_KEY_HANDLE m_hPriv = 0;
	BCRYPT_KEY_HANDLE m_hPub = 0;
	BCRYPT_KEY_HANDLE m_hAES = 0;

	PCSTR m_name;
	union {
		ULONG64 m_Nonce64;
		UCHAR m_Nonce[12];
	};
	ULONG m_nMsg = 2;
	bool m_bstart;

	CClientServer(PCSTR name, bool bstart) : m_name(name), m_bstart(bstart)
	{
	}

	~CClientServer()
	{
		if (m_hAES) BCryptDestroyKey(m_hAES);
		if (m_hPub) BCryptDestroyKey(m_hPub);
		if (m_hPriv) BCryptDestroyKey(m_hPriv);
	}

	NTSTATUS ImportPubKey(_In_ PBYTE pb, _In_ ULONG cb, _Out_ PCWSTR *ppszAlgId)
	{
		if (cb < sizeof(BCRYPT_ECCKEY_BLOB))
		{
			return STATUS_BAD_DATA;
		}

		NTSTATUS status;
		BCRYPT_ALG_HANDLE hAlgorithm;

		PCWSTR pszAlgId;
		switch (reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic)
		{
		case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
			pszAlgId = BCRYPT_ECDH_P256_ALGORITHM;
			break;
		case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
			pszAlgId = BCRYPT_ECDH_P384_ALGORITHM;
			break;
		case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
			pszAlgId = BCRYPT_ECDH_P521_ALGORITHM;
			break;
		case BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC:
			switch (reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pb)->cbKey)
			{
			case 32:
				pszAlgId = BCRYPT_ECDH_P256_ALGORITHM;
				break;
			case 48:
				pszAlgId = BCRYPT_ECDH_P384_ALGORITHM;
				break;
			case 66:
				pszAlgId = BCRYPT_ECDH_P521_ALGORITHM;
				break;
			default: return STATUS_NOT_SUPPORTED;
			}
			break;
		default: return STATUS_NOT_SUPPORTED;
		}

		if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
		{
			status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_ECCPUBLIC_BLOB, &m_hPub, pb, cb, 0);

			BCryptCloseAlgorithmProvider(hAlgorithm, 0);

			*ppszAlgId = pszAlgId;
		}

		return status;
	}

	NTSTATUS SharePubKey(BCRYPT_KEY_HANDLE hKey)
	{
		NTSTATUS status;
		PBYTE pb = 0;
		ULONG cb = 0;
		while (0 <= (status = BCryptExportKey(hKey, 0, BCRYPT_ECCPUBLIC_BLOB, pb, cb, &cb, 0)))
		{
			if (pb)
			{
				status = m_pLink->OnData(pb, cb);
				break;
			}

			pb = (PBYTE)alloca(cb);
		}

		return status;
	}

	NTSTATUS Start(PCWSTR pszAlgId)
	{
		NTSTATUS status;
		0 <= (status = BCryptGenRandom(0, m_Nonce, sizeof(m_Nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG)) &&
			0 <= (status = CreateECDHKey(&m_hPriv, pszAlgId)) && 0 <= (status = SharePubKey(m_hPriv));
		return status;
	}

	struct DMSG 
	{
		UCHAR Tag[0x10];
		union {
			ULONG64 Nonce64;
			struct {
				UCHAR Nonce[12];
				enum { e_magic = '>)(<' } magic;
			};
		};
		UCHAR Buf[];
	};

	NTSTATUS SendMsg()
	{
		PBYTE psz = 0;
		DMSG* msg = 0;
		ULONG len = 0;
		ULONG nMsg = m_nMsg--;
		while (0 < (int)(len = _snprintf((PSTR)psz, len, "message:#%u from [%hs]", nMsg, m_name)))
		{
			if (psz)
			{
				BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = { 
					sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, 
					msg->Nonce, sizeof(msg->Nonce), 0, 0, msg->Tag, sizeof(msg->Tag)
				};

				m_Nonce64++;
				memcpy(msg->Nonce, m_Nonce, sizeof(m_Nonce));
				msg->magic = DMSG::e_magic;

				NTSTATUS status;
				if (0 <= (status = BCryptEncrypt(m_hAES, psz, len, &acmi, 0, 0, psz, len, &len, 0)))
				{
					return m_pLink->OnData((PBYTE)msg, offsetof(DMSG, Buf) + len);
				}
				return status;
			}

			msg = (DMSG*)alloca(offsetof(DMSG, Buf) + len);
			psz = msg->Buf;
		}

		return STATUS_INTERNAL_ERROR;
	}

	void PrintKey(CONST BYTE *pbKey, _In_ DWORD cbKey)
	{
		PSTR psz = 0;
		ULONG cch = 0;
		while (CryptBinaryToStringA(pbKey, cbKey, CRYPT_STRING_BASE64, psz, &cch))
		{
			if (psz)
			{
				DbgPrint("%hs: %hs\r\n", m_name, psz);
				break;
			}

			psz = (PSTR)alloca(cch);
		}
	}

	NTSTATUS DeriveSessionKey()
	{
		NTSTATUS status;

		BCRYPT_SECRET_HANDLE hSecret = 0;
		if (0 <= (status = BCryptSecretAgreement(m_hPriv, m_hPub, &hSecret, 0)))
		{
			PBYTE pbSecret = 0;
			ULONG cbSecret = 0;

			while (0 <= (status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, 0, pbSecret, cbSecret, &cbSecret, 0)))
			{
				if (pbSecret)
				{
					UCHAR aes[32];
					ULONG cb = sizeof(aes);
					if (CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbSecret, cbSecret, aes, &cb))
					{
						PrintKey(aes, cb);
						if (0 <= (status = GenAesKey(&m_hAES, aes, cb)))
						{
							if (m_bstart)
							{
								SendMsg();
							}
						}
					}
					else
					{
						status = GetLastHresult();
					}

					break;
				}

				pbSecret = (PBYTE)alloca(cbSecret);
			}

			BCryptDestroySecret(hSecret);
		}

		return status;
	}

	NTSTATUS OnData(PBYTE pb, ULONG cb)
	{
		NTSTATUS status;
		if (!m_hPub)
		{
			PCWSTR pszAlgId;
			if (0 <= (status = ImportPubKey(pb, cb, &pszAlgId)))
			{
				if (!m_hPriv)
				{
					status = Start(pszAlgId);
				}

				if (0 <= status)
				{
					status = DeriveSessionKey();
				}
			}

			return status;
		}

		if (m_hAES)
		{
			if (offsetof(DMSG, Buf) <= cb)
			{
				DMSG* msg = (DMSG*)pb;
				if (DMSG::e_magic == msg->magic)
				{
					pb = msg->Buf, cb -= offsetof(DMSG, Buf);

					BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO acmi = { 
						sizeof(acmi), BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION, 
						msg->Nonce, sizeof(msg->Nonce), 0, 0, msg->Tag, sizeof(msg->Tag)
					};

					if (0 <= (status = BCryptDecrypt(m_hAES, pb, cb, &acmi, 0, 0, pb, cb, &cb, 0)))
					{
						DbgPrint("%hs: << %.*hs\r\n", m_name, cb, pb);

						if (m_nMsg)
						{
							return SendMsg();
						}
					}

					return status;
				}
			}
		}

		return STATUS_INVALID_DEVICE_STATE;
	}
};

void DemoDH()
{
	CClientServer c("client", true), s("server", false);
	c.m_pLink = &s;
	s.m_pLink = &c;
	s.Start(BCRYPT_ECDH_P521_ALGORITHM);
}

/*
[2026-04-14 18:48:41] server: tWiFgxhDbWYjTNrrWHB5Sj+R6uxHWtNQVcNOX/8AqXY=

[2026-04-14 18:48:41] client: tWiFgxhDbWYjTNrrWHB5Sj+R6uxHWtNQVcNOX/8AqXY=

[2026-04-14 18:48:41] server: << message:#2 from [client]
[2026-04-14 18:48:41] client: << message:#2 from [server]
[2026-04-14 18:48:41] server: << message:#1 from [client]
[2026-04-14 18:48:41] client: << message:#1 from [server]
*/