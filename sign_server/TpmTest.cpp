#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "TPM.h"
#include "util.h"

void reverse(PBYTE pb, ULONG cb );

NTSTATUS EccSecretEncrypt(_In_ BCRYPT_KEY_HANDLE hPubKey,
						  _In_ PCWSTR ekNameAlg,
						  _In_ PCWSTR pszAlgId,
						  _Out_ PBYTE pbBlob,
						  _In_ ULONG cbBlob,
						  _Out_ PULONG pcbBlob,
						  _Out_ PBYTE pbSeed, 
						  _In_ ULONG cbSeed);

NTSTATUS CryptKDFe(_In_ PCWSTR ekNameAlg,
				   _In_ PBYTE pbSecret,
				   _In_ ULONG cbSecret,
				   _In_ PVOID pvU,
				   _In_ ULONG cbU,
				   _In_ PVOID pvV,
				   _In_ ULONG cbV,
				   _Out_ PBYTE pbSeed, 
				   _In_ ULONG cbSeed);

NTSTATUS EccSecretDecrypt(_In_ BCRYPT_KEY_HANDLE hPrivKey, // EK key
						  _In_ PCWSTR ekNameAlg, // EK hash alg
						  _In_ PBYTE pb, 
						  _In_ ULONG cb,
						  _Out_ PBYTE pbSeed, 
						  _In_ ULONG cbSeed)
{
	if (cb < 3 * sizeof(WORD))
	{
		return STATUS_BAD_DATA;
	}

	union {
		PWORD pw;
		PBYTE pc;
	};

	pc = pb;
	ULONG cbEphPub = _byteswap_ushort(*pw++);
	if (cbEphPub + sizeof(WORD) != cb)
	{
		return STATUS_BAD_DATA;
	}

	switch (cb = _byteswap_ushort(*pw++))
	{
	case 32:
	case 48:
	case 66:
		if (cbEphPub == (cb + sizeof(WORD))* 2)
		{
			break;
		}
	default:
		return STATUS_BAD_DATA;
	}

	union {
		PVOID pvEkPub = 0;
		PBYTE pbEkPub;
		PBCRYPT_ECCKEY_BLOB pEkBlob;
	};

	ULONG cbEkPub = 0;
	NTSTATUS status;
	while (0 <= (status = BCryptExportKey(hPrivKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pbEkPub, cbEkPub, &cbEkPub, 0)))
	{
		if (pEkBlob)
		{
			PCWSTR pszAlgId = 0;
			union {
				PVOID pv;
				PBCRYPT_ECCKEY_BLOB pEphBlob;
				PBYTE pbEphPub;
			};

			pv = alloca(cbEphPub = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * cb);

			switch (pEphBlob->dwMagic = pEkBlob->dwMagic)
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
			}

			pEphBlob->cbKey = cb;
			pb = (PBYTE)memcpy(pEphBlob + 1, pc, cb);
			pc += cb;
			if (cb != _byteswap_ushort(*pw++))
			{
				return STATUS_BAD_DATA;
			}
			memcpy(pb + cb, pc, cb);

			BCRYPT_KEY_HANDLE hPubKey;
			if (0 <= (status = ImportPublicKey(&hPubKey, pszAlgId, pbEphPub, cbEphPub)))
			{
				BCRYPT_SECRET_HANDLE hSecret;
				if (0 <= (status = BCryptSecretAgreement(hPrivKey, hPubKey, &hSecret, 0)))
				{
					PBYTE pbSecret = 0;
					ULONG cbSecret = 0;

					while (0 <= (status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, 0, pbSecret, cbSecret, &cbSecret, 0)))
					{
						if (pbSecret)
						{
							reverse(pbSecret, cbSecret);
							DumpBytes(pbSecret, cbSecret, ">>KDF_RAW_SECRET");

							status = CryptKDFe(ekNameAlg, pbSecret, cbSecret, pEphBlob + 1, cb, 
								pEkBlob + 1, pEkBlob->cbKey, pbSeed, cbSeed);

							break;
						}

						pbSecret = (PBYTE)alloca(cbSecret);
					}

					BCryptDestroySecret(hSecret);
				}

				BCryptDestroyKey(hPubKey);
			}

			break;
		}

		pvEkPub = alloca(cbEkPub);
	}

	return status;
}

UINT ActivateCredential(_In_ BOOL bEcc,
						_In_ BCRYPT_KEY_HANDLE hEkKey,
						_In_ PCWSTR pszAlgId,
						_In_ ULONG SymKeyLen,
						_In_ PBYTE pbName, 
						_In_ ULONG cbName,
						_In_ PBYTE pbChallenge, 
						_In_ ULONG cbChallenge)
{
	DbgPrint("%hs(\"%ws\" %x)\r\n", __FUNCTION__, pszAlgId, cbChallenge);
	union {
		PBYTE pb;
		PUINT16 pw;
	};

	if (sizeof(UINT16) > cbChallenge) 
	{
		return __LINE__;
	}

	pb = pbChallenge, cbChallenge -= sizeof(UINT16);

	ULONG cb = _byteswap_ushort(*pw++);

	if (cb + sizeof(UINT16) > cbChallenge)
	{
		return __LINE__;
	}

	if (cb < sizeof(UINT16))
	{
		return __LINE__;
	}

	cbChallenge -= cb + sizeof(UINT16);

	ULONG cbMacSize = _byteswap_ushort(*pw++);

	if (cbMacSize > (cb -= sizeof(UINT16)))
	{
		return __LINE__;
	}

	switch (cbMacSize)
	{
	case 20:
	case 32:
	case 48:
	case 64:
		break;
	default:
		return __LINE__;
	}

	PBYTE outerHMAC = pb;

	union {
		PBYTE pbEnc;
		PUINT16 pw2;
	};

	if (sizeof(UINT16) > (cb -= cbMacSize))
	{
		return __LINE__;
	}

	pbEnc = pb += cbMacSize, pb += cb;

	if (_byteswap_ushort(*pw++) != cbChallenge)
	{
		return __LINE__;
	}

	if (bEcc)
	{
		--pw;
		PBYTE seed = (PBYTE)alloca(cbMacSize);
		EccSecretDecrypt(hEkKey, pszAlgId, pb, cbChallenge + sizeof(WORD), seed, cbMacSize);
		pb = seed, cbChallenge = cbMacSize;
	}
	else
	{
		BCRYPT_OAEP_PADDING_INFO pi = { pszAlgId, const_cast<UCHAR*>(IDENTITY), sizeof(IDENTITY) };

		if (0 > BCryptDecrypt(hEkKey, pb, cbChallenge, &pi, 0, 0, pb, cbChallenge, &cbChallenge, BCRYPT_PAD_OAEP))
		{
			return __LINE__;
		}
	}

	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 > BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SP800108_CTR_HMAC_ALGORITHM, NULL, 0))
	{
		return __LINE__;
	}

	BCRYPT_KEY_HANDLE hCtrKey;
	status = BCryptGenerateSymmetricKey(hAlgorithm, &hCtrKey, 0, 0, pb, cbChallenge, 0);

	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	if (0 > status)
	{
		return __LINE__;
	}

	BCryptBuffer KdfBufs[] = {
		{ sizeof(STORAGE) - 1, KDF_LABEL, const_cast<PBYTE>(STORAGE) },
		{ ((ULONG)wcslen(pszAlgId) + 1) * sizeof(WCHAR), KDF_HASH_ALGORITHM, const_cast<PWSTR>(pszAlgId) },
		{ cbName, KDF_CONTEXT, pbName }
	};

	BCryptBufferDesc KdfDesc = { BCRYPTBUFFER_VERSION, _countof(KdfBufs), KdfBufs };

	PUCHAR HMACkey = (PUCHAR)alloca(cbMacSize + SymKeyLen), symKey = HMACkey + cbMacSize;

	ULONG cbResult;
	if (0 <= (status = BCryptKeyDerivation(hCtrKey, &KdfDesc, symKey, SymKeyLen, &cbResult, 0)))
	{
		KdfBufs->cbBuffer = sizeof(INTEGRITY) - 1;
		KdfBufs->pvBuffer = const_cast<PBYTE>(INTEGRITY);
		KdfDesc.cBuffers--;
		status = BCryptKeyDerivation(hCtrKey, &KdfDesc, HMACkey, cbMacSize, &cbResult, 0);

		DumpBytes(HMACkey, cbMacSize, ">> HMACkey");
		DumpBytes(symKey, SymKeyLen, ">> symKey");
	}

	BCryptDestroyKey(hCtrKey);

	PBYTE pbHmac = (PBYTE)alloca(cbMacSize);

	if (0 > status || 
		0 > Hmac2(pszAlgId, HMACkey, cbMacSize, pbEnc, cb, pbName, cbName, pbHmac, cbMacSize) ||
		memcmp(pbHmac, outerHMAC, cbMacSize) ||
		0 > CFBXcrypt(symKey, SymKeyLen, pbEnc, cb, TRUE))
	{
		return __LINE__;
	}

	cbChallenge = _byteswap_ushort(*pw2++);
	DumpBytes(pbEnc, cbChallenge, "CV");

	return 0;
}

void AIK_PARAMS::Test(PCWSTR pszAlgId, ULONG dwLength)
{
	BCRYPT_KEY_HANDLE hKey;
	if (0 <= CreateKeyPairKey(&hKey, pszAlgId, dwLength))
	{
		UCHAR m_secret[] = "[(0123456789ABCDEF)]";
		m_pwszCNGNameHash = BCRYPT_SHA256_ALGORITHM;
		m_cbHash = 32;
		m_SymKeyLen = 16;

		TPMT_HA ha = { TPM_ALG_SHA256 };
		m_pbAikName = (PBYTE)&ha, m_cbAikName = sizeof(UINT16) + SHA256_DIGEST_SIZE;
		memset(ha.digest.sha256, 'h', sizeof(ha.digest.sha256));

		PCWSTR pszEncAlgId = wcscmp(BCRYPT_RSA_ALGORITHM, pszAlgId) ? pszAlgId : 0;

		ULONG cb;
		if (PBYTE buf = new UCHAR [cb = 0x400])
		{
			if (0 <= GenerateActivation20(hKey, pszEncAlgId, m_secret, sizeof(m_secret) - 1, buf, cb, &cb))
			{
				if (ULONG line = ActivateCredential(0 != pszEncAlgId, hKey, m_pwszCNGNameHash, 
					m_SymKeyLen, m_pbAikName, m_cbAikName, buf, cb))
				{
					__debugbreak();
					DbgPrint("\f%hs(%u): !!\r\n", __FILE__, line);
				}
			}
			else
			{
				__debugbreak();
			}
			delete [] buf;
		}
		BCryptDestroyKey(hKey);
	}
}

void TPM20Test()
{
	AIK_PARAMS params;
	params.Test(BCRYPT_RSA_ALGORITHM, 2048);
	params.Test(BCRYPT_ECDH_P256_ALGORITHM, 0);
	params.Test(BCRYPT_ECDH_P384_ALGORITHM, 0);
	params.Test(BCRYPT_ECDH_P521_ALGORITHM, 0);
}

#include <Cryptuiapi.h>

void ShowCert(HWND hwnd, PCCERT_CONTEXT pCertContext, PCWSTR szTitle)
{
	CRYPTUI_VIEWCERTIFICATE_STRUCTW cvi = { 
		sizeof(cvi), hwnd, CRYPTUI_DISABLE_ADDTOSTORE|CRYPTUI_DISABLE_EDITPROPERTIES, szTitle, pCertContext
	};

	BOOL b;
	CryptUIDlgViewCertificateW(&cvi, &b);
}

_NT_END