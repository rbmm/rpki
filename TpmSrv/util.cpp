#include "stdafx.h"

_NT_BEGIN
#include "../log/log.h"
#include "util.h"

void DumpBytes(const UCHAR* pb, ULONG cb, PCSTR msg)
{
	PSTR psz = 0;
	ULONG cch = 0;
	while (CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXASCIIADDR, psz, &cch))
	{
		if (psz)
		{
			DbgPrint("%hs\r\n%.*hs\r\n", msg, cch, psz);
			break;
		}

		if (!(psz = new CHAR[cch]))
		{
			break;
		}
	}

	if (psz)
	{
		delete[] psz;
	}
}

NTSTATUS Hmac2(_In_ PCWSTR pszAlgId,
	_In_ PUCHAR pbCV,
	_In_ ULONG cbCV,
	_In_ PUCHAR pbInput1,
	_In_ ULONG cbInput1,
	_In_ PUCHAR pbInput2,
	_In_ ULONG cbInput2,
	_Out_ PBYTE pbHash,
	_In_ ULONG cbHash)
{
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
	{
		BCRYPT_HASH_HANDLE hHash;

		status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, pbCV, cbCV, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			0 <= (status = BCryptHashData(hHash, pbInput1, cbInput1, 0)) &&
				0 <= (status = BCryptHashData(hHash, pbInput2, cbInput2, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbHash, cbHash, 0));

			BCryptDestroyHash(hHash);
		}
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey,
	_In_ BCRYPT_ALG_HANDLE hAlgorithm,
	_In_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_In_ PCWSTR ChainingMode,
	_In_opt_ ULONG MessageBlockLength/* = 0*/)
{
	NTSTATUS status;
	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, pbSecret, cbSecret, 0)))
	{
		if (0 <= (status = BCryptSetProperty(hKey, BCRYPT_CHAINING_MODE,
			(PBYTE)ChainingMode, (1 + (ULONG)wcslen(ChainingMode)) * sizeof(WCHAR), 0)) &&
			(!MessageBlockLength || 0 <= (status = BCryptSetProperty(hKey,
				BCRYPT_MESSAGE_BLOCK_LENGTH, (PBYTE)&MessageBlockLength, sizeof(MessageBlockLength), 0))))
		{
			*phKey = hKey;
			return STATUS_SUCCESS;
		}

		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phKey,
	_In_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_In_ PCWSTR ChainingMode,
	_In_opt_ ULONG MessageBlockLength/* = 0*/)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, 0, 0)))
	{
		status = GenAesKey(phKey, hAlgorithm, pbSecret, cbSecret, ChainingMode, MessageBlockLength);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS CFBXcrypt(PUCHAR pbSymKey, ULONG cbSymKey, PBYTE pb, ULONG cb, PBYTE pbOut, BOOL bDecrypt)
{
	NTSTATUS status;

	BCRYPT_KEY_HANDLE hKey;

	if (0 <= (status = GenAesKey(&hKey, pbSymKey, cbSymKey, BCRYPT_CHAIN_MODE_CFB, 16)))
	{
		UCHAR b[16] = {};
		ULONG ex = cb & 15, s;
		cb &= ~15;
		if (ex)
		{
			memcpy(b, pb + cb, ex);
		}

		auto BCryptXcrypt = bDecrypt ? BCryptDecrypt : BCryptEncrypt;

		0 <= (status = cb ? BCryptXcrypt(hKey, pb, cb, 0, 0, 0, pbOut, cb, &cb, 0) : 0) &&
			0 <= (status = ex ? BCryptXcrypt(hKey, b, sizeof(b), 0, 0, 0, b, sizeof(b), &s, 0) : 0);

		if (ex)
		{
			memcpy(pbOut + cb, b, ex);
		}

		BCryptDestroyKey(hKey);
	}

	return status;
}

NTSTATUS ImportPublicKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszAlgId, _In_ PBYTE pbKey, _In_ ULONG cbKey)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PUBLIC_KEY_BLOB, phKey, pbKey, cbKey, 0);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS GenAesKey(_Out_ BCRYPT_KEY_HANDLE* phAesKey, _In_ BCRYPT_KEY_HANDLE hPrivKey, _In_ BCRYPT_KEY_HANDLE hPubKey)
{
	HRESULT hr;

	BCRYPT_SECRET_HANDLE hSecret = 0;
	if (0 <= (hr = BCryptSecretAgreement(hPrivKey, hPubKey, &hSecret, 0)))
	{
		BYTE pbSecret[66], pbHash[32];
		ULONG cbSecret, cbHash = sizeof(pbHash);

		hr = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, 0, pbSecret, sizeof(pbSecret), &cbSecret, 0);

		BCryptDestroySecret(hSecret);

		if (0 <= hr && HR(hr, CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbSecret, cbSecret, pbHash, &cbHash)))
		{
			hr = GenAesKey(phAesKey, pbHash, cbHash, BCRYPT_CHAIN_MODE_GCM);
		}
	}

	return hr;
}

NTSTATUS GetKeyBlockLength(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ PULONG BlockLength)
{
	ULONG cb;
	return BCryptGetProperty(hKey, BCRYPT_BLOCK_LENGTH, (PBYTE)BlockLength, sizeof(ULONG), &cb, 0);
}

NTSTATUS GetAlgorithmName(_In_ BCRYPT_KEY_HANDLE hKey, _Out_ PWSTR pszAlgId, _In_ ULONG cb)
{
	return BCryptGetProperty(hKey, BCRYPT_ALGORITHM_NAME, (PBYTE)pszAlgId, cb, &cb, 0);
}

NTSTATUS CreateKeyPairKey(_In_ BCRYPT_KEY_HANDLE* phKey, PCWSTR pszAlgId, ULONG dwLength/* = 0*/)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;
		status = BCryptGenerateKeyPair(hAlgorithm, &hKey, dwLength, 0);
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

HRESULT GetPublicKeyFromCert(_Out_ BCRYPT_KEY_HANDLE* phKey,
	_In_ const BYTE* pbCertEncoded,
	_In_ DWORD cbCertEncoded,
	_In_ ULONG dwFlags)
{
	HRESULT hr;
	if (PCCERT_CONTEXT pCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded)))
	{
		HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING,
			&pCertContext->pCertInfo->SubjectPublicKeyInfo, dwFlags, 0, phKey));

		CertFreeCertificateContext(pCertContext);
	}

	return hr;
}

#define BDH(n) BCRYPT_ECDH_P ## n ## _ALGORITHM
#define BDSA(n) BCRYPT_ECDSA_P ## n ## _ALGORITHM

#define FAI(pcszAlgId, bSign, n) if (!wcscmp(pcszAlgId, BDH(n))) return bSign ? BDSA(n) : 0;\
	if (!wcscmp(pcszAlgId, BDSA(n))) return bSign ? 0 : BDH(n);

PCWSTR NewAlgName(_In_ PCWSTR pcszAlgId, _In_ BOOL bSign)
{
	FAI(pcszAlgId, bSign, 256);
	FAI(pcszAlgId, bSign, 384);
	FAI(pcszAlgId, bSign, 521);

	return 0;
}

PCWSTR FixAlgName(_In_ PCWSTR pcszAlgId, _Inout_ PVOID pvBlob, _In_ BOOL bSign)
{
	if (PCWSTR pcszNewAlgId = NewAlgName(pcszAlgId, bSign))
	{
		(reinterpret_cast<BCRYPT_KEY_BLOB*>(pvBlob)->Magic &= 0xFF00FFFF) |= bSign ? ('S' << 16) : ('K' << 16);
		return pcszNewAlgId;
	}

	return pcszAlgId;
}

HRESULT NKeyToBKey(_In_ BOOL bSign, _In_ NCRYPT_KEY_HANDLE hKey, _Out_ BCRYPT_KEY_HANDLE* phKey)
{
	PBYTE pb = 0;
	ULONG cb = 0, s;
	NTSTATUS status;
	while (NOERROR == (status = NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			WCHAR szAlgId[16];
			if (NOERROR == (status = NCryptGetProperty(hKey, NCRYPT_ALGORITHM_PROPERTY, (PBYTE)szAlgId, sizeof(szAlgId), &s, 0)))
			{
				BCRYPT_ALG_HANDLE hAlgorithm;
				if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, FixAlgName(szAlgId, pb, bSign), 0, 0)))
				{
					status = BCryptImportKeyPair(hAlgorithm, 0, BCRYPT_PRIVATE_KEY_BLOB, phKey, pb, cb, 0);
					BCryptCloseAlgorithmProvider(hAlgorithm, 0);
				}
			}

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

PBYTE rmemcpy(PBYTE pb, PBYTE qb, ULONG cb)
{
	if (cb)
	{
		qb += cb;
		do
		{
			*pb++ = *--qb;
		} while (--cb);
	}

	return pb;
}

BOOL IsSupportedAlg(_In_ PCRYPT_ALGORITHM_IDENTIFIER Algorithm, _Out_ PCWSTR* ppszEccAlgId)
{
	*ppszEccAlgId = 0;

	if (!strcmp(szOID_RSA_RSA, Algorithm->pszObjId))
	{
		return TRUE;
	}

	if (!strcmp(szOID_ECC_PUBLIC_KEY, Algorithm->pszObjId))
	{
		union {
			UCHAR buf[0x40];
			PCSTR AlgorithmParameter;
		};

		ULONG cb = sizeof(buf);

		if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
			Algorithm->Parameters.pbData, Algorithm->Parameters.cbData, 0, 0, buf, &cb))
		{
			if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P256))
			{
				*ppszEccAlgId = BCRYPT_ECDH_P256_ALGORITHM;
				return TRUE;
			}

			if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P384))
			{
				*ppszEccAlgId = BCRYPT_ECDH_P384_ALGORITHM;
				return TRUE;
			}

			if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P521))
			{
				*ppszEccAlgId = BCRYPT_ECDH_P521_ALGORITHM;
				return TRUE;
			}
		}
	}

	return FALSE;
}

NTSTATUS TransformEccKey(_Out_ BCRYPT_KEY_HANDLE* phKey,
	_In_ BCRYPT_KEY_HANDLE hKey,
	_In_ PCWSTR pszAlgId,
	_In_ PCWSTR pszBlobType)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	NTSTATUS status;
	while (0 <= (status = BCryptExportKey(hKey, 0, pszBlobType, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			BCRYPT_ALG_HANDLE hAlgorithm;

			if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
			{
				reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic ^= ('S' ^ 'K') << 16;
				status = BCryptImportKeyPair(hAlgorithm, 0, pszBlobType, phKey, pb, cb, 0);
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			}

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

NTSTATUS BKeyToNkey(_In_ BOOL bSign,
	_In_ BCRYPT_KEY_HANDLE hKey,
	_In_ PCWSTR pszKeyName,
	_In_opt_ ULONG dwFlags/* = 0*/,
	_In_opt_ ULONG ExportFlags/* = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG*/)
{
	PBYTE pb = 0;
	ULONG cb = 0;
	NTSTATUS status;
	while (0 <= (status = BCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			if ('CE' == (WORD)reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic)
			{
				(reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic &= 0xFF00FFFF) |= bSign ? ('S' << 16) : ('K' << 16);
			}

			NCRYPT_PROV_HANDLE hProvider;
			if (!NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0))
			{
				NCryptBuffer buf = {
					(1 + (ULONG)wcslen(pszKeyName)) * sizeof(WCHAR), NCRYPTBUFFER_PKCS_KEY_NAME, const_cast<PWSTR>(pszKeyName)
				};
				NCryptBufferDesc ParameterList = { NCRYPTBUFFER_VERSION, 1, &buf };
				NCRYPT_KEY_HANDLE hNKey;
				if (NOERROR == (status = NCryptImportKey(hProvider, 0, BCRYPT_PRIVATE_KEY_BLOB, &ParameterList,
					&hNKey, pb, cb, ExportFlags ? NCRYPT_DO_NOT_FINALIZE_FLAG | dwFlags : dwFlags & ~NCRYPT_DO_NOT_FINALIZE_FLAG)))
				{
					if (ExportFlags)
					{
						if (NOERROR == (status = NCryptSetProperty(hNKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&ExportFlags, sizeof(ExportFlags), 0)))
						{
							status = NCryptFinalizeKey(hNKey, 0);
						}
					}
					NCryptFreeObject(hNKey);
				}
				NCryptFreeObject(hProvider);
			}
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

HRESULT DeleteNKey(_In_ NCRYPT_PROV_HANDLE hProvider, _In_ PCWSTR lpKeyName)
{
	NTSTATUS status;
	NCRYPT_KEY_HANDLE hKey;

	if (NOERROR == (status = NCryptOpenKey(hProvider, &hKey, lpKeyName, 0, 0)))
	{
		if (status = NCryptDeleteKey(hKey, 0))
		{
			NCryptFreeObject(hKey);
		}
	}

	return status;
}

HRESULT DeleteNKey(_In_ PCWSTR pszProviderName, _In_ PCWSTR lpKeyName)
{
	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status;

	if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, pszProviderName, 0)))
	{
		NCRYPT_KEY_HANDLE hKey;
		status = NCryptOpenKey(hProvider, &hKey, lpKeyName, 0, 0);

		NCryptFreeObject(hProvider);

		if (NOERROR == status)
		{
			if (status = NCryptDeleteKey(hKey, 0))
			{
				NCryptFreeObject(hKey);
			}
		}
	}

	return status;
}

_NT_END