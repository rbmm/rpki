#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "TPM.h"
#include "util.h"

NTSTATUS CryptKDFe(_In_ PCWSTR ekNameAlg,
				   _In_ PBYTE pbSecret,
				   _In_ ULONG cbSecret,
				   _In_ PVOID pvU,
				   _In_ ULONG cbU,
				   _In_ PVOID pvV,
				   _In_ ULONG cbV,
				   _Out_ PBYTE pbSeed, 
				   _In_ ULONG cbSeed)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SP80056A_CONCAT_ALGORITHM, 0, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;
		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, pbSecret, cbSecret, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			BCryptBuffer KdfBufs[] = {
				{ ((ULONG)wcslen(ekNameAlg) + 1) * sizeof(WCHAR), KDF_HASH_ALGORITHM, const_cast<PWSTR>(ekNameAlg) },
				{ sizeof(IDENTITY), KDF_ALGORITHMID, const_cast<UCHAR*>(IDENTITY) },
				{ cbU, KDF_PARTYUINFO, pvU }, 
				{ cbV, KDF_PARTYVINFO, pvV },
			};

			DumpBytes((PBYTE)pvU, cbU, "U");
			DumpBytes((PBYTE)pvV, cbV, "V");

			BCryptBufferDesc KdfDesc = { BCRYPTBUFFER_VERSION, _countof(KdfBufs), KdfBufs };

			status = BCryptKeyDerivation(hKey, &KdfDesc, pbSeed, cbSeed, &cbSeed, 0);

			BCryptDestroyKey(hKey);

			DumpBytes(pbSeed, cbSeed, "seed");
		}
	}

	return status;
}

// hPubKey from ECC EK
NTSTATUS EccSecretEncrypt(_In_ BCRYPT_KEY_HANDLE hPubKey,
						  _In_ PCWSTR ekNameAlg,
						  _In_ PCWSTR pszAlgId,
						  _Out_ PBYTE pbBlob,
						  _In_ ULONG cbBlob,
						  _Out_ PULONG pcbBlob,
						  _Out_ PBYTE pbSeed, 
						  _In_ ULONG cbSeed)
{
	NTSTATUS status;

	union {
		PVOID pvEkPub = 0;
		PBYTE pbEkPub;
		PBCRYPT_ECCKEY_BLOB pEkBlob;
	};
	ULONG cbEkPub = 0;

	while (0 <= (status = BCryptExportKey(hPubKey, NULL, BCRYPT_ECCPUBLIC_BLOB, pbEkPub, cbEkPub, &cbEkPub, 0)))
	{
		if (pEkBlob)
		{
			BCRYPT_KEY_HANDLE hPrivKey;

			if (0 <= (status = CreateKeyPairKey(&hPrivKey, pszAlgId)))
			{
				union {
					PVOID pvEphPub = 0;
					PBCRYPT_ECCKEY_BLOB pEphBlob;
					PBYTE pbEphPub;
				};

				ULONG cbEphPub = 0;
				while (0 <= (status = BCryptExportKey(hPrivKey, 0, BCRYPT_ECCPUBLIC_BLOB, pbEphPub, cbEphPub, &cbEphPub, 0)))
				{
					if (pEphBlob)
					{
						ULONG cbKey = pEphBlob->cbKey;
						if (cbBlob < (*pcbBlob = 2 * cbKey + 3 * sizeof(WORD)))
						{
							status = STATUS_BUFFER_TOO_SMALL;
							break;
						}

						union {
							PWORD pw;
							PBYTE pb;
						};

						pb = pbBlob;
						*pw++ = _byteswap_ushort((USHORT)(2 * (sizeof(WORD) + cbKey)));
						*pw++ = _byteswap_ushort((USHORT)cbKey);
						memcpy(pb, ++pEphBlob, cbKey);
						pb += cbKey;
						*pw++ = _byteswap_ushort((USHORT)cbKey);
						memcpy(pb, pbEphPub + cbKey, cbKey);

						DumpBytes(pbBlob, *pcbBlob, "ECC BLOB");

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

									DumpBytes(pbSecret, cbSecret, "KDF_RAW_SECRET");

									status = CryptKDFe(ekNameAlg, pbSecret, cbSecret, pEphBlob, cbKey, 
										pEkBlob + 1, pEkBlob->cbKey, pbSeed, cbSeed);

									break;
								}

								pbSecret = (PBYTE)alloca(cbSecret);
							}

							BCryptDestroySecret(hSecret);
						}

						break;
					}

					pvEphPub = alloca(cbEphPub);
				}

				BCryptDestroyKey(hPrivKey);
			}

			break;
		}

		pvEkPub = alloca(cbEkPub);
	}
	
	return status;
}
;

/************************************************************************/
/* 

1. Marshal the CV(pbCV, cbCV) into a TPM2B_DIGEST
2. Using methods of the asymmetric "EK", create a seed value
3. Create a symmetric key for encryption: symKey := KDFa (ekNameAlg, seed, "STORAGE", Name, NULL , bits)
4. Create encIdentity by encrypting the CV: encIdentity := CFB(ekSymAlg) (symKey, 0, CV)
5. Compute the HMAC key: HMACkey := KDFa (ekNameAlg, seed, "INTEGRITY", NULL, NULL, bits)
6. Compute the HMAC over the encIdentity from step 4: outerHMAC := HMAC(ekNameAlg) (HMACkey, encIdentity || Name)

*/
/************************************************************************/

// seed have size hmacKeyLen = m_cbHash
NTSTATUS AIK_PARAMS::FormatChallenge(_In_ PBYTE pbChallenge, _In_ PBYTE seed, _In_ PBYTE pbSecret, _In_ ULONG cbSecret)
{
	// encIdentity := [UINT16 cbCV][UCHAR pbCV[cbCV]]
	// pbChallange := [UINT16 cbTotalSize][UINT16 hmacKeyLen][UCHAR outerHMAC[hmacKeyLen]]
	// [UCHAR encIdentity[]][UINT16 cbSeed][UCHAR seed[cbSeed]]

	ULONG SymKeyLen = m_SymKeyLen, hmacKeyLen = m_cbHash;
	PCWSTR pwszCNGNameHash = m_pwszCNGNameHash;

	PUCHAR symKey = (PUCHAR)alloca(hmacKeyLen + SymKeyLen), HMACkey = symKey + SymKeyLen;

	union {
		PBYTE pb;
		PUINT16 pw;
	};

	pb = pbChallenge;
	*pw++ = _byteswap_ushort(2 * sizeof(UINT16) + (USHORT)hmacKeyLen + (USHORT)cbSecret);
	*pw++ = _byteswap_ushort((USHORT)hmacKeyLen);
	PBYTE outerHMAC = pb;
	if (IsDebuggerPresent()) memset(pb, 'm', hmacKeyLen);
	pb += hmacKeyLen;
	ULONG cbEnc = sizeof(UINT16) + cbSecret;
	PBYTE pbEnc = pb;
	*pw++ =  _byteswap_ushort((USHORT)cbSecret);
	memcpy(pb, pbSecret, cbSecret);

	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SP800108_CTR_HMAC_ALGORITHM, NULL, 0)))
	{
		BCRYPT_KEY_HANDLE hKey;

		status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, 0, 0, seed, hmacKeyLen, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			BCryptBuffer KdfBufs[] = {
				{ sizeof(STORAGE) - 1, KDF_LABEL, const_cast<PBYTE>(STORAGE) },
				{ ((ULONG)wcslen(pwszCNGNameHash) + 1) * sizeof(WCHAR), KDF_HASH_ALGORITHM, const_cast<PWSTR>(pwszCNGNameHash) },
				{ m_cbAikName, KDF_CONTEXT, m_pbAikName }
			};

			BCryptBufferDesc KdfDesc = { BCRYPTBUFFER_VERSION, _countof(KdfBufs), KdfBufs };

			ULONG cbResult;
			if (0 <= (status = BCryptKeyDerivation(hKey, &KdfDesc, symKey, SymKeyLen, &cbResult, 0)))
			{
				DumpBytes(symKey, SymKeyLen, "symKey");

				KdfBufs->cbBuffer = sizeof(INTEGRITY) - 1;
				KdfBufs->pvBuffer = const_cast<PBYTE>(INTEGRITY);
				KdfDesc.cBuffers--;
				status = BCryptKeyDerivation(hKey, &KdfDesc, HMACkey, hmacKeyLen, &cbResult, 0);
			}

			BCryptDestroyKey(hKey);

			if (0 <= status)
			{
				DumpBytes(HMACkey, hmacKeyLen, "HMACkey");

				if (0 <= (status = CFBXcrypt(symKey, SymKeyLen, pbEnc, cbEnc, FALSE)))
				{
					DumpBytes(pbEnc, cbEnc, "encrypted");

					if (0 <= (status = Hmac2(pwszCNGNameHash, HMACkey, hmacKeyLen, 
						pbEnc, cbEnc, m_pbAikName, m_cbAikName, outerHMAC, hmacKeyLen)))
					{
						DumpBytes(outerHMAC, hmacKeyLen, "outerHMAC");
					}
				}
			}
		}
	}

	return status;
}

NTSTATUS AIK_PARAMS::GenerateActivationEcc(_In_ BCRYPT_KEY_HANDLE hKey,
										   _In_ PCWSTR pszEncAlgId,
										   _In_ PBYTE pbSecret, 
										   _In_ ULONG cbSecret, 
										   _Inout_ PBYTE pbBuffer,
										   _In_ ULONG cbBuffer,
										   _Out_ ULONG* pcbResult)
{
	ULONG hmacKeyLen = m_cbHash;

	// The output secret value has the size of the digest produced by the nameAlg.
	PUCHAR seed = (PUCHAR)alloca(hmacKeyLen);

	ULONG cbBlob, cbNeed = NeedBytes(hmacKeyLen, cbSecret, 0);

	if (cbBuffer < cbNeed)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	NTSTATUS status;
	if (0 <= (status = EccSecretEncrypt(hKey, m_pwszCNGNameHash, pszEncAlgId,
		pbBuffer + cbNeed, cbBuffer - cbNeed, &cbBlob, seed, hmacKeyLen)))
	{
		if (0 <= (status = FormatChallenge(pbBuffer, seed, pbSecret, cbSecret)))
		{
			*pcbResult = cbNeed + cbBlob;
		}
	}

	return status;
}

HRESULT AIK_PARAMS::GenerateActivationRsa(_In_ BCRYPT_KEY_HANDLE hKey,
										  _Reserved_ PCWSTR ,
										  _In_ PBYTE pbSecret, 
										  _In_ ULONG cbSecret, 
										  _Inout_ PBYTE pbBuffer,
										  _In_ ULONG cbBuffer,
										  _Out_ ULONG* pcbResult)
{
	NTSTATUS status;

	ULONG hmacKeyLen = m_cbHash;

	// The output secret value has the size of the digest produced by the nameAlg.
	PUCHAR seed = (PUCHAR)alloca(hmacKeyLen);

	BCRYPT_OAEP_PADDING_INFO pi = { m_pwszCNGNameHash, const_cast<UCHAR*>(IDENTITY), sizeof(IDENTITY) };

	union {
		PBYTE pbSeed = 0;
		PUINT16 pw;
	};

	ULONG cbNeed = NeedBytes(hmacKeyLen, cbSecret, sizeof(WORD) );

	if (cbBuffer < cbNeed)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	if (0 > (status = BCryptGenRandom(0, seed, hmacKeyLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		return status;
	}

	DumpBytes(seed, hmacKeyLen, "seed");

	if (IsDebuggerPresent()) memset(seed, 's', hmacKeyLen);

	ULONG cbEncrypted;

	if (0 <= (status = BCryptEncrypt(hKey, seed, hmacKeyLen, &pi, 0, 0, 
		pbSeed = pbBuffer + cbNeed, cbBuffer - cbNeed, &cbEncrypted, BCRYPT_PAD_OAEP)))
	{
		*--pw = _byteswap_ushort((USHORT)cbEncrypted);
		*pcbResult = cbNeed + cbEncrypted;

		return FormatChallenge(pbBuffer, seed, pbSecret, cbSecret);
	}

	return status;
}

HRESULT AIK_PARAMS::GenerateActivation20(_In_ BCRYPT_KEY_HANDLE hKey, 
										 _In_ PCWSTR pszEncAlgId,
										 _In_ PBYTE pbSecret, 
										 _In_ ULONG cbSecret, 
										 _Inout_ PBYTE pbBuffer,
										 _In_ ULONG cbBuffer,
										 _Out_ ULONG* pcbResult)
{
	// https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/Object/MakeCredential.c#L40
	// The credential information may not be larger than the digest size used for
	// the Name of the key associated with handle.

	//UCHAR secret[SHA1_DIGEST_SIZE];
	DumpBytes(pbSecret, cbSecret, "CV");
	DumpBytes(m_pbAikName, m_cbAikName, "name");

	return (this->*(pszEncAlgId ? &AIK_PARAMS::GenerateActivationEcc : &AIK_PARAMS::GenerateActivationRsa))
		(hKey, pszEncAlgId, pbSecret, cbSecret, pbBuffer, cbBuffer, pcbResult);
}

_NT_END