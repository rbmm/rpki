#include "stdafx.h"

_NT_BEGIN

#include "kas.h"
#include "pkcs#10.h"
#include "aik.h"
#include "util.h"

HRESULT MD5(_In_ const void* pb, _In_ ULONG cb, _Out_ PBYTE pbHash, _In_ ULONG cbHash)
{
	return GetLastHresult(CryptHashCertificate2(BCRYPT_MD5_ALGORITHM, 0, 0, (PBYTE)pb, cb, pbHash, &cbHash));
}

HRESULT GetMachineUID_TPM(_Out_ PBYTE pbId, _In_ ULONG cbId, _In_ NCRYPT_PROV_HANDLE hProvider)
{
	NTSTATUS status;

	PBYTE pb = 0;
	ULONG cb = 0;

	while (NOERROR == (status = NCryptGetProperty(hProvider, NCRYPT_PCP_EKPUB_PROPERTY, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			status = MD5(pb, cb, pbId, cbId);
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return status;
}

HRESULT GetMachineUID_TPM(_Out_ PBYTE pbId, _In_ ULONG cbId)
{
	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status;

	if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0)))
	{
		status = GetMachineUID_TPM(pbId, cbId, hProvider);

		NCryptFreeObject(hProvider);
	}

	return status;
}

HRESULT GetMachineUID_LSA(_Out_ PBYTE pbId, _In_ ULONG cbId)
{
	NTSTATUS status;

	LSA_HANDLE hPolicy;
	LSA_OBJECT_ATTRIBUTES oa = { sizeof(oa) };
	if (0 <= (status = LsaOpenPolicy(0, &oa, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy)))
	{
		PPOLICY_ACCOUNT_DOMAIN_INFO padi;
		status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (void**)&padi);
		LsaClose(hPolicy);
		if (0 <= status)
		{
			status = MD5(padi->DomainSid, RtlLengthSid(padi->DomainSid), pbId, cbId);
			LsaFreeMemory(padi);
		}
	}

	return status;
}

HRESULT WINAPI GetMachineUID(_Out_ PBYTE pbId, _In_ ULONG cbId, _Out_ PBOOLEAN pbTPM)
{
	NTSTATUS status = GetMachineUID_TPM(pbId, cbId);
	return status ? *pbTPM = FALSE, GetMachineUID_LSA(pbId, cbId) : *pbTPM = TRUE, NOERROR;
}

HRESULT GetEKCert(_Out_ PCCERT_CONTEXT* ppCertContext, 
				  _In_ NCRYPT_PROV_HANDLE hProvider, 
				  _In_ PCWSTR pszProperty1,
				  _In_ PCWSTR pszProperty2)
{
	HCERTSTORE hStore;

	ULONG cb;
	HRESULT hr; 
	if (NOERROR == (hr = NCryptGetProperty(hProvider, pszProperty1, (PBYTE)&hStore, sizeof(hStore), &cb, 0)) ||
		NOERROR == (hr = NCryptGetProperty(hProvider, pszProperty2, (PBYTE)&hStore, sizeof(hStore), &cb, 0)))
	{
		if (PCCERT_CONTEXT pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, 0)))
		{
			*ppCertContext = pCertContext;
		}
		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT CreateHelloProtectedKey(_In_ NCRYPT_PROV_HANDLE hProvider, 
								_In_ PCWSTR pszAlgId, 
								_In_ PCWSTR lpKeyName, 
								_Out_ NCRYPT_KEY_HANDLE* phKey)
{
	NTSTATUS status; 

	NCRYPT_KEY_HANDLE hKey;
	if (NTE_BAD_KEYSET == (status = NCryptOpenKey(hProvider, &hKey, lpKeyName, 0, 0)))
	{
		status = NCryptCreatePersistedKey(hProvider, &hKey, pszAlgId, lpKeyName, 0, 0);
		lpKeyName = 0;
	}

	if (NOERROR == status)
	{
		if (lpKeyName)
		{
			*phKey = hKey;
			return NOERROR;
		}

		NCRYPT_UI_POLICY uiPolicy = { 
			1, NCRYPT_UI_PROTECT_KEY_FLAG|NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG,
			L"SSO Client Registration", L"SSO Authorization Key",
			L"Look into the camera to generate the key."
		};

		if (NOERROR == (status = NCryptSetProperty(hKey, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&uiPolicy, sizeof(uiPolicy), 0)))
		{
			if (NOERROR == (status = NCryptFinalizeKey(hKey, 0)))
			{
				*phKey = hKey;
				return NOERROR;
			}
		}

		NCryptFreeObject(hKey);
	}
	return status;
}

HRESULT
WINAPI
StartAIKHandshake(
	_In_ BOOL bAikRsa,
	_In_ BOOL bKeyRsa,
	_In_ PCWSTR pszKeyName,
	_In_reads_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
	_In_reads_z_(25) PCWSTR MachineName,
	_Out_ PBOOLEAN pbTpmPresent,
	_Out_ PDATA_BLOB request,
	_Out_ PBYTE* ppbKey,
	_Out_ ULONG* pcbKey)
{
	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status;
	*pbTpmPresent = FALSE;

	if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0))) 
	{
		PCWSTR pszProperty1, pszProperty2;
		PCWSTR pszAIKAlgId;
		PCWSTR pszKeyAlgId;
		PCSTR pszPublicKeyObjId;

		if (bAikRsa)
		{
			pszAIKAlgId = BCRYPT_RSA_ALGORITHM;
			pszProperty1 = NCRYPT_PCP_RSA_EKNVCERT_PROPERTY;
			pszProperty2 = NCRYPT_PCP_RSA_EKCERT_PROPERTY;
		}
		else
		{
			pszAIKAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
			pszProperty1 = NCRYPT_PCP_ECC_EKNVCERT_PROPERTY;
			pszProperty2 = NCRYPT_PCP_ECC_EKCERT_PROPERTY;
		}

		if (bKeyRsa)
		{
			pszKeyAlgId = BCRYPT_RSA_ALGORITHM;
			pszPublicKeyObjId = szOID_RSA_RSA;
		}
		else
		{
			pszKeyAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
			pszPublicKeyObjId = szOID_ECC_PUBLIC_KEY;
		}

		// get EKCert
		PCCERT_CONTEXT pCertContext;

		if (NOERROR == (status = GetEKCert(&pCertContext, hProvider, pszProperty1, pszProperty2)))
		{
			*pbTpmPresent = TRUE;

			NCRYPT_KEY_HANDLE hAIK, hKey;
			// create hAIK key
			if (NOERROR == (status = NCryptCreatePersistedKey(hProvider, &hAIK, pszAIKAlgId, 0, 0, 0)))
			{
				ULONG dwFlags = NCRYPT_PCP_IDENTITY_KEY;

				// set pbNonce on hAIK and mark it as Certify(Identity) key
				if (NOERROR == (status = NCryptSetProperty(hAIK, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, (PBYTE)&dwFlags, sizeof(dwFlags), 0)) &&
					NOERROR == (status = NCryptSetProperty(hAIK, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, pbNonce, SHA1_DIGEST_SIZE, 0)) &&
					NOERROR == (status = NCryptFinalizeKey(hAIK, 0)))
				{
					PBYTE pbKey = 0;
					ULONG cbKey = 0;

					// export AIK key
					while (NOERROR == (status = NCryptExportKey(hAIK, 0, BCRYPT_OPAQUE_KEY_BLOB, 0, pbKey, cbKey, &cbKey, 0)))
					{
						if (pbKey)
						{
							PBYTE pbIdBinding = 0;
							ULONG cbIdBinding = 0;
							while (NOERROR == (status = NCryptGetProperty(hAIK, NCRYPT_PCP_TPM12_IDBINDING_PROPERTY, pbIdBinding, cbIdBinding, &cbIdBinding, 0)))
							{
								if (pbIdBinding)
								{
									// create or open user key
									if (NOERROR == (status = CreateHelloProtectedKey(hProvider, pszKeyAlgId, pszKeyName, &hKey)))
									{
										NCryptBuffer paramBuffers = { SHA1_DIGEST_SIZE, NCRYPTBUFFER_ATTESTATION_STATEMENT_NONCE, pbNonce };
										NCryptBufferDesc ParameterList = { NCRYPTBUFFER_VERSION, 1, &paramBuffers };

										ULONG cbKAS = 0;
										union {
											PVOID pv = 0;
											PBYTE pbKAS;
											PCP_KEY_ATTESTATION_STATEMENT* pKAS;
										};
										// Executing Certify
										while (NOERROR == (status = NCryptCreateClaim(hKey, hAIK,
											NCRYPT_CLAIM_SUBJECT_ONLY, &ParameterList, pbKAS, cbKAS, &cbKAS, 0)))
										{
											if (pKAS)
											{
												// insert IdBinding to PCP_KEY_ATTESTATION_STATEMENT
												PBYTE pb = pbKAS + pKAS->HeaderSize;
												memmove(pb + cbIdBinding, pb + pKAS->cbIdBinding, pKAS->cbKeyAttestation);
												memcpy(pb, pbIdBinding, cbIdBinding);
												pKAS->cbIdBinding = cbIdBinding;
												pKAS->cbAIKOpaque = 0;

												// build PKCS#10

												if (NOERROR == (status = BuildPkcs10(request,
													N_CRYPT_KEY_HANDLE(hKey, pszPublicKeyObjId),
													MS_PLATFORM_KEY_STORAGE_PROVIDER, MachineName, pCertContext,
													pbKAS, pKAS->HeaderSize + cbIdBinding + pKAS->cbKeyAttestation)))
												{
													*ppbKey = pbKey, pbKey = 0, * pcbKey = cbKey;
												}

												break;
											}

											pv = alloca(cbKAS + cbIdBinding);
										}

										NCryptFreeObject(hKey);
									}

									break;
								}

								pbIdBinding = (PBYTE)alloca(cbIdBinding);
							}

							break;
						}

						if (!(pbKey = (PBYTE)LocalAlloc(LMEM_FIXED, cbKey)))
						{
							status = NTE_NO_MEMORY;
							break;
						}
					}

					LocalFree(pbKey);
				}

				NCryptFreeObject(hAIK);
			}

			CertFreeCertificateContext(pCertContext);
		}

		NCryptFreeObject(hProvider);
	}

	return status;
}

HRESULT
WINAPI
StartHandshake(_In_ BOOL bKeyRsa,
	_In_reads_z_(25) PCWSTR MachineName,
	_Out_ PDATA_BLOB request,
	_Out_ BCRYPT_KEY_HANDLE* phKey)
{
	HRESULT hr;
	BCRYPT_KEY_HANDLE hKey;

	ULONG dwLength;
	PCWSTR pszKeyAlgId;
	PCSTR pszPublicKeyObjId;

	if (bKeyRsa)
	{
		dwLength = 2048;
		pszKeyAlgId = BCRYPT_RSA_ALGORITHM;
		pszPublicKeyObjId = szOID_RSA_RSA;
	}
	else
	{
		dwLength = 0;
		pszKeyAlgId = BCRYPT_ECDSA_P256_ALGORITHM;
		pszPublicKeyObjId = szOID_ECC_PUBLIC_KEY;
	}

	if (0 <= (hr = CreateKeyPairKey(&hKey, pszKeyAlgId, dwLength)))
	{
		if (NOERROR == (hr = BuildPkcs10(request, B_CRYPT_KEY_HANDLE(hKey, pszPublicKeyObjId),
			MS_KEY_STORAGE_PROVIDER, MachineName)))
		{
			*phKey = hKey;
			return NOERROR;
		}
	}

	return hr;
}

HRESULT AddEncodedCertificateToStore(
	_In_ const BYTE* pbCertEncoded,
	_In_ DWORD cbCertEncoded,
	_In_ PCWSTR pwszKeyName,
	_In_opt_ BCRYPT_KEY_HANDLE hKey/* = 0*/)
{
	HRESULT hr;
	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"MY")))
	{
		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		// CertSetCertificateContextProperty have no effect on 
		// PCCERT_CONTEXT returned by CertAddEncodedCertificateToStore
		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		if (PCCERT_CONTEXT pCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded)))
		{
			CRYPT_KEY_PROV_INFO ckpi = {
				const_cast<PWSTR>(pwszKeyName),
				const_cast<PWSTR>(hKey ? MS_KEY_STORAGE_PROVIDER : MS_PLATFORM_KEY_STORAGE_PROVIDER)
			};

			if (HR(hr, CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &ckpi)))
			{
				if (HR(hr, CertAddCertificateContextToStore(hCertStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0)))
				{
					if (hKey)
					{
						hr = BKeyToNkey(TRUE, hKey, pwszKeyName, NCRYPT_OVERWRITE_KEY_FLAG, 0);
					}
				}
			}
			CertFreeCertificateContext(pCertContext);
		}

		CertCloseStore(hCertStore, 0);
	}
	
	return hr;
}

HRESULT DecryptSecret(_In_ PBYTE pbKey, 
					  _In_ ULONG cbKey,
					  _Inout_ PBYTE pbSecret,
					  _In_ ULONG cbSecret,
					  _Out_ PULONG pcbSecret)
{
	HRESULT hr;
	STATIC_OBJECT_ATTRIBUTES(oa, "\\Device\\NamedPipe\\D1A2A28D-2CA8-40EA-B815-7743319ED695");
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	if (0 <= (hr = NtOpenFile(&hFile, 
		SYNCHRONIZE|FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|FILE_READ_DATA, 
		&oa, &iosb, 0, FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		FILE_PIPE_INFORMATION fpi = { FILE_PIPE_MESSAGE_MODE, FILE_PIPE_QUEUE_OPERATION };
		if (0 <= (hr = NtSetInformationFile(hFile, &iosb, &fpi, sizeof(fpi), FilePipeInformation)))
		{
			struct TACTIVATION 
			{
				union {
					HRESULT hr;
					ULONG cbKey;
				};
				ULONG cbSecret;
				UCHAR buf[];//key+secret

				void* operator new(size_t s, ULONG cb)
				{
					return LocalAlloc(LMEM_FIXED, s + cb);
				}

				void operator delete(PVOID pv)
				{
					LocalFree(pv);
				}
			};

			if (TACTIVATION* pa = new(cbSecret + cbKey) TACTIVATION)
			{
				pa->cbKey = cbKey, pa->cbSecret = cbSecret;
				memcpy(cbKey + (PBYTE)memcpy(pa->buf, pbKey, cbKey), pbSecret, cbSecret);
				if (0 <= (hr = NtFsControlFile(hFile, 0, 0, 0, &iosb, FSCTL_PIPE_TRANSCEIVE,  
					pa, offsetof(TACTIVATION, buf) + cbSecret + cbKey, 
					pa, offsetof(TACTIVATION, buf) + cbSecret)))
				{
					if (0 <= (hr = pa->hr))
					{
						if (pa->cbSecret < cbSecret)
						{
							memcpy(pbSecret, pa->buf, cbSecret = pa->cbSecret);
							*pcbSecret = cbSecret;
						}
						else
						{
							hr = STATUS_INFO_LENGTH_MISMATCH;
						}
					}
				}

				delete pa;
			}
		}
		NtClose(hFile);
	}

	return hr;
}

HRESULT 
WINAPI 
Activate(
	_In_ PCWSTR pszKeyName,
	_In_ PBYTE pbKey,
	_In_ ULONG cbKey,
	_In_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_In_ PBYTE pbCertEncoded,
	_In_ ULONG cbCertEncoded,
	_Out_ PBYTE* ppb,
	_Out_ ULONG* pcb)
{
	HRESULT hr;
	if (NOERROR == (hr = DecryptSecret(pbKey, cbKey, pbSecret, cbSecret, &cbSecret)))
	{
		*ppb = pbSecret, *pcb = cbSecret;
		UCHAR aes[32];
		ULONG cb = sizeof(aes);

		if (HR(hr, CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbSecret, cbSecret, aes, &cb)) &&
			0 <= (hr = CFBXcrypt(aes, cb, pbCertEncoded, cbCertEncoded, pbCertEncoded, TRUE)))
		{
			hr = AddEncodedCertificateToStore(pbCertEncoded, cbCertEncoded, pszKeyName);
		}
	}

	return hr;
}

_NT_END