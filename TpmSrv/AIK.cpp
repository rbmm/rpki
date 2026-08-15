#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "kas.h"
#include "pkcs#10.h"
#include "aik.h"

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

HRESULT GetMachineUID(_Out_ PBYTE pbId, _In_ ULONG cbId, _In_opt_ NCRYPT_PROV_HANDLE hProvider/* = 0*/)
{
	if (hProvider)
	{
		return GetMachineUID_TPM(pbId, cbId, hProvider);
	}
	NTSTATUS status = GetMachineUID_TPM(pbId, cbId);
	return status ? GetMachineUID_LSA(pbId, cbId) : NOERROR;
}

HRESULT GetMachineUID(_Out_writes_z_(25) PWSTR buf, _In_ ULONG cch, _In_opt_ NCRYPT_PROV_HANDLE hProvider/* = 0*/)
{
	UCHAR hash[16];
	if (NTSTATUS status = GetMachineUID(hash, sizeof(hash), hProvider))
	{
		return status;
	}
	return GetLastHresult(CryptBinaryToStringW(hash, sizeof(hash), CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF, buf, &cch));
}

HRESULT GetEKCert(_Out_ PCCERT_CONTEXT* ppCertContext, _In_ NCRYPT_PROV_HANDLE hProvider, _In_ PCWSTR pszProperty)
{
	HCERTSTORE hStore;

	ULONG cb;
	HRESULT hr; 
	if (NOERROR == (hr = NCryptGetProperty(hProvider, pszProperty, (PBYTE)&hStore, sizeof(hStore), &cb, 0)))
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

HRESULT StartAIKHandshake(
	_In_ PCWSTR pszAIKAlgId,
	_In_ PCWSTR pszKeyName,
	_In_ PCWSTR pszKeyAlgId,
	_In_ PCSTR pszPublicKeyObjId,
	_In_reads_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
	_In_ HANDLE hToken,
	_Out_ PBOOL pbTpmPresent,
	_Out_ PDATA_BLOB request,
	_Out_ NCRYPT_KEY_HANDLE* phAIK)
{
	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status;
	*pbTpmPresent = FALSE;

	if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0))) 
	{
		*pbTpmPresent = TRUE;

		// get unique machine name
		WCHAR MachineName[25];
		if (NOERROR == (status = GetMachineUID(MachineName, _countof(MachineName), hProvider)))
		{
			PCWSTR pszProperty;
			
			if (pszAIKAlgId)
			{
				pszProperty = NCRYPT_PCP_ECC_EKNVCERT_PROPERTY;
			}
			else
			{
				pszAIKAlgId = BCRYPT_RSA_ALGORITHM;
				pszProperty = NCRYPT_PCP_RSA_EKNVCERT_PROPERTY;
			}

			// get EKCert
			PCCERT_CONTEXT pCertContext;

			if (NOERROR == (status = GetEKCert(&pCertContext, hProvider, pszProperty))) 
			{
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
									while (NOERROR == (status = NCryptCreateClaim(hKey, hAIK, NCRYPT_CLAIM_SUBJECT_ONLY, &ParameterList, pbKAS, cbKAS, &cbKAS, 0)))
									{
										if (pKAS)
										{
											// insert IdBinding to PCP_KEY_ATTESTATION_STATEMENT
											pbNonce = pbKAS + pKAS->HeaderSize;
											memmove(pbNonce + cbIdBinding, pbNonce + pKAS->cbIdBinding, pKAS->cbKeyAttestation);
											memcpy(pbNonce, pbIdBinding, cbIdBinding);
											pKAS->cbIdBinding = cbIdBinding;
											pKAS->cbAIKOpaque = 0;

											// build PKCS#10

											if (NOERROR == (status = BuildPkcs10(request,
												N_CRYPT_KEY_HANDLE(hKey, pszPublicKeyObjId), hToken,
												MS_PLATFORM_KEY_STORAGE_PROVIDER, MachineName, pCertContext,
												pbKAS, pKAS->HeaderSize + cbIdBinding + pKAS->cbKeyAttestation)))
											{
												*phAIK = hAIK, hAIK = 0;
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
					}

					if (hAIK) NCryptFreeObject(hAIK);
				}

				CertFreeCertificateContext(pCertContext);
			}
		}

		NCryptFreeObject(hProvider);
	}

	return status;
}


HRESULT DecryptSecret(
	_In_ NCRYPT_KEY_HANDLE hKey,
	_Inout_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_Out_ PULONG pcbSecret)
{
	NTSTATUS status; 

	if (NOERROR == (status = NCryptSetProperty(hKey, NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY, pbSecret, cbSecret, 0)))
	{
		status = NCryptGetProperty(hKey, NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY, pbSecret, cbSecret, pcbSecret, 0);
	}

	return status;
}

NTSTATUS BKeyToNkey(_In_ BOOL bSign,
					_In_ BCRYPT_KEY_HANDLE hKey, 
					_In_ PCWSTR pszKeyName, 
					_In_opt_ ULONG dwFlags = 0, 
					_In_opt_ ULONG ExportFlags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG);

HRESULT AddEncodedCertificateToStore(
	_Out_ PCCERT_CONTEXT *ppCertContext,
	_In_ HANDLE hToken,
	_In_ const BYTE* pbCertEncoded,
	_In_ DWORD cbCertEncoded,
	_In_ PCWSTR pwszKeyName,
	_In_opt_ BCRYPT_KEY_HANDLE hKey/* = 0*/)
{
	HRESULT hr;
	if (0 <= (hr = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken))))
	{
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

						if (!hr)
						{
							*ppCertContext = pCertContext, pCertContext = 0;
						}
					}
				}
				CertFreeCertificateContext(pCertContext);
			}

			CertCloseStore(hCertStore, 0);
		}

		hToken = 0;
		NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
	}
	
	return hr;
}

_NT_END