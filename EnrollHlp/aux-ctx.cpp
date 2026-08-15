#include "stdafx.h"

_NT_BEGIN
#include "../log/log.h"
#include "aux-ctx.h"
#include "decode.h"
#include "util.h"
#include "TPM.h"
#include "EnrollHlp.h"

void ACB::I_SetPublicKey(_In_ PCERT_PUBLIC_KEY_INFO pInfo)
{
	_bittestandreset(&m_dwFlags, e_need_PKI);

	HRESULT hr = STATUS_NOT_SUPPORTED;

	if (IsSupportedAlg(&pInfo->Algorithm, &m_pszEccAlgId) && NOERROR == (hr = m_cert->SetPublicKey(pInfo)))
	{
		HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, pInfo, CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, 0, &m_hUserKey));
	}

	m_hr = hr;
}

void ACB::I_SetUPN(_In_ PCWSTR pcszUPN)
{
	if (!m_hr && _bittestandreset(&m_dwFlags, e_need_UPN))
	{
		checkFinish(m_cert->SetUPN(pcszUPN));
	}
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dvre/76747b5c-06c2-4c73-9207-8ebb6ee891ea
// 1.2.840.113556.1.5.284.2
// The server MUST generate a globally unique identifier (GUID) and include it as the value.
// https://call4cloud.nl/ms-organization-access-tenantid/

#define szOID_DEVICE_GUID	"1.2.840.113556.1.5.284.2"
#define szOID_OBJECT_GUID	"1.2.840.113556.1.5.284.3"
#define szOID_TENAT_GUID	"1.2.840.113556.1.5.284.5"
#define szOID_CLOUD_JOIN	"1.2.840.113556.1.5.284.7"
#define szOID_TENAT_REGION	"1.2.840.113556.1.5.284.8"

void ACB::I_SetMachine(_In_ PCWSTR pcszMachine)
{
	if (!m_hr)
	{
		CRYPT_DATA_BLOB db_guid = { sizeof(GUID), m_pbMachine };

		if (CryptStringToBinaryW(pcszMachine, 0, CRYPT_STRING_BASE64, db_guid.pbData, &db_guid.cbData, 0, 0) &&
			sizeof(GUID) == db_guid.cbData)
		{
			if (_bittestandreset(&m_dwFlags, e_need_machine))
			{
				checkFinish(m_cert->AddExtension(szOID_DEVICE_GUID, &db_guid, FALSE, X509_OCTET_STRING));
			}
		}
	}
}

void ACB::I_SetUser(_In_ PCWSTR pcszUser)
{
	if (!m_hr && _bittestandreset(&m_dwFlags, e_need_user))
	{
		wcscpy_s(m_pszUserName, m_cchUserName, pcszUser);
		checkFinish(m_cert->SetSubjectName(pcszUser));
	}
}

void ACB::checkFinish(HRESULT hr)
{
	if (!hr && !m_dwFlags)
	{
		hr = m_cert->Sign(m_hSignKey);
	}
	m_hr = hr;
}

void ACB::I_SetEKCert(_In_ const BYTE* pbCertEncoded, _In_ DWORD cbCertEncoded)
{
	if (!m_hEkKey)
	{
		if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded))
		{
			if (IsSupportedAlg(&pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm, &m_pszEccAlgId))
			{
				ValidateCert(pCertContext, szOID_KP_TPM_EK_CERTIFICATE);
			
				// we need encrypt key
				CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pCertContext->pCertInfo->SubjectPublicKeyInfo, 
					CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, 0, &m_hEkKey);
			}

			CertFreeCertificateContext(pCertContext);
		}
	}
}

void ACB::I_SetKAS(_In_ const BYTE* pbKAS, _In_ DWORD cbKAS)
{
	if (!m_pbKeyAttestationStatement)
	{
		if (m_pbKeyAttestationStatement = new UCHAR[cbKAS])
		{
			memcpy(m_pbKeyAttestationStatement, pbKAS, cbKAS);
			m_cbKeyAttestationStatement = cbKAS;
		}
	}
}

void ACB::I_SetProviderName(_In_ PCWSTR ProviderName)
{
	if (!m_hr && _bittestandreset(&m_dwFlags, e_need_provider))
	{
		m_IsTPM = !wcscmp(ProviderName, MS_PLATFORM_KEY_STORAGE_PROVIDER);
		checkFinish(m_cert->SetTemplateName(m_IsTPM ? wszCERTTYPE_SMARTCARD_USER : wszCERTTYPE_USER));
	}
}

HRESULT Verify_PKCS_10(_In_ PBYTE pbPKCS, _In_ ULONG cbPKCS);

HRESULT
WINAPI
CreateCert(
	_Out_ PBYTE pbOut,
	_In_  ULONG cbOut,
	_Out_ PULONG pcbResult,
	_In_ PBYTE pbPKCS,
	_In_ ULONG cbPKCS,
	_Inout_updates_bytes_(SHA1_DIGEST_SIZE) PBYTE pbNonce,
	_Out_writes_bytes_(16) PBYTE pbMachine,
	_Out_writes_z_(cchUserName) PWSTR pszUserName,
	_In_ ULONG cchUserName,
	_In_ PCERT_INFO IssuerCert,
	_In_ BCRYPT_KEY_HANDLE hSignKey,
	_In_ PCWSTR pwszCaURL,
	_In_ PCWSTR pwszOcspURL,
	_In_ ULONG nDays)
{
	HRESULT hr;
	union {
		FILETIME NotAfter;
		ULONG64 time;
	};
	GetSystemTimeAsFileTime(&NotAfter);
	time += 10000000ULL * 3600* 24*nDays;

	CERT_EXTENSION Extensions[12];
	CERT_BUID cert(_countof(Extensions), Extensions, &NotAfter);

	static const PCSTR szUsageIdentifier[] = { 
		szOID_PKIX_KP_CLIENT_AUTH,
		szOID_PKIX_KP_EMAIL_PROTECTION
	};

	static const CERT_ENHKEY_USAGE eku = { 
		_countof(szUsageIdentifier), const_cast<PSTR*>(szUsageIdentifier) 
	};

	if ((0 <= (hr = cert.SetKeyUsage(CERT_DIGITAL_SIGNATURE_KEY_USAGE)) &&
		0 <= (hr = cert.SetEnhancedKeyUsage(&eku)) &&
		0 <= (hr = cert.SetIssuer(IssuerCert)) &&
		0 <= (hr = cert.SetCA(pwszCaURL, pwszOcspURL)) &&
		0 <= (hr = cert.SetSerial()) ))
	{
		RTL_FRAME<ACB> ctx(hSignKey, &cert, pbMachine, pszUserName, cchUserName);

		if (NOERROR == (hr = Verify_PKCS_10(pbPKCS, cbPKCS)))
		{
			hr = E_FAIL;

			if (NOERROR == ctx.m_hr && !ctx.m_dwFlags)
			{
				ULONG cbCertEncoded = cert.cbCertEncoded();
				PBYTE pbCertEncoded = cert.pbCertEncoded();

				if (ctx.m_IsTPM)
				{
					if (ctx.m_hEkKey && ctx.m_pbKeyAttestationStatement)
					{
						AIK_PARAMS params;
						if (params.ParseKeyAttestation(
							ctx.m_pbKeyAttestationStatement, ctx.m_cbKeyAttestationStatement, 
							pbNonce, SHA1_DIGEST_SIZE, ctx.m_hUserKey))
						{
							// https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/Object/MakeCredential.c#L40
							// The credential information may not be larger than the digest size used for
							// the Name of the key associated with handle.

							UCHAR aes[32];
							if (0 <= BCryptGenRandom(0, pbNonce, SHA1_DIGEST_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG))
							{
								struct SAK
								{
									USHORT cbSecret, cbCert;
									UCHAR buf[];
								};

								C_ASSERT(sizeof(SAK) == offsetof(SAK, buf));

								SAK* p = (SAK*)pbOut;
								ULONG cb, s = sizeof(aes);

								if (0 <= params.GenerateActivation20(ctx.m_hEkKey, ctx.m_pszEccAlgId,
									pbNonce, SHA1_DIGEST_SIZE, p->buf, cbOut - sizeof(SAK), &cb))
								{
									if (cbOut - sizeof(SAK) - cb >= cbCertEncoded &&
										CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, pbNonce, SHA1_DIGEST_SIZE, aes, &s) &&
										0 <= CFBXcrypt(aes, s, pbCertEncoded, cbCertEncoded, p->buf + cb, FALSE))
									{
										p->cbSecret = (USHORT)cb;
										p->cbCert = (USHORT)cbCertEncoded;
										*pcbResult = sizeof(SAK) + cb + cbCertEncoded;
										hr = S_OK;
									}
								}
							}
						}
					}
				}
				else
				{
					if (cbOut >= cbCertEncoded)
					{
						memcpy(pbOut, pbCertEncoded, cbCertEncoded);
						*pcbResult = cbCertEncoded;
						hr = S_OK;
					}
				}
			}
		}
	}

	return hr;
}

_NT_END