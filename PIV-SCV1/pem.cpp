#include "stdafx.h"

_NT_BEGIN

#include "../piv_hook/sc_container.h"

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _Out_ PBYTE* ppb, _Out_ ULONG* pcb, _In_opt_ ULONG64 MaxSize = 0);
HRESULT ShowCert(_In_opt_ HWND hwndDlg, _In_ PCCERT_CONTEXT pCertContext);

PSTR __fastcall strnstr(SIZE_T n1, const void* str1, SIZE_T n2, const void* str2);

#define _strnstr(a, b, x) strnstr(RtlPointerToOffset(a, b), a, sizeof(x) - 1, x)

HRESULT ShowCert(_In_opt_ HWND hwndDlg, _In_ PCCERT_CONTEXT pCertContext);

HRESULT NKeyToBKey(_In_ NCRYPT_KEY_HANDLE hKey, _In_ ULONG cbCertEncoded, _Out_ RBMM_CARD** ppcard)
{
	RBMM_CARD* pcard = 0;
	PBYTE pb = 0;
	ULONG cb = 0;
	NTSTATUS status;
	while (NOERROR == (status = NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			if ('CE' == (WORD)reinterpret_cast<BCRYPT_KEY_BLOB*>(pb)->Magic)
			{
				pb[2] = 'S';
			}
			pcard->cbCert = cbCertEncoded;
			pcard->cbKey = cb;
			*ppcard = pcard;
			return S_OK;
		}

		if (!(pcard = new(cb + cbCertEncoded) RBMM_CARD))
		{
			return NTE_NO_MEMORY;
		}

		pb = pcard->buf + cbCertEncoded;
	}

	delete pcard;

	return status;
}

HRESULT NKeyToBKey_PKCS8(_In_ PNCryptBufferDesc ParameterList, 
						 _In_ PBYTE pb, 
						 _In_ ULONG cb, 
						 _In_ ULONG cbCertEncoded, 
						 _Out_ RBMM_CARD** ppcard)
{
	HRESULT hr;
	NCRYPT_PROV_HANDLE hProvider;

	if (NOERROR == (hr = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0)))
	{
		NCRYPT_KEY_HANDLE hKey;
		hr = NCryptImportKey(hProvider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, 
			ParameterList, &hKey, pb, cb, NCRYPT_DO_NOT_FINALIZE_FLAG);

		NCryptFreeObject(hProvider);

		if (NOERROR == hr)
		{
			static const ULONG flags = NCRYPT_ALLOW_EXPORT_FLAG|NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

			if (NOERROR == (hr = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&flags, sizeof(flags), 0)) &&
				NOERROR == (hr = NCryptFinalizeKey(hKey, NCRYPT_SILENT_FLAG)))
			{
				hr = NKeyToBKey(hKey, cbCertEncoded, ppcard);
			}

			NCryptFreeObject(hKey);
		}
	}

	return hr;
}

HRESULT NKeyToBKey_PKCS8(_In_ NCRYPT_KEY_HANDLE hKey, _In_ ULONG cbCertEncoded, _Out_ RBMM_CARD** ppcard)
{
	HRESULT hr;
	union {
		UCHAR pp[sizeof(CRYPT_PKCS12_PBE_PARAMS)+8];
		CRYPT_PKCS12_PBE_PARAMS params;
	};
	BCryptBuffer buf[] = { 
		{ sizeof(pp), NCRYPTBUFFER_PKCS_ALG_PARAM, pp },
		{
			sizeof(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES), 
				NCRYPTBUFFER_PKCS_ALG_OID, 
				const_cast<PSTR>(szOID_PKCS_12_pbeWithSHA1And3KeyTripleDES)
		},
	};
	NCryptBufferDesc ParameterList { NCRYPTBUFFER_VERSION, _countof(buf), buf };

	params.iIterations = 1;
	params.cbSalt = sizeof(pp) - sizeof(CRYPT_PKCS12_PBE_PARAMS);

	PBYTE pb = 0;
	ULONG cb = 0;
	while (NOERROR == (hr = NCryptExportKey(hKey, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &ParameterList, pb, cb, &cb, 0)))
	{
		if (pb)
		{
			hr = NKeyToBKey_PKCS8(&ParameterList, pb, cb, cbCertEncoded, ppcard);

			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

HRESULT PFXImport(_Out_ RBMM_CARD** ppcard,
				  _In_ PBYTE pb,
				  _In_ ULONG cb,
				  _In_ PCWSTR szPassword,
				  _In_opt_ HWND hwndDlg)
{
	HRESULT hr;
	CRYPT_DATA_BLOB PFX = { cb, pb };
	if (HCERTSTORE hStore = HR(hr, PFXImportCertStore(&PFX, szPassword,
		PKCS12_ALWAYS_CNG_KSP | PKCS12_NO_PERSIST_KEY | NCRYPT_ALLOW_EXPORT_FLAG)))
	{
		PCCERT_CONTEXT pCertContext = 0;
		while (pCertContext = HR(hr, CertEnumCertificatesInStore(hStore, pCertContext)))
		{
			CERT_KEY_CONTEXT ckc;
			if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_CONTEXT_PROP_ID, &ckc, &(cb = sizeof(ckc))))
			{
				if (CERT_NCRYPT_KEY_SPEC == ckc.dwKeySpec)
				{
					if (NOERROR == (hr = ShowCert(hwndDlg, pCertContext)) )
					{
						DWORD cbCertEncoded = pCertContext->cbCertEncoded;

						if (NOERROR == (hr = NKeyToBKey_PKCS8(ckc.hNCryptKey, cbCertEncoded, ppcard)))
						{
							RBMM_CARD* pcard = *ppcard;
							memcpy(pcard->buf, pCertContext->pbCertEncoded, cbCertEncoded);
						}
					}

					CertFreeCertificateContext(pCertContext);
					break;
				}
			}
		}

		CertCloseStore(hStore, 0);
	}

	return hr;
}

HRESULT PkcsImportKey(_Out_ RBMM_CARD** ppcard, 
					  _In_reads_(cb) BYTE* pb, 
					  _In_ ULONG cb, 
					  _In_opt_ PCWSTR pszPassword = 0)
{
	NCryptBufferDesc *pParameterList = 0;
	BCryptBuffer buf;
	NCryptBufferDesc ParameterList { NCRYPTBUFFER_VERSION, 1, &buf };

	if (pszPassword)
	{
		buf.BufferType = NCRYPTBUFFER_PKCS_SECRET;
		buf.cbBuffer = (1 + (ULONG)wcslen(pszPassword)) * sizeof(WCHAR);
		buf.pvBuffer = const_cast<PWSTR>(pszPassword);

		pParameterList = &ParameterList;
	}

	return NKeyToBKey_PKCS8(pParameterList, pb, cb, 0, ppcard);
}

PCWSTR GetCNGAlgid(_In_ PSTR szCurveOid, _Out_ PBCRYPT_ECCKEY_BLOB pBlob)
{
	if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY|CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 
		szCurveOid, CRYPT_OID_PREFER_CNG_ALGID_FLAG))
	{
		if (3*sizeof(ULONG) <= pcoi->ExtraInfo.cbData)
		{
			pBlob->dwMagic = reinterpret_cast<ULONG*>(pcoi->ExtraInfo.pbData)[1];
			pBlob->cbKey = (reinterpret_cast<ULONG*>(pcoi->ExtraInfo.pbData)[2] + 7) / 8;
			return pcoi->pwszCNGAlgid;
		}
	}

	return 0;
}

BOOLEAN IsCertMatch(_In_ PCCERT_CONTEXT pCertContext, _In_ BCRYPT_KEY_BLOB* pBlob, _In_ ULONG cbBlob)
{
	PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo = &pCertContext->pCertInfo->SubjectPublicKeyInfo;

	ULONG cbPublicKey;
	union {
		PBYTE pbPublicKey;
		PVOID pv;
		BCRYPT_RSAKEY_BLOB* pRsaBlob;
	};

	ULONG Magic = pBlob->Magic - 0x01000000;
	BOOLEAN fOk = FALSE;

	if (!strcmp(szOID_RSA_RSA, SubjectPublicKeyInfo->Algorithm.pszObjId))
	{
		if (CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PUBLIC_KEY_BLOB, 
			SubjectPublicKeyInfo->PublicKey.pbData, SubjectPublicKeyInfo->PublicKey.cbData, 
			CRYPT_DECODE_ALLOC_FLAG, 0, &pbPublicKey, &cbPublicKey))
		{
			if (Magic == pRsaBlob->Magic &&
				cbBlob > sizeof(BCRYPT_RSAKEY_BLOB) + pRsaBlob->cbPublicExp + pRsaBlob->cbModulus &&
				reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(pBlob)->BitLength == pRsaBlob->BitLength &&
				reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(pBlob)->cbPublicExp == pRsaBlob->cbPublicExp &&
				reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(pBlob)->cbModulus == pRsaBlob->cbModulus)
			{
				fOk = !memcmp(pRsaBlob + 1, reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(pBlob) + 1, 
					pRsaBlob->cbPublicExp + pRsaBlob->cbModulus);
			}

			LocalFree(pbPublicKey);
		}
		return fOk;
	}

	if (!strcmp(szOID_ECC_PUBLIC_KEY, SubjectPublicKeyInfo->Algorithm.pszObjId) &&
		SubjectPublicKeyInfo->PublicKey.cbData-- && 4 == *SubjectPublicKeyInfo->PublicKey.pbData++)
	{
		union {
			PSTR pszObjId;
			UCHAR buf[64];
		};

		ULONG cb = sizeof(buf);

		if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, 
			SubjectPublicKeyInfo->Algorithm.Parameters.pbData, 
			SubjectPublicKeyInfo->Algorithm.Parameters.cbData, 0, 0, buf, &cb))
		{
			BCRYPT_ECCKEY_BLOB EccBlob;

			if (GetCNGAlgid(pszObjId, &EccBlob))
			{
				if (Magic == EccBlob.dwMagic && 
					SubjectPublicKeyInfo->PublicKey.cbData == 2 * EccBlob.cbKey && 
					cbBlob > SubjectPublicKeyInfo->PublicKey.cbData + sizeof(BCRYPT_ECCKEY_BLOB) &&
					EccBlob.cbKey == reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pBlob)->cbKey)
				{
					return !memcmp(reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(pBlob) + 1, 
						SubjectPublicKeyInfo->PublicKey.pbData, 
						SubjectPublicKeyInfo->PublicKey.cbData);
				}
			}
		}
	}

	return FALSE;
}

extern const volatile UCHAR guz;

class __declspec(novtable) Pem
{
	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb) = 0;

public:
	virtual ~Pem() = default;

	HRESULT import(_In_reads_(cch) PCSTR psz, _In_ ULONG cch)
	{
		HRESULT hr;

		if (HR(hr, CryptStringToBinaryA(psz, cch, CRYPT_STRING_BASE64, (PBYTE)psz, &cch, 0, 0)))
		{
			hr = process((PBYTE)psz, cch);
		}

		return hr;
	}

	void* operator new(size_t s, void* pv, ULONG cb)
	{
		return cb < s ? 0 : pv;
	}

	void operator delete (void* /*pv*/)
	{
	}
};

struct PemCert : public Pem
{
	PCCERT_CONTEXT m_pCertContext = 0;

	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		m_pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pb, cb);
		return m_pCertContext ? NOERROR : GetLastHresult();
	}
};

struct PemPrivateKey : public Pem
{
	PCWSTR _M_pszPassword;
	RBMM_CARD* m_pcard = 0;

	PemPrivateKey(PCWSTR pszPassword = 0) : _M_pszPassword(pszPassword)
	{
	}

	virtual HRESULT process(_In_reads_(cb) BYTE* pb, _In_ ULONG cb)
	{
		return PkcsImportKey(&m_pcard, pb, cb, _M_pszPassword);
	}
};

PCSTR IsTag(_In_ PCSTR buf, _In_ PCSTR end, _In_ PCSTR TAG, _In_ ULONG cb)
{
	return (ULONG_PTR)(end - buf) < cb || memcmp(buf, TAG, cb) ? 0 : buf + cb;
}

PCSTR IsBegin(_In_ PCSTR buf, _In_ PCSTR end)
{
	const static char BEGIN[] = "BEGIN";
	return IsTag(buf, end, BEGIN, sizeof(BEGIN) - 1);
}

PCSTR IsEnd(_In_ PCSTR buf, _In_ PCSTR end)
{
	const static char END[] = "END";
	return IsTag(buf, end, END, sizeof(END) - 1);
}

HRESULT PEMImport(_Out_ RBMM_CARD** ppcard,
				  _In_ PBYTE pb,
				  _In_ ULONG cb,
				  _In_ PCWSTR szPassword,
				  _In_opt_ HWND hwndDlg)
{
	const static char _____[] = "-----";
	const static char ENCRYPTED_PRIVATE_KEY[] = "ENCRYPTED PRIVATE KEY";
	const static char CERTIFICATE[] = "CERTIFICATE";

	enum { fInvalid ,fCert, fEncPrivKey, fPrivKey, fPubKey, fRsaPubKey, fRsaPrivKey } bt;

	PCSTR buf = (PCSTR)pb, end = buf + cb;

	HRESULT hr = NTE_NOT_FOUND;
	PVOID stack = alloca(guz);
	ULONG nCerts = 0;
	PCCERT_CONTEXT* ppCertContexts = (PCCERT_CONTEXT*)stack;
	RBMM_CARD* pcard = 0;

	while (buf = _strnstr(buf, end, _____))
	{
		hr = HRESULT_FROM_NT(STATUS_INVALID_IMAGE_FORMAT);

		bt = fInvalid;

		if (!(buf = IsBegin(buf, end - sizeof(_____))) || *buf++ != ' ')
		{
			break;
		}

		PCSTR pcTag = buf;

		if (buf = IsTag(pcTag, end, CERTIFICATE, sizeof(CERTIFICATE) - 1))
		{
			bt = fCert;
		}
		else if (buf = IsTag(pcTag, end, 
			ENCRYPTED_PRIVATE_KEY + _countof("ENCRYPTED"), 
			sizeof(ENCRYPTED_PRIVATE_KEY) - _countof("ENCRYPTED") - 1))
		{
			bt = fPrivKey;
		}
		else if (buf = IsTag(pcTag, end, ENCRYPTED_PRIVATE_KEY, sizeof(ENCRYPTED_PRIVATE_KEY) - 1))
		{
			bt = fEncPrivKey;
		}
		else
		{
			if (!(buf = _strnstr(pcTag, end - 2, _____)))
			{
				break;
			}
			goto __0;
		}

		if (!(buf = IsTag(buf, end - 2, _____, sizeof(_____) - 1)))
		{
			break;
		}

__0:
		ULONG len = RtlPointerToOffset(pcTag, buf);

		PCSTR pc = buf;

		if (!(buf = _strnstr(buf, end, _____)))
		{
			break;
		}

		cb = RtlPointerToOffset(pc, buf - sizeof(_____));

		if (!(buf = IsEnd(buf, end - sizeof(_____))) || 
			*buf++ != ' ' ||
			!(buf = IsTag(buf, end, pcTag, len)))
		{
			break;
		}

		UCHAR pembuf[sizeof(PemPrivateKey)];
		Pem* pem = 0;

		switch (bt)
		{
		case fCert:
			pem = new(pembuf, sizeof(pembuf)) PemCert;
			break;

		case fPrivKey:
			szPassword = 0;
		case fEncPrivKey:
			if (pcard)
			{
				hr = STATUS_TOO_MANY_SECRETS;
				break;
			}
			pem = new(pembuf, sizeof(pembuf)) PemPrivateKey(szPassword);
			break;
		}

		if (pem)
		{
			if (S_OK == pem->import(pc, cb))
			{
				if (fCert == bt)
				{
					if (--ppCertContexts < stack)
					{
						stack = alloca(sizeof(PVOID));
					}
					*ppCertContexts = static_cast<PemCert*>(pem)->m_pCertContext;
					nCerts++;
				}
				else
				{
					pcard = static_cast<PemPrivateKey*>(pem)->m_pcard;
				}
			}
		}
	}

	if (nCerts)
	{
		do 
		{
			PCCERT_CONTEXT pCertContext = *ppCertContexts++;
			if (pcard && IsCertMatch(pCertContext, reinterpret_cast<BCRYPT_KEY_BLOB*>(pcard->buf), pcard->cbKey))
			{
				if (hr = ShowCert(hwndDlg, pCertContext))
				{
				}
				else
				{
					ULONG cbCertEncoded = pCertContext->cbCertEncoded;
					if (RBMM_CARD* pCard = new(pcard->cbKey + cbCertEncoded) RBMM_CARD)
					{
						pCard->cbCert = cbCertEncoded;
						memcpy(pCard->buf, pCertContext->pbCertEncoded, cbCertEncoded);
						memcpy(pCard->buf + cbCertEncoded, pcard->buf, pCard->cbKey = pcard->cbKey);
						*ppcard = pCard;
						hr = S_OK;
					}
				}

				delete pcard;
				pcard = 0;
			}
			CertFreeCertificateContext(pCertContext);
		} while (--nCerts);
	}

	if (pcard)
	{
		delete pcard;
	}

	return hr;
}

_NT_END