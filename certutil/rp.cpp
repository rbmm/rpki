#include "stdafx.h"

_NT_BEGIN

#include "../inc/rtlframe.h"
#include "../log/log.h"
#include "json.h"
#include "cert.h"
#include "util.h"

void DumpBytesInLine(const UCHAR* pb, ULONG cb, PCSTR prefix = "", PCSTR suffix = "\n")
{
	if (cb)
	{
		PSTR psz = 0;
		ULONG cch = 0;
		while(CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, psz, &cch))
		{
			if (psz)
			{
				DbgPrint("%hs%hs%hs", prefix, psz, suffix);
				break;
			}

			psz = (PSTR)alloca(cch);
		}
	}
}

void DumpHash(PUCHAR pb, ULONG cb, _In_ PCWSTR pwszCNGHashAlgid = BCRYPT_SHA1_ALGORITHM)
{
	UCHAR hash[64];
	ULONG len = sizeof(hash);
	if (CryptHashCertificate2(pwszCNGHashAlgid, 0, 0, pb, cb, hash, &len))
	{
		DumpBytesInLine(hash, len, "Thumbprint: ");
	}
}

void* WINAPI FAlloc(size_t s)
{
	if (JHeapPtr* heap = RTL_FRAME<JHeapPtr>::get())
	{
		if (PVOID pv = heap->heap->Alloc(s))
		{
			return pv;
		}
	}

	return 0;
}

void WINAPI FFree(PVOID)
{
}

DWORD HashString(PCSTR lpsz, DWORD hash = 0)
{
	while (char c = *lpsz++) hash = hash * 33 ^ c;
	return hash;
}

static void DebugCasePrint(PCSTR name)
{
	DbgPrint("case 0x%08x: // %hs\r\n"
		"\tif (!_bittestandreset(&flags, e_%hs) || JNode::v_str != value->vt) return FALSE;\r\n"
		"\tpcsz = value->pcstr;\r\n"
		"\tbreak;\r\n", HashString(name), name, name);
};

void ShowCert(HWND hwnd, PBYTE pb, ULONG cb, PCWSTR szTitle)
{
	if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pb, cb))
	{
		CRYPTUI_VIEWCERTIFICATE_STRUCTW cvi = {
			sizeof(cvi), hwnd, CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EDITPROPERTIES, szTitle, pCertContext
		};

		BOOL b;
		CryptUIDlgViewCertificateW(&cvi, &b);
		CertFreeCertificateContext(pCertContext);
	}
}

HRESULT CreateKey(_Out_ NCRYPT_KEY_HANDLE* phKey, 
				  _In_ PCWSTR pszAlgId, 
				  _In_ PCWSTR pwszKeyName,
				  _In_ ULONG dwFlags,
				  _In_opt_ ULONG dwLength)
{
	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status;

	if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, MS_KEY_STORAGE_PROVIDER, 0)))
	{
		BOOLEAN fCreated = FALSE;
		NCRYPT_KEY_HANDLE hKey;
		if (!pwszKeyName || (NTE_BAD_KEYSET == (status = NCryptOpenKey(hProvider, &hKey, pwszKeyName, 0, dwFlags))))
		{
			status = NCryptCreatePersistedKey(hProvider, &hKey, pszAlgId, pwszKeyName, 0, dwFlags);
			fCreated = TRUE;
		}

		NCryptFreeObject(hProvider);

		if (NOERROR == status)
		{
			dwFlags = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

			if (!fCreated || (NOERROR == (status = dwLength ? NCryptSetProperty(hKey, NCRYPT_LENGTH_PROPERTY,
				(PBYTE)&dwLength, sizeof(dwLength), 0) : NOERROR) &&
				NOERROR == (status = NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY,
				(PBYTE)&dwFlags, sizeof(dwFlags), 0)) &&
				NOERROR == (status = NCryptFinalizeKey(hKey, 0))))
			{
				*phKey = hKey;
				return NOERROR;
			}

			NCryptFreeObject(hKey);
		}
	}

	return status;
}

BOOLEAN Convert(_In_ PCSTR pcsz, _Out_ PWSTR* ppwz, _Out_opt_ PWSTR* ppassword = 0)
{
	ULONG ByteCount = 0, len = (ULONG)strlen(pcsz) + 1;
	PWSTR pwz = 0;
	while(0 <= RtlUTF8ToUnicodeN(pwz, ByteCount, &ByteCount, pcsz, len))
	{
		if (pwz)
		{
			if (ppassword)
			{
				if (PWSTR Password = wcschr(pwz, '*'))
				{
					*Password = 0;
					*ppassword = Password + 1;
				}
				else
				{
					return FALSE;
				}
			}

			*ppwz = pwz;
			return TRUE;
		}

		if (!(pwz = (PWSTR)FAlloc(ByteCount)))
		{
			return FALSE;
		}
	}

	return FALSE;
}

BOOLEAN ParseUsage(_In_ JNode* value, _Out_ PBYTE pKeyUsage)
{
	*pKeyUsage = 0;

	if (!value)
	{
		return FALSE;
	}

	do 
	{
		if (JNode::v_str != value->vt)
		{
			return FALSE;
		}

		switch (HashString(value->pcstr))
		{
		case 0x95574a0c: // CERT_DIGITAL_SIGNATURE_KEY_USAGE
			*pKeyUsage |= CERT_DIGITAL_SIGNATURE_KEY_USAGE;
			break;
		case 0xf5be0cff: // CERT_NON_REPUDIATION_KEY_USAGE
			*pKeyUsage |= CERT_NON_REPUDIATION_KEY_USAGE;
			break;
		case 0x4f01bad9: // CERT_KEY_ENCIPHERMENT_KEY_USAGE
			*pKeyUsage |= CERT_KEY_ENCIPHERMENT_KEY_USAGE;
			break;
		case 0x62be483e: // CERT_DATA_ENCIPHERMENT_KEY_USAGE
			*pKeyUsage |= CERT_DATA_ENCIPHERMENT_KEY_USAGE;
			break;
		case 0x1dced4c3: // CERT_KEY_AGREEMENT_KEY_USAGE
			*pKeyUsage |= CERT_KEY_AGREEMENT_KEY_USAGE;
			break;
		case 0x87074449: // CERT_KEY_CERT_SIGN_KEY_USAGE
			*pKeyUsage |= CERT_KEY_CERT_SIGN_KEY_USAGE;
			break;
		case 0xf7610f3c: // CERT_CRL_SIGN_KEY_USAGE
			*pKeyUsage |= CERT_CRL_SIGN_KEY_USAGE;
			break;
		case 0x38447d28: // CERT_ENCIPHER_ONLY_KEY_USAGE
			*pKeyUsage |= CERT_ENCIPHER_ONLY_KEY_USAGE;
			break;
		default:
			DbgPrint("case 0x%08x: // %hs\r\n"
				"\t*pKeyUsage |= %hs;\r\n"
				"\tbreak;\r\n", HashString(value->pcstr), value->pcstr, value->pcstr);
		}
	} while (value = value->next);

	return TRUE;
}

BOOLEAN SetTemplate(CERT_BUID* cert, _In_ JNode* value)
{
	if (!value || JNode::v_str != value->vt)
	{
		return FALSE;
	}

	CERT_TEMPLATE_EXT cte = { const_cast<PSTR>(value->pcstr) };

	if (!(value = value->next) || JNode::v_int != value->vt)
	{
		return FALSE;
	}

	cte.dwMajorVersion = (ULONG)value->iVal;

	if (value = value->next)
	{
		if (JNode::v_int != value->vt)
		{
			return FALSE;
		}

		cte.fMinorVersion = TRUE;
		cte.fMinorVersion = (ULONG)value->iVal;
	}

	return value->next ? FALSE : !cert->SetTemplateNameV2(&cte);
}

BOOLEAN SetBC(CERT_BUID* cert, _In_ JNode* value)
{
	if (!value || JNode::v_bool != value->vt)
	{
		return FALSE;
	}

	CERT_BASIC_CONSTRAINTS2_INFO bci = {value->bVal};

	if (!(value = value->next) || JNode::v_bool != value->vt)
	{
		return FALSE;
	}

	if (bci.fPathLenConstraint = value->bVal)
	{
		if (!(value = value->next) || JNode::v_int != value->vt)
		{
			return FALSE;
		}

		bci.dwPathLenConstraint = (ULONG)value->iVal;
	}

	return value->next ? FALSE : !cert->SetBasicConstraint(&bci);
}

BOOLEAN IsOIDString(PCSTR pcsz)
{
	while (strtoul(pcsz, const_cast<char**>(&pcsz), 10))
	{
		switch (*pcsz)
		{
		case 0:
			return TRUE;
		case '.':
			pcsz++;
			continue;
		default: return FALSE;
		}
	}
	return FALSE;
}

ULONG GetStringsCount(JNode* value)
{
	ULONG n = 0;
	if (value)
	{
		do 
		{
			if (JNode::v_str != value->vt)
			{
				return 0;
			}
			n++;
		} while (value = value->next);
	}
	return n;
}

ULONG GetNamesCount(JNode* value, _Out_ PULONG pOtherCount)
{
	ULONG n = 0;
	if (value)
	{
		do 
		{
			switch (value->vt)
			{
			case JNode::v_str:
				n++;
				break;
			case JNode::v_obj:
				if (ULONG m = GetStringsCount(value->first))
				{
					n += m;
					*pOtherCount += m;
				}
				else
				{
					return 0;
				}
				break;
			default: return 0;
			}
		} while (value = value->next);
	}
	return n;
}

HRESULT AddEncodedCertificateToStore(_In_ const BYTE* pbCertEncoded,
									 _In_ DWORD cbCertEncoded,
									 _In_ ULONG dwStoreFlags,
									 _In_ PCWSTR Name,
									 _In_ PCWSTR pwszKeyName,
									 _In_ ULONG dwKeyFlags)
{
	HRESULT hr;
	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwStoreFlags, Name)))
	{
		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		// CertSetCertificateContextProperty have no effect on 
		// PCCERT_CONTEXT returned by CertAddEncodedCertificateToStore
		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		if (PCCERT_CONTEXT pCertContext = HR(hr, CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded)))
		{
			CRYPT_KEY_PROV_INFO ckpi = {
				const_cast<PWSTR>(pwszKeyName),
				const_cast<PWSTR>(MS_KEY_STORAGE_PROVIDER),
				0, NCRYPT_MACHINE_KEY_FLAG & dwKeyFlags
			};

			if (HR(hr, CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &ckpi)))
			{
				HR(hr, CertAddCertificateContextToStore(hCertStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0));
			}

			CertFreeCertificateContext(pCertContext);
		}

		CertCloseStore(hCertStore, 0);
	}

	return hr;
}

HRESULT GetStoreFlags(_In_ PCWSTR pwz, _Out_ ULONG* pdwFlags)
{
	switch (*pwz)
	{
	case 'M':
		*pdwFlags = CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE;
		break;
	case 'U':
		*pdwFlags = CERT_STORE_OPEN_EXISTING_FLAG | CERT_SYSTEM_STORE_CURRENT_USER;
		break;
	default:
		return E_INVALIDARG;
	}
	return pwz[1] ? E_INVALIDARG : NOERROR;
}

BOOLEAN SetEnKeyUsage(_Inout_ CERT_BUID* cert, _In_ JNode* value)
{
	CERT_ENHKEY_USAGE EnKeyUsage;
	if (EnKeyUsage.cUsageIdentifier = GetStringsCount(value))
	{
		PSTR* rgpszUsageIdentifier = (PSTR*)alloca(EnKeyUsage.cUsageIdentifier * sizeof(PVOID));
		EnKeyUsage.rgpszUsageIdentifier = rgpszUsageIdentifier;
		do 
		{
			*rgpszUsageIdentifier++ = const_cast<PSTR>(value->pcstr);
		} while (value = value->next);

		return 0 <= cert->SetEnhancedKeyUsage(&EnKeyUsage);
	}

	return FALSE;
}

BOOLEAN SetPolicy(_Inout_ CERT_BUID* cert, _In_ JNode* value)
{
	CERT_POLICIES_INFO cpi;
	if (cpi.cPolicyInfo = GetStringsCount(value))
	{
		CERT_POLICY_INFO *rgPolicyInfo = (CERT_POLICY_INFO*)alloca(cpi.cPolicyInfo * sizeof(CERT_POLICY_INFO));
		cpi.rgPolicyInfo = rgPolicyInfo;
		do 
		{
			rgPolicyInfo->pszPolicyIdentifier = const_cast<PSTR>(value->pcstr);
			rgPolicyInfo->cPolicyQualifier = 0;
			rgPolicyInfo++->rgPolicyQualifier = 0;
		} while (value = value->next);

		return 0 <= cert->SetPolicy(&cpi);
	}

	return FALSE;
}

BOOLEAN SetCA(_Inout_ CERT_BUID* cert, _In_ JNode* value)
{
	CERT_AUTHORITY_INFO_ACCESS ca;
	if (ca.cAccDescr = GetStringsCount(value))
	{
		PCERT_ACCESS_DESCRIPTION rgAccDescr = (PCERT_ACCESS_DESCRIPTION)alloca(ca.cAccDescr * sizeof(CERT_ACCESS_DESCRIPTION));
		ca.rgAccDescr = rgAccDescr;
		do 
		{
			if (!Convert(value->pcstr, &rgAccDescr->AccessLocation.pwszURL))
			{
				return FALSE;
			}
			rgAccDescr->AccessLocation.dwAltNameChoice = CERT_ALT_NAME_URL;
			rgAccDescr++->pszAccessMethod = const_cast<PSTR>(value->name);

		} while (value = value->next);

		return !cert->SetCA(&ca);
	}
	return FALSE;
}

PCERT_OTHER_NAME ParseOtherName(_In_ JNode* value, _Out_ PCERT_OTHER_NAME pOtherName)
{
	if (!value)
	{
		return 0;
	}

	CRYPT_ENCODE_PARA EncodePara = { sizeof(CRYPT_ENCODE_PARA), FAlloc, FFree };

	do 
	{
		if (JNode::v_str != value->vt)
		{
			return 0;
		}

		pOtherName->pszObjId = const_cast<PSTR>(value->name);

		CERT_NAME_VALUE cnv;
		PCSTR lpszStructType = 0;

		if (!strcmp(szOID_NT_PRINCIPAL_NAME, pOtherName->pszObjId))
		{
			PWSTR pcszUPN;

			if (!Convert(value->pcstr, &pcszUPN))
			{
				return 0;
			}

			cnv.dwValueType = CERT_RDN_UNICODE_STRING;
			cnv.Value.pbData = (PBYTE)pcszUPN;
			cnv.Value.cbData = (ULONG)wcslen(pcszUPN)*sizeof(WCHAR);
			lpszStructType = X509_UNICODE_NAME_VALUE;
		}
		else if (IsOIDString(pOtherName->pszObjId))
		{
			cnv.dwValueType = CERT_RDN_OCTET_STRING;
			cnv.Value.pbData = (PBYTE)value->pcstr;
			cnv.Value.cbData = (ULONG)strlen(value->pcstr);
			lpszStructType = X509_NAME_VALUE;

			if (!CryptStringToBinaryA(value->pcstr, 0, CRYPT_STRING_HEX, cnv.Value.pbData, &cnv.Value.cbData, 0, 0))
			{
				return 0;
			}
		}
		else
		{
			return FALSE;
		}

		if (!CryptEncodeObjectEx(X509_ASN_ENCODING, lpszStructType, 
			&cnv, CRYPT_ENCODE_ALLOC_FLAG, &EncodePara, &pOtherName->Value.pbData, &pOtherName->Value.cbData))
		{
			return 0;
		}

	} while (pOtherName++, value = value->next);

	return pOtherName;
}

BOOLEAN SetAltName(_Inout_ CERT_BUID* cert, _In_ JNode* value)
{
	ULONG OtherCount = 0;
	CERT_ALT_NAME_INFO ani;
	if (ani.cAltEntry = GetNamesCount(value, &OtherCount))
	{
		PCERT_OTHER_NAME pOtherName = 0;
		PCERT_ALT_NAME_ENTRY rgAltEntry = (PCERT_ALT_NAME_ENTRY)alloca(ani.cAltEntry * sizeof(CERT_ALT_NAME_ENTRY));
		ani.rgAltEntry = rgAltEntry;
		if (OtherCount)
		{
			pOtherName = (PCERT_OTHER_NAME)alloca(OtherCount* sizeof(CERT_OTHER_NAME));
		}
		do 
		{
			switch (HashString(value->name))
			{
			case 0x3d4d7e97: // CERT_ALT_NAME_RFC822_NAME
				if (JNode::v_str != value->vt || !Convert(value->pcstr, &rgAltEntry->pwszRfc822Name))
				{
					return FALSE;
				}
				rgAltEntry->dwAltNameChoice = CERT_ALT_NAME_RFC822_NAME;
				break;
			case 0xe1cf6c41: // CERT_ALT_NAME_DNS_NAME
				if (JNode::v_str != value->vt || !Convert(value->pcstr, &rgAltEntry->pwszDNSName))
				{
					return FALSE;
				}
				rgAltEntry->dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
				break;
			case 0x00015fcb: // CERT_ALT_NAME_URL
				if (JNode::v_str != value->vt || !Convert(value->pcstr, &rgAltEntry->pwszURL))
				{
					return FALSE;
				}
				rgAltEntry->dwAltNameChoice = CERT_ALT_NAME_URL;
				break;
			case 0x50c9ee1c: // CERT_ALT_NAME_OTHER_NAME
				rgAltEntry->pOtherName = pOtherName;
				if (JNode::v_obj != value->vt || !(pOtherName = ParseOtherName(value->first, pOtherName)))
				{
					return FALSE;
				}
				rgAltEntry->dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
				break;
			default:
				DbgPrint("case 0x%08x: // CERT_ALT_NAME_%hs\r\n" 
					"\tif (JNode::v_str != value->vt || !Convert(value->pcstr, &rgAltEntry->pwszRfc822Name))\r\n"
					"\t{\r\n"
					"\t\treturn FALSE;\r\n"
					"\t}\r\n"
					"\trgAltEntry->dwAltNameChoice = CERT_ALT_NAME_%hs;\r\n"
					"\tbreak;\r\n", HashString(value->name), value->name, value->name);
			}
		} while (rgAltEntry++, value = value->next);

		return !cert->SetAltName(&ani);
	}

	return FALSE;
}

HRESULT Sign(_Inout_ CERT_BUID* cert, _In_ PWSTR IssuerPfx, _In_ PWSTR IssuerPassword, _In_opt_ NCRYPT_KEY_HANDLE hKey)
{
	HRESULT hr;

	if (hKey)
	{
		// root cert
		if (NOERROR == (hr = cert->SetIssuer()))
		{
			hr = cert->Sign(hKey);
		}

		return hr;
	}

	PCCERT_CONTEXT pCertContext;

	if ('>' != *IssuerPfx)
	{
		// signer in PFX
		if (NOERROR == (hr = PFXImport(IssuerPfx, IssuerPassword, &hKey, &pCertContext)))
		{
			if (NOERROR == (hr = cert->SetIssuer(pCertContext->pCertInfo)))
			{
				hr = cert->Sign(hKey);
			}
			CertFreeCertificateContext(pCertContext);
		}

		return hr;
	}

	// signer in store (">MY:M|U*hash")

	if (PWSTR pwz = wcschr(++IssuerPfx, ':'))
	{
		*pwz++ = 0;

		ULONG cch = (ULONG)wcslen(IssuerPassword);
		CRYPT_HASH_BLOB chb = { (1 + cch) * sizeof(WCHAR), (PBYTE)IssuerPassword };

		ULONG dwFlags;

		if (NOERROR == (hr = GetStoreFlags(pwz, &dwFlags)) && 
			HR(hr, CryptStringToBinaryW(IssuerPassword, cch, CRYPT_STRING_HEX, 
			chb.pbData, &chb.cbData, 0, 0)))
		{
			if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, dwFlags, IssuerPfx)))
			{
				pCertContext = HR(hr, CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &chb, 0));
				CertCloseStore(hCertStore, 0);
				if (pCertContext)
				{
					DWORD dwKeySpec;
					BOOL fCallerFreeProvOrNCryptKey;

					if (HR(hr, CryptAcquireCertificatePrivateKey(pCertContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, 
						0, &hKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey)))
					{
						if (NOERROR == (hr = cert->SetIssuer(pCertContext->pCertInfo)))
						{
							hr = cert->Sign(hKey);
						}

						if (fCallerFreeProvOrNCryptKey)
						{
							if (CERT_NCRYPT_KEY_SPEC == dwKeySpec)
							{
								NCryptFreeObject(hKey);
							}
							else
							{
								CryptReleaseContext(hKey, 0);
							}
						}
					}

					CertFreeCertificateContext(pCertContext);
				}
			}
		}

		return hr;
	}

	return E_INVALIDARG;
}

BOOLEAN ccep(JNode* value)
{
	enum { 
		e_Subject, e_Alg, e_Pfx, e_Days, e_Issuer, e_Cert, e_CA, 
		e_Template, e_Policy, e_Usage, e_EnUsage, e_BC, e_Name, e_count 
	};
	LONG flags = (1 << e_count) - 1;
	ULONG nDays;
	PWSTR IssuerPfx = 0, IssuerPassword = 0;
	PWSTR Pfx = 0, Password = 0, pszCert = 0;
	PWSTR pszAlgId = 0, pszSubjectName = 0, pwszKeyName = 0;
	BYTE KeyUsage;
	ULONG dwKeyFlags = 0;

	CERT_EXTENSION Extensions[16];
	CERT_BUID cert(_countof(Extensions), Extensions);

	do
	{
		switch (HashString(value->name))
		{
		case 0x27e9041c: // Subject
			if (!_bittestandreset(&flags, e_Subject) || JNode::v_str != value->vt || 
				!Convert(value->pcstr, &pszSubjectName) ||
				cert.SetSubjectName(pszSubjectName)) return FALSE;
			break;

		case 0x000109ca: // Alg
			if (!_bittestandreset(&flags, e_Alg) || JNode::v_str != value->vt || 
				!Convert(value->pcstr, &pszAlgId)) return FALSE;

			// "alg[:keyname:M|U]"
			if (pwszKeyName = wcschr(pszAlgId, ':'))
			{
				*pwszKeyName++ = 0;
				if (PWSTR pwz = wcsrchr(pwszKeyName, ':'))
				{
					*pwz++ = 0;

					switch (*pwz)
					{
					case 'M':
						dwKeyFlags = NCRYPT_MACHINE_KEY_FLAG;
						break;
					case 'U':
						dwKeyFlags = 0;
						break;
					default:
						return FALSE;
					}
					if (*++pwz)
					{
						return FALSE;
					}
				}
			}
			break;

		case 0x0001508e: // Pfx
			if (!_bittestandreset(&flags, e_Pfx) || JNode::v_str != value->vt || 
				!Convert(value->pcstr, &Pfx, &Password)) return FALSE;
			break;

		case 0x00256000: // Cert
			if (!_bittestandreset(&flags, e_Cert) || JNode::v_str != value->vt || 
				!Convert(value->pcstr, &pszCert)) return FALSE;
			break;

		case 0x0024c4cf: // Days
			if (!_bittestandreset(&flags, e_Days) || JNode::v_int != value->vt ||
				!(nDays = (ULONG)value->iVal)) return FALSE;

			cert.SetDays(nDays);
			break;

		case 0xa497f38b: // Issuer
			if (!_bittestandreset(&flags, e_Issuer) || JNode::v_str != value->vt || 
				!Convert(value->pcstr, &IssuerPfx, &IssuerPassword)) return FALSE;
			break;

		case 0x000008e2: // CA
			if (!_bittestandreset(&flags, e_CA) || JNode::v_obj != value->vt ||
				!SetCA(&cert, value->first)) return FALSE;
			break;

		case 0xcf712050: // Template
			if (!_bittestandreset(&flags, e_Template) || JNode::v_arr != value->vt ||
				!SetTemplate(&cert, value->first)) return FALSE;
			break;

		case 0xb996aac0: // Policy
			if (!_bittestandreset(&flags, e_Policy) || JNode::v_arr != value->vt ||
				!SetPolicy(&cert, value->first)) return FALSE;
			break;

		case 0x05c4cc05: // Usage
			if (!_bittestandreset(&flags, e_Usage) || JNode::v_arr != value->vt ||
				!ParseUsage(value->first, &KeyUsage) || cert.SetKeyUsage(KeyUsage)) return FALSE;
			break;

		case 0xea1651ee: // EnUsage
			if (!_bittestandreset(&flags, e_EnUsage) || JNode::v_arr != value->vt ||
				!SetEnKeyUsage(&cert, value->first)) return FALSE;
			break;

		case 0x000008c1: // BC
			if (!_bittestandreset(&flags, e_BC) || JNode::v_arr != value->vt ||
				!SetBC(&cert, value->first)) return FALSE;
			break;

		case 0x002c5c07: // Name
			if (!_bittestandreset(&flags, e_Name) || JNode::v_obj != value->vt ||
				!SetAltName(&cert, value->first)) return FALSE;
			break;

		default:
			if (IsOIDString(value->name))
			{
				if (JNode::v_str != value->vt)
				{
					return FALSE;
				}

				DATA_BLOB db = { 1 + (ULONG)strlen(value->pcstr), (PBYTE)value->pcstr };

				if (!CryptStringToBinaryA(value->pcstr, db.cbData - 1, CRYPT_STRING_HEX, 
					db.pbData, &db.cbData, 0, 0) || cert.AddExtension(value->name, &db, FALSE, X509_OCTET_STRING))
				{
					return FALSE;
				}
			}
			else
			{
				DebugCasePrint(value->name);
			}
		}
	} while (value = value->next);

	if (flags & ((1 << e_Issuer) - 1))
	{
		return FALSE;
	}

	HRESULT hr;
	NCRYPT_KEY_HANDLE hKey;
	if (NOERROR == (hr = CreateKey(&hKey, pszAlgId, pwszKeyName, dwKeyFlags, wcscmp(BCRYPT_RSA_ALGORITHM, pszAlgId) ? 0 : 2048)))
	{
		if (NOERROR == (hr = cert.SetSerial()) &&
			NOERROR == (hr = cert.SetPublicKey(hKey)) &&
			NOERROR == (hr = Sign(&cert, IssuerPfx, IssuerPassword, _bittest(&flags, e_Issuer) ? hKey : 0)))
		{
			if (pwszKeyName)
			{
				ULONG dwStoreFlags;
				if (NOERROR == (hr = GetStoreFlags(Password, &dwStoreFlags)))
				{
					hr = AddEncodedCertificateToStore(cert.pbCertEncoded(), cert.cbCertEncoded(), 
						dwStoreFlags, Pfx, pwszKeyName, dwKeyFlags);
				}
			}
			else
			{
				hr = ExportToPfx(Pfx, hKey, Password, cert.pbCertEncoded(), cert.cbCertEncoded());
			}

			if (NOERROR == hr)
			{
				DumpHash(cert.pbCertEncoded(), cert.cbCertEncoded());

				if (!_bittest(&flags, e_Cert))
				{
					hr = SaveToFile(pszCert, cert.pbCertEncoded(), cert.cbCertEncoded());
					ShowCert(0, cert.pbCertEncoded(), cert.cbCertEncoded(), pszSubjectName);
				}
			}
		}

		NCryptFreeObject(hKey);
	}

	if (hr)
	{
		LogError("::", hr);
	}

	return NOERROR == hr;
}

HRESULT ccep()
{
	if (PWSTR pszJson = wcschr(GetCommandLineW(), '*'))
	{
		PBYTE pb;
		ULONG cb;
		HRESULT hr;
		if (0 <= (hr = ReadFromFile(pszJson + 1, &pb, &cb)))
		{
			hr = STATUS_BAD_DATA;

			JHeap1 heap(8*cb);
			RTL_FRAME<JHeapPtr>  ptr{ &heap };

			JNode top_value;
			if (top_value.DoParse((PSTR)pb, (PSTR)pb + cb) && JNode::v_obj == top_value.vt)
			{
				ULONG nOP = heap.m_nOP;

				if (JNode* value = top_value.first)
				{
					hr = ccep(value) ? NOERROR : STATUS_BAD_DATA;
				}

				heap.m_nOP = nOP;
			}
			LocalFree(pb);
		}

		return hr;
	}

	return STATUS_INVALID_PARAMETER_1;
}

void NTAPI ep(void*)
{
	_G_noTimePrefix = TRUE;
	InitLog(L"cert-build.log");
	HRESULT hr = ccep();
	if (hr)
	{
		LogError(">>", hr);
	}
	DestroyLog();
	if (hr) ShowLogInNotepad(L"cert-build.log");
	ExitProcess(hr);
}

_NT_END