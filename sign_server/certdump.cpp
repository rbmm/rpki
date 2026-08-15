#include "stdafx.h"

_NT_BEGIN
#include "../log/log.h"
#include "aux-ctx.h"
#include "decode.h"

typedef CONST UCHAR *PCUCHAR;
void TestDecode(PDATA_BLOB pdb);
void TestDecode(PCUCHAR pb, ULONG cb);
void ShowCert(HWND hwnd, PCCERT_CONTEXT pCertContext, PCWSTR szTitle);

HRESULT Verify_PKCS_10(PBYTE pb, ULONG cb);

inline HRESULT Verify_PKCS_10(BSTR request)
{
	Verify_PKCS_10(ToData(request));
}

inline HRESULT Verify_PKCS_10(PDATA_BLOB pdb)
{
	return Verify_PKCS_10(pdb->pbData, pdb->cbData);
}

PCSTR DumpOID_I(PCSTR prefix, PCSTR pszObjId, PCSTR suffix = "\r\n")
{
	if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, const_cast<PSTR>(pszObjId), 0))
	{
		DbgPrint("%hs%ws(%hs) [%ws, %ws]%hs", prefix, pcoi->pwszName, pcoi->pszOID, pcoi->pwszCNGAlgid, pcoi->pwszCNGExtraAlgid, suffix);
	}
	else
	{
		DbgPrint("%hs%hs%hs", prefix, pszObjId, suffix);
	}
	return pszObjId;
}

void DumpOID(PCSTR* ppszObjId)
{
	DumpOID_I(*ppszObjId, "\t\tOID= ");
}

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

void DumpHash(PUCHAR pb, ULONG cb, _In_ PCWSTR pwszCNGHashAlgid = BCRYPT_MD5_ALGORITHM)
{
	UCHAR hash[64];
	ULONG len = sizeof(hash);
	if (CryptHashCertificate2(pwszCNGHashAlgid, 0, 0, pb, cb, hash, &len))
	{
		DumpBytesInLine(hash, len, "\tHash: ");
	}
}

void DumpName(PCSTR pszObjId, DWORD dwValueType, PCERT_RDN_VALUE_BLOB Value, ULONG i = 0)
{
	if ('*' == *pszObjId)
	{
		DbgPrint("\t%hs: ", pszObjId + 1);
	}
	else
	{
		DumpOID_I("\t", pszObjId, ": ");
	}

	switch (dwValueType)
	{
	case CERT_RDN_UTF8_STRING:
		switch(i)
		{
		case 2:
			ACB::SetMachine((PCWSTR)Value->pbData);
			break;
		case 3:
			ACB::SetUser((PCWSTR)Value->pbData);
			break;
		}

	case CERT_RDN_UNICODE_STRING:
		DbgPrint("\f%.*ws\r\n", Value->cbData / sizeof(WCHAR), Value->pbData);
		break;

	case CERT_RDN_PRINTABLE_STRING:
	case CERT_RDN_IA5_STRING:
	case CERT_RDN_TELETEX_STRING:
		DbgPrint("\f%.*hs\r\n", Value->cbData, Value->pbData);
		break;

	default: __debugbreak();
	}
}

void DumpName(const CERT_NAME_BLOB* Name, PCWSTR msg)
{
	LogOutputNT(~0, msg);

	PCERT_NAME_INFO pcni;
	if (0 <= Decode(X509_NAME, Name->pbData, Name->cbData, &pcni))
	{
		if (DWORD cRDN = pcni->cRDN)
		{
			PCERT_RDN rgRDN = pcni->rgRDN;

			do 
			{
				if (DWORD cRDNAttr = rgRDN->cRDNAttr)
				{
					PCERT_RDN_ATTR rgRDNAttr = rgRDN->rgRDNAttr;
					do 
					{
						DumpName(rgRDNAttr->pszObjId, rgRDNAttr->dwValueType, &rgRDNAttr->Value);

					} while (rgRDNAttr++, --cRDNAttr);
				}
			} while (rgRDN++, --cRDN);
		}

		LocalFree(pcni);
	}
}

void DumpName(PCERT_OTHER_NAME pOtherName)
{
	PCERT_NAME_VALUE pcnv;

	if (0 <= Decode(X509_UNICODE_ANY_STRING, pOtherName->Value.pbData, pOtherName->Value.cbData, &pcnv))
	{
		DumpName(pOtherName->pszObjId, pcnv->dwValueType, &pcnv->Value);
		LocalFree(pcnv);
	}
}

void DumpAltName(PCERT_ALT_NAME_INFO NameInfo)
{
	DbgPrint("\tSUBJECT_ALT_NAME:\r\n");

	if (DWORD cAltEntry = NameInfo->cAltEntry)
	{
		PCERT_ALT_NAME_ENTRY rgAltEntry = NameInfo->rgAltEntry;
		do 
		{
			switch (rgAltEntry->dwAltNameChoice)
			{
			case CERT_ALT_NAME_OTHER_NAME:
				DumpName(rgAltEntry->pOtherName);
				break;

			case CERT_ALT_NAME_DNS_NAME:
			case CERT_ALT_NAME_RFC822_NAME:
			case CERT_ALT_NAME_URL:
				DbgPrint("\t%ws\r\n", rgAltEntry->pwszDNSName);
				break;
			case CERT_ALT_NAME_REGISTERED_ID:
				DbgPrint("\t%hs\r\n", rgAltEntry->pszRegisteredID);
				break;
			case CERT_ALT_NAME_DIRECTORY_NAME:
				DumpName(&rgAltEntry->DirectoryName, L"\tDIRECTORY_NAME:\r\n");
				break;
			}
		} while (rgAltEntry++, --cAltEntry);
	}
}

void DumpKeyUsage(PCRYPT_BIT_BLOB pcbb)
{
	DumpBytesInLine(pcbb->pbData, pcbb->cbData, "\tKEY_USAGE: ");
}

void DumpExchangedKeyUsage(PCERT_ENHKEY_USAGE EnKeyUsage)
{
	DbgPrint("\tENHANCED_KEY_USAGE:\r\n");
	if (DWORD cUsageIdentifier = EnKeyUsage->cUsageIdentifier)
	{
		PSTR *rgpszUsageIdentifier = EnKeyUsage->rgpszUsageIdentifier;
		do 
		{
			DumpOID_I("\t\t", *rgpszUsageIdentifier++);
		} while (--cUsageIdentifier);
	}
}

void DumpKeyId(PCRYPT_HASH_BLOB KeyId)
{
	DumpBytesInLine(KeyId->pbData, KeyId->cbData, "\tSUBJECT_KEY_IDENTIFIER: ");
}

void ProcessAnyName(PCERT_NAME_VALUE p)
{
	DumpName("*", p->dwValueType, &p->Value);
}

void ProcessAnyName2(PCERT_NAME_VALUE p, int i)
{
	PCSTR prefix = "*";
	switch(i)
	{
	case 2:
		prefix = "*MachineName";
		break;
	case 3:
		prefix = "*UserName";
		break;
	case 4:
		prefix = "*ProcessName";
		break;
	}
	DumpName(prefix, p->dwValueType, &p->Value, i);
}

void DumpTemplateV2(PCERT_TEMPLATE_EXT p)
{
	DbgPrint("\t%hs %u.%u.%u\r\n", p->pszObjId, p->dwMajorVersion, p->dwMinorVersion, p->fMinorVersion);
}

void DumpPolicyInfo(PCERT_POLICIES_INFO ppi)
{
	if (DWORD cPolicyInfo = ppi->cPolicyInfo)
	{
		CERT_POLICY_INFO *rgPolicyInfo = ppi->rgPolicyInfo;
		do 
		{
			DbgPrint("\tPolicyIdentifier=%hs\r\n", rgPolicyInfo->pszPolicyIdentifier);

			if (DWORD cPolicyQualifier = rgPolicyInfo->cPolicyQualifier)
			{
				CERT_POLICY_QUALIFIER_INFO *rgPolicyQualifier = rgPolicyInfo->rgPolicyQualifier;
				do 
				{
					DbgPrint("\t\tPolicyQualifierId=%hs\r\n", rgPolicyQualifier->pszPolicyQualifierId);

					PVOID pv;
					if (0 <= Decode(rgPolicyQualifier->pszPolicyQualifierId, &rgPolicyQualifier->Qualifier, &pv))
					{
						__nop();
					}
					else if (0 <= Decode(rgPolicyInfo->pszPolicyIdentifier, &rgPolicyQualifier->Qualifier, &pv))
					{
						__nop();
					}
					else 
					{
						TestDecode(&rgPolicyQualifier->Qualifier);
					}

				} while (rgPolicyQualifier++, --cPolicyQualifier);
			}
		} while (rgPolicyInfo++, --cPolicyInfo);
	}
}

void ProcessExtensionsI(DWORD cExtension, PCERT_EXTENSION rgExtension)
{
	if (cExtension)
	{
		do 
		{
			DbgPrint("\tEXTENSION %c:\r\n", rgExtension->fCritical ? '*' : ' ');

			PVOID pv;

			union {
				PVOID pvpfn;
				void (*pfn)(void*);
			};

			PCSTR pszObjId = DumpOID_I("\t", rgExtension->pszObjId);

			PCSTR lpszStructType = pszObjId;

			if (!strcmp(szOID_ENROLL_CERTTYPE_EXTENSION, pszObjId))
			{
				lpszStructType = X509_UNICODE_NAME_VALUE;
				pvpfn = ProcessAnyName;
			}
			else if (!strcmp(szOID_CERTIFICATE_TEMPLATE, pszObjId))
			{
				lpszStructType = X509_CERTIFICATE_TEMPLATE;
				pvpfn = DumpTemplateV2;
			}
			else if (!strcmp(szOID_APPLICATION_CERT_POLICIES, pszObjId))
			{
				lpszStructType = szOID_CERT_POLICIES;
				pvpfn = DumpPolicyInfo;
			}
			else if (!strcmp(szOID_SUBJECT_KEY_IDENTIFIER, pszObjId))
			{
				pvpfn = DumpKeyId;
			}
			else if (!strcmp(szOID_SUBJECT_ALT_NAME2, pszObjId))
			{
				pvpfn = DumpAltName;
			}
			else if (!strcmp(szOID_KEY_USAGE, pszObjId))
			{
				pvpfn = DumpKeyUsage;
			}
			else if (!strcmp(szOID_ENHANCED_KEY_USAGE, pszObjId))
			{
				pvpfn = DumpExchangedKeyUsage;
			}
			else
			{
				TestDecode(&rgExtension->Value);
				continue;
			}

			if (0 <= Decode(lpszStructType, &rgExtension->Value, &pv))
			{
				pfn(pv);
				LocalFree(pv);
			}

		} while (rgExtension++, --cExtension);
	}
}

void ProcessExtensions(PCERT_EXTENSIONS pExt)
{
	ProcessExtensionsI(pExt->cExtension, pExt->rgExtension);
}

void PrintclientId(ULONG* pi, int)
{
	DbgPrint("\tRequestClientInfoClientId=%x\r\n", *pi);
}

void ProcessCspName(PCRYPT_CSP_PROVIDER CSPProvider)
{
	DbgPrint("dwKeySpec=%x pwszProviderName=\"%ws\"\r\n", CSPProvider->dwKeySpec, CSPProvider->pwszProviderName);
	ACB::SetProviderName(CSPProvider->pwszProviderName);
}

void ProcessOsVersion(PCERT_NAME_VALUE p)
{
	switch (p->dwValueType)
	{
	case CERT_RDN_IA5_STRING:
		DbgPrint("\tOsVersion=%.*hs\r\n", p->Value.cbData, p->Value.pbData);
		break;
	default:
		DbgPrint("\t!! dwValueType=%x\r\n", p->dwValueType);
	}
}

void ProcessUPN(PCERT_NAME_VALUE p)
{
	switch (p->dwValueType)
	{
	case CERT_RDN_UTF8_STRING:
		DbgPrint("\tUPN=%ws\r\n", p->Value.pbData);
		ACB::SetUPN((PWSTR)p->Value.pbData);
		break;
	default:
		DbgPrint("\t!! dwValueType=%x\r\n", p->dwValueType);
	}
}

void ProcessClientInfo(PCRYPT_SEQUENCE_OF_ANY p)
{
	//SEQUENCE {
	//	clientId INTEGER,
	//	MachineName UTF8STRING,
	//	UserName UTF8STRING,
	//	ProcessName UTF8STRING
	//}

	if (DWORD cValue = p->cValue)
	{
		PCRYPT_DER_BLOB rgValue = p->rgValue;
		int i = 0;
		do 
		{
			PCSTR psz="";
			union {
				PVOID pvpfn;
				void (*pfn)(void*, int i);
			};
			switch (i++)
			{
			case 0: 
				psz = X509_INTEGER;
				pvpfn = PrintclientId;
				break;
			case 1: 
			case 2: 
			case 3: 
				psz = X509_UNICODE_NAME_VALUE;
				pvpfn = ProcessAnyName2;
				break;
			}
			PVOID pv;
			if (0 <= Decode(psz, rgValue->pbData, rgValue->cbData, &pv))
			{
				pfn(pv, i);
				LocalFree(pv);
			}
		} while (rgValue++, --cValue);
	}
}

void DumpEVP(PCRYPT_ENROLLMENT_NAME_VALUE_PAIR pcenvp)
{
	DbgPrint("\t\t{ \"%ws\" : \"%ws\" }\r\n", pcenvp->pwszName, pcenvp->pwszValue);
}

void ProcessKeyAttestationStatement(PCRYPT_DATA_BLOB p)
{
	ACB::SetKAS(p->pbData, p->cbData);
}

void DumpAttributes(DWORD cAttribute, PCRYPT_ATTRIBUTE rgAttribute)
{
	if (cAttribute)
	{
		do 
		{
			DumpOID_I("ATTR=", rgAttribute->pszObjId);

			if (DWORD cValue = rgAttribute->cValue)
			{
				PCRYPT_ATTR_BLOB rgValue = rgAttribute->rgValue;
				do 
				{
					PVOID pv;

					union {
						PVOID pvpfn;
						void (*pfn)(void*);
					};

					PCSTR pszObjId = rgAttribute->pszObjId, lpszStructType = pszObjId;

					if (!strcmp(pszObjId, szOID_OS_VERSION))
					{
						pvpfn = ProcessOsVersion;
						lpszStructType = X509_NAME_VALUE;
					}
					else if (!strcmp(pszObjId, szOID_NT_PRINCIPAL_NAME))
					{
						pvpfn = ProcessUPN;
						lpszStructType = X509_UNICODE_NAME_VALUE;
					}
					else if (!strcmp(pszObjId, szOID_ENROLL_EK_INFO))
					{
						// !! EKCert already in rgValue !!
						ACB::SetEKCert(rgValue->pbData, rgValue->cbData);
						continue;
					}
					else if (!strcmp(pszObjId, szOID_ENROLL_ATTESTATION_STATEMENT))
					{
						pvpfn = ProcessKeyAttestationStatement;
						lpszStructType = X509_OCTET_STRING;
					}
					else if (!strcmp(pszObjId, szOID_REQUEST_CLIENT_INFO))
					{
						pvpfn = ProcessClientInfo;
						lpszStructType = X509_SEQUENCE_OF_ANY;
					}
					else if (!strcmp(pszObjId, szOID_ENROLLMENT_CSP_PROVIDER))
					{
						pvpfn = ProcessCspName;
						lpszStructType = szOID_ENROLLMENT_CSP_PROVIDER;
					}
					else if (!strcmp(pszObjId, szOID_CERT_EXTENSIONS) ||
						!strcmp(pszObjId, szOID_RSA_certExtensions))
					{
						pvpfn = ProcessExtensions;
						lpszStructType = X509_EXTENSIONS;
					}
					else if (!strcmp(pszObjId, szOID_ENROLLMENT_NAME_VALUE_PAIR))
					{
						pvpfn = DumpEVP;
					}
					else if (!strcmp(pszObjId, szOID_PKCS_9_CONTENT_TYPE))
					{
						pvpfn = DumpOID;
						lpszStructType = X509_OBJECT_IDENTIFIER; // szOID_ECC_PUBLIC_KEY
					}
					else if (!strcmp(pszObjId, szOID_PKCS_9_MESSAGE_DIGEST))
					{
						pvpfn = DumpKeyId;
						lpszStructType = X509_OCTET_STRING; // szOID_SUBJECT_KEY_IDENTIFIER
					}
					else
					{
						DbgPrint("!! unknown attribute\n");
						TestDecode(rgValue);
						continue;
					}

					if (0 <= Decode(lpszStructType, rgValue, &pv))
					{
						pfn(pv);
						LocalFree(pv);
					}
				} while (rgValue++, --cValue);
			}

		} while (rgAttribute++, --cAttribute);
	}
}

void Dump(PCERT_REQUEST_INFO pcri)
{
	PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo = &pcri->SubjectPublicKeyInfo;

	DumpHash(SubjectPublicKeyInfo->PublicKey.pbData, SubjectPublicKeyInfo->PublicKey.cbData, BCRYPT_SHA1_ALGORITHM);

	DbgPrint("CERT_REQUEST_INFO: dwVersion=%x %hs\r\n", pcri->dwVersion, SubjectPublicKeyInfo->Algorithm.pszObjId);

	char buf[0x100];
	if (CertNameToStrA(X509_ASN_ENCODING, &pcri->Subject, CERT_X500_NAME_STR, buf, _countof(buf)))
	{
		DbgPrint("\t%hs\r\n", buf);
	}

	DumpAttributes(pcri->cAttribute, pcri->rgAttribute);
}

PBYTE rmemcpy(ULONG pad, PBYTE pb, PBYTE qb, ULONG cb)
{
	if (pad)
	{
		do 
		{
			*pb++ = 0;
		} while (--pad);
	}

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

ULONG GetSignatureLength(PCSTR AlgorithmParameter)
{
	if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P256))
	{
		return 0x20;
	}

	if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P384))
	{
		return 0x30;
	}

	if (!strcmp(AlgorithmParameter, szOID_ECC_CURVE_P521))
	{
		return 0x42;
	}

	return 0;
}

ULONG GetEccSigLen(PCERT_ECC_SIGNATURE peccsign)
{
	ULONG cb = __max(peccsign->r.cbData, peccsign->s.cbData);
	return cb > 32 ? cb > 48 ? cb > 66 ? 0 : 66 : 48 : 32;
}

HRESULT Verify_PKCS_10(PBYTE pb, ULONG cb)
{
	HRESULT hr;
	PCERT_REQUEST_INFO pcri;
	PCERT_SIGNED_CONTENT_INFO pcsci;

	if (0 <= (hr = Decode(X509_CERT, pb, cb, &pcsci)))
	{
		PSTR pszObjId = pcsci->SignatureAlgorithm.pszObjId;

		DumpOID_I("SignatureAlgorithm=", pszObjId);

		if (0 <= (hr = Decode(X509_CERT_REQUEST_TO_BE_SIGNED, 
			pcsci->ToBeSigned.pbData, pcsci->ToBeSigned.cbData, &pcri)))
		{
			BCRYPT_PKCS1_PADDING_INFO pi = { }, *ppi = &pi;
			ULONG dwFlags = BCRYPT_PAD_PKCS1;

			if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, 
				pcsci->SignatureAlgorithm.pszObjId, CRYPT_OID_PREFER_CNG_ALGID_FLAG|CRYPT_SIGN_ALG_OID_GROUP_ID))
			{
				pi.pszAlgId = pcoi->pwszCNGAlgid;

				BCRYPT_KEY_HANDLE hKey;

				if (HR(hr, CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pcri->SubjectPublicKeyInfo, CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG, 0, &hKey)))
				{
					UCHAR hash[64];
					ULONG len = sizeof(hash);

					if (HR(hr, CryptHashCertificate2(pi.pszAlgId, 0, 0, 
						pcsci->ToBeSigned.pbData, pcsci->ToBeSigned.cbData, hash, &len)))
					{
						if (pcoi->pwszCNGExtraAlgid &&
							!wcscmp(CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM, pcoi->pwszCNGExtraAlgid))
						{
							ULONG Length = 0;
							if (pcsci->SignatureAlgorithm.Parameters.cbData)
							{
								PCSTR *ppszObjId;
								if (0 <= (hr = Decode(X509_OBJECT_IDENTIFIER, &pcsci->SignatureAlgorithm.Parameters, &ppszObjId)))
								{
									DumpOID_I("Parameters=", *ppszObjId);
									Length = GetSignatureLength(*ppszObjId);
									LocalFree(ppszObjId);
								}
							}

							dwFlags = 0, ppi = 0;
							PCERT_ECC_SIGNATURE ecc_sign;
							if (0 <= (hr = Decode(X509_ECC_SIGNATURE, &pcsci->Signature, &ecc_sign)))
							{
								if (!Length)
								{
									Length = GetEccSigLen(ecc_sign);
								}
								if (ecc_sign->r.cbData <= Length && ecc_sign->s.cbData <= Length)
								{
									rmemcpy(Length - ecc_sign->s.cbData, rmemcpy(Length - ecc_sign->r.cbData,
										pcsci->Signature.pbData = (BYTE*)alloca(pcsci->Signature.cbData = 2 *Length), 
										ecc_sign->r.pbData, ecc_sign->r.cbData), 
										ecc_sign->s.pbData, ecc_sign->s.cbData);
								}

								LocalFree(ecc_sign);
							}
						}

						hr = BCryptVerifySignature(hKey, ppi, hash, len, 
							pcsci->Signature.pbData, pcsci->Signature.cbData, dwFlags);

						DbgPrint("VerifySignature = %x\r\n", hr);

						if (0 <= hr)
						{
							ACB::SetPublicKey(&pcri->SubjectPublicKeyInfo);

							Dump(pcri);
						}
					}

					BCryptDestroyKey(hKey);
				}
			}

			LocalFree(pcri);
		}

		LocalFree(pcsci);
	}

	return hr;
}

//////////////////////////////////////////////////////////////////////////

void DumpCMC_DATA(PCMC_DATA_INFO pcmc)
{
	if (DWORD cTaggedAttribute = pcmc->cTaggedAttribute)
	{
		PCMC_TAGGED_ATTRIBUTE rgTaggedAttribute = pcmc->rgTaggedAttribute;

		do 
		{
			DbgPrint("dwBodyPartID=%x\r\n", rgTaggedAttribute->dwBodyPartID); 
			DumpOID_I("OID=", rgTaggedAttribute->Attribute.pszObjId);

			if (!strcmp(szOID_CMC_ADD_ATTRIBUTES, rgTaggedAttribute->Attribute.pszObjId))
			{
				if (ULONG cValue = rgTaggedAttribute->Attribute.cValue)
				{
					PCRYPT_ATTR_BLOB rgValue = rgTaggedAttribute->Attribute.rgValue;

					do 
					{
						PCMC_ADD_ATTRIBUTES_INFO paa;
						if (0 <= Decode(CMC_ADD_ATTRIBUTES, rgValue, &paa))
						{
							DbgPrint("dwCmcDataReference=%x cCertReference=%x\n", paa->dwCmcDataReference, paa->cCertReference);

							DumpAttributes(paa->cAttribute, paa->rgAttribute);

							LocalFree(paa);
						}

					} while (rgValue++, --cValue);
				}
			}

		} while (rgTaggedAttribute++, --cTaggedAttribute);
	}

	if (DWORD cTaggedRequest = pcmc->cTaggedRequest)
	{
		PCMC_TAGGED_REQUEST rgTaggedRequest = pcmc->rgTaggedRequest;
		do 
		{
			if (CMC_TAGGED_CERT_REQUEST_CHOICE == rgTaggedRequest->dwTaggedRequestChoice)
			{
				PCMC_TAGGED_CERT_REQUEST pTaggedCertRequest = rgTaggedRequest->pTaggedCertRequest;

				DbgPrint("dwBodyPartID=%x\n", pTaggedCertRequest->dwBodyPartID);

				Verify_PKCS_10(&pTaggedCertRequest->SignedCertRequest);
			}

		} while (rgTaggedRequest++, --cTaggedRequest);
	}
}

void Dump_PKCS_7(PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY p)
{
	union {
		PCRYPT_CONTENT_INFO pci;
		PULONG pu;
		PCERT_NAME_VALUE pcnv;
	};

	if (DWORD cValue = p->cValue)
	{
		PCRYPT_DER_BLOB rgValue = p->rgValue;
		PDATA_BLOB pdb;

		ULONG i = 0;
		do 
		{
			switch (i++)
			{
			case 0:
				if (0 <= Decode(X509_INTEGER, rgValue, &pu))
				{
					DbgPrint("\tCMSVersion=%x\r\n", *pu);
					LocalFree(pu);
				}
				break;
			case 1:
				break;
			case 3:
				if (0 <= Decode(X509_NAME_VALUE, rgValue, &pcnv))
				{
					switch (pcnv->dwValueType)
					{
					case CERT_RDN_ENCODED_BLOB:
						TestDecode(&pcnv->Value);
						break;
					default:
						DbgPrint("\t!! dwValueType=%x\n", pcnv->dwValueType);
					}
					LocalFree(pcnv);
				}
				break;
			default:
				TestDecode(rgValue);
				break;
			case 2:
				if (0 <= Decode(PKCS_CONTENT_INFO, rgValue, &pci))
				{
					DumpOID_I("\tOID=", pci->pszObjId);

					if (!strcmp(pci->pszObjId, szOID_CT_PKI_DATA) ||
						!strcmp(pci->pszObjId, szOID_PKCS_7_DATA))
					{
						PCMC_DATA_INFO pcmc;

						if (0 <= Decode(X509_OCTET_STRING, &pci->Content, &pdb))
						{
							if (0 <= Decode(CMC_DATA, pdb, &pcmc))
							{
								DumpCMC_DATA(pcmc);
								LocalFree(pcmc);
							}
							else
							{
								Verify_PKCS_10(pdb->pbData, pdb->cbData);
							}
							LocalFree(pdb);
						}
					}

					LocalFree(pci);
				}
				break;
			}

		} while (rgValue++, --cValue);
	}
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, 
					 _In_ PCERT_CHAIN_PARA pChainPara,
					 _Out_opt_ PCCERT_CHAIN_CONTEXT* ppChainContext = 0)
{
	PCCERT_CHAIN_CONTEXT pChainContext = 0;

	HRESULT hr;

	if (HR(hr, CertGetCertificateChain(HCCE_LOCAL_MACHINE, pCertContext, 0, 0, pChainPara, 
		CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, 0, &pChainContext)))
	{
		CERT_CHAIN_POLICY_PARA PolicyPara = { sizeof(PolicyPara) };
		CERT_CHAIN_POLICY_STATUS PolicyStatus = { sizeof(PolicyStatus) };

		//CERT_CHAIN_POLICY_NT_AUTH
		if (HR(hr, CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, pChainContext, &PolicyPara, &PolicyStatus)))
		{
			if (CRYPT_E_REVOCATION_OFFLINE == (hr = PolicyStatus.dwError))
			{
				hr = S_OK;
			}
		}

		if (0 <= hr && ppChainContext)
		{
			*ppChainContext = pChainContext;
		}
		else
		{
			CertFreeCertificateChain(pChainContext);
		}
	}

	ShowCert(0, pCertContext, L"EkCert");

	return LogError("VerifyCertificate", hr);
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext, _In_ PCSTR szUsageIdentifier)
{
	CERT_CHAIN_PARA ChainPara = { 
		sizeof(ChainPara), { USAGE_MATCH_TYPE_AND, { 1, const_cast<PSTR*>(&szUsageIdentifier) } } 
	};

	return ValidateCert(pCertContext, &ChainPara);
}

ULONG ValidateSign(_In_ HCRYPTMSG hCryptMsg, _Inout_ PCMSG_CTRL_VERIFY_SIGNATURE_EX_PARA pcvs, _In_ PCSTR szUsageIdentifier)
{
	HRESULT hr;
	PBYTE pbCertEncoded = 0;
	ULONG cbCertEncoded = 0;

	ULONG dwIndex = --(pcvs->dwSignerIndex);

	while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CERT_PARAM, dwIndex, pbCertEncoded, &cbCertEncoded)))
	{
		if (pbCertEncoded)
		{
			if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(CRYPT_ASN_ENCODING, pbCertEncoded, cbCertEncoded))
			{
				pcvs->pvSigner = const_cast<PCERT_CONTEXT>(pCertContext);

				if (HR(hr, CryptMsgControl(hCryptMsg, 0, CMSG_CTRL_VERIFY_SIGNATURE_EX, pcvs)))
				{
					hr = ValidateCert(pCertContext, szUsageIdentifier);
				}

				CertFreeCertificateContext(pCertContext);
			}

			break;
		}

		pbCertEncoded = (PBYTE)alloca(cbCertEncoded);
	}

	return hr;
}

HRESULT GetMsgType(_In_ HCRYPTMSG hCryptMsg, _Out_ PULONG dwMsgType)
{
	ULONG cb = sizeof(ULONG);

	return CryptMsgGetParam(hCryptMsg, CMSG_TYPE_PARAM, 0, dwMsgType, &cb) ? S_OK : GetLastHr();
}

HRESULT IsSignedMessage(HCRYPTMSG hCryptMsg)
{
	ULONG dwMsgType;

	HRESULT hr = GetMsgType(hCryptMsg, &dwMsgType);

	if (0 <= hr)
	{
		return dwMsgType == CMSG_SIGNED ? S_OK : HRESULT_FROM_NT(STATUS_OBJECT_TYPE_MISMATCH);
	}

	return hr;
}

HRESULT GetAttrs(HCRYPTMSG hCryptMsg, DWORD dwSignerIndex)
{
	HRESULT hr;
	ULONG cb = 0;
	union {
		PBYTE pb = 0;
		PCRYPT_ATTRIBUTES pca;
	};
	while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_SIGNER_AUTH_ATTR_PARAM, dwSignerIndex, pb, &cb)))
	{
		if (pb)
		{
			DumpAttributes(pca->cAttr, pca->rgAttr);
			break;
		}

		pb = (PBYTE)alloca(cb);
	}

	return hr;
}

HRESULT VerifyCMC(const BYTE* pbEncodedBlob, ULONG cbEncodedBlob, _In_ PCSTR szUsageIdentifier)
{
	HRESULT hr;
	if (HCRYPTMSG hCryptMsg = HR(hr, CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0)))
	{
		if (HR(hr, CryptMsgUpdate(hCryptMsg, pbEncodedBlob, cbEncodedBlob, TRUE)))
		{
			if (NOERROR == (hr = IsSignedMessage(hCryptMsg)))
			{
				CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA cvs = { sizeof(cvs), 0, 0, CMSG_VERIFY_SIGNER_CERT };

				ULONG cb;

				if (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CERT_COUNT_PARAM, 0, &cvs.dwSignerIndex, &(cb = sizeof(ULONG)))))
				{
					hr = ERROR_NOT_FOUND;

					if (cvs.dwSignerIndex)
					{
						do 
						{
							if (NOERROR == (hr = ValidateSign(hCryptMsg, &cvs, szUsageIdentifier)))
							{
								PBYTE pb = 0;
								cb = 0;

								while (HR(hr, CryptMsgGetParam(hCryptMsg, CMSG_CONTENT_PARAM, 0, pb, &cb)))
								{
									if (pb)
									{
										Verify_PKCS_10(pb, cb);
										GetAttrs(hCryptMsg, cvs.dwSignerIndex);
										break;
									}

									pb = (PBYTE)alloca(cb);
								}

								break;
							}

						} while (cvs.dwSignerIndex);
					}
				}
			}
		}

		CryptMsgClose(hCryptMsg);
	}

	return hr;
}

void DumpCMC(const BYTE* pbEncodedBlob, ULONG cbEncodedBlob)
{
	VerifyCMC(pbEncodedBlob, cbEncodedBlob, szOID_ENROLLMENT_AGENT);
	PCRYPT_CONTENT_INFO_SEQUENCE_OF_ANY p;

	if (0 <= Decode(PKCS_CONTENT_INFO_SEQUENCE_OF_ANY, pbEncodedBlob, cbEncodedBlob, &p))
	{
		DumpOID_I("OID= ", p->pszObjId);

		if (!strcmp(p->pszObjId, szOID_PKCS_7_SIGNED))// == szOID_RSA_signedData
		{
			Dump_PKCS_7(p);
		}

		LocalFree(p);
	}
}

_NT_END