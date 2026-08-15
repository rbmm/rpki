#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "aik.h"

void ShowCert(HWND hwnd, PCCERT_CONTEXT pCertContext, PCWSTR szTitle)
{
	CRYPTUI_VIEWCERTIFICATE_STRUCTW cvi = {
		sizeof(cvi), hwnd, CRYPTUI_DISABLE_ADDTOSTORE | CRYPTUI_DISABLE_EDITPROPERTIES, szTitle, pCertContext
	};

	BOOL b;
	CryptUIDlgViewCertificateW(&cvi, &b);
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dvre/76747b5c-06c2-4c73-9207-8ebb6ee891ea
// 1.2.840.113556.1.5.284.2
// The server MUST generate a globally unique identifier (GUID) and include it as the value.
#define szOID_DEVICE_GUID	"1.2.840.113556.1.5.284.2"

HRESULT CheckUserCert()
{
	HRESULT hr;
	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0,
		CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_CURRENT_USER, L"My")))
	{
		PCCERT_CONTEXT pCertContext = 0;

		UCHAR MachineGuid[16];

		BOOL bGuidInit = FALSE;

		while (pCertContext = HR(hr, CertEnumCertificatesInStore(hCertStore, pCertContext)))
		{
			PCERT_INFO pCertInfo = pCertContext->pCertInfo;
			if (PCERT_EXTENSION pExt = CertFindExtension(szOID_DEVICE_GUID,
				pCertInfo->cExtension, pCertInfo->rgExtension))
			{
				union {
					CRYPT_DATA_BLOB db_guid;
					UCHAR buf[sizeof(CRYPT_DATA_BLOB) + sizeof(GUID)];
				};
				ULONG cb = sizeof(buf);
				if (CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OCTET_STRING,
					pExt->Value.pbData, pExt->Value.cbData, 0, 0, &db_guid, &cb))
				{
					if (sizeof(GUID) == db_guid.cbData)
					{
						if (!bGuidInit)
						{
							bGuidInit = 0 <= GetMachineUID(MachineGuid, sizeof(MachineGuid));
						}
						if (bGuidInit && !memcmp(MachineGuid, db_guid.pbData, sizeof(GUID)))
						{
							ShowCert(0, pCertContext, L"User Certificate");
							CertFreeCertificateContext(pCertContext);
							break;
						}
					}
				}
			}
		}

		CertCloseStore(hCertStore, 0);
	}

	return hr;
}

PCWSTR GetPortName();

HRESULT RunNormal()
{
	switch (HRESULT hr = CheckUserCert())
	{
	default:
		LogError("CheckUserCert", hr);
		return hr;
	case NOERROR:
		return NOERROR;
	case CRYPT_E_NOT_FOUND:
		UNICODE_STRING ObjectName;
		RtlInitUnicodeString(&ObjectName, GetPortName());
		HANDLE hPort;
		ULONG mml;
		SECURITY_QUALITY_OF_SERVICE sqos = { sizeof(sqos), SecurityImpersonation };
		switch (hr = NtConnectPort(&hPort, &ObjectName, &sqos, 0, 0, &mml, 0, 0))
		{
		case STATUS_PORT_CONNECTION_REFUSED:
			DbgPrint("----- request send -----\r\n");
			return NOERROR;
		default:
			return hr;
		}
		break;
	}
}

_NT_END