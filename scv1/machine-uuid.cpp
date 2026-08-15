#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "machine-uuid.h"

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
	return GetLastHresult(CryptBinaryToStringW(hash, sizeof(hash), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buf, &cch));
}

_NT_END