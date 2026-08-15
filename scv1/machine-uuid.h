#pragma once

#define SHA1_DIGEST_SIZE 20

HRESULT GetMachineUID(_Out_ PBYTE pbId, _In_ ULONG cbId, _In_opt_ NCRYPT_PROV_HANDLE hProvider = 0);
HRESULT GetMachineUID(_Out_writes_z_(25) PWSTR buf, _In_ ULONG cch, _In_opt_ NCRYPT_PROV_HANDLE hProvider = 0);

