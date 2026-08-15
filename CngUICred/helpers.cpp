#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "helpers.h"

HRESULT RtlStringToCom(_In_ PCUNICODE_STRING str, _Out_ PWSTR *ppsz)
{
	*ppsz = 0;

	if (ULONG Length = str->Length)
	{
		if (PWSTR psz = (PWSTR)CoTaskMemAlloc(Length + sizeof(WCHAR)))
		{
			memcpy(psz, str->Buffer, Length);
			*(PWSTR)RtlOffsetToPointer(psz, Length) = 0;
			*ppsz = psz;
			return S_OK;
		}

		return E_OUTOFMEMORY;
	}

	return S_OK;
}

HRESULT CoSidToString(_In_ PSID Sid, _Out_ PWSTR *ppsz)
{
	UNICODE_STRING str;
	HRESULT hr = RtlConvertSidToUnicodeString(&str, Sid, TRUE);
	if (0 <= hr)
	{
		hr = RtlStringToCom(&str, ppsz);
		RtlFreeUnicodeString(&str);
	}

	return hr;
}

void Utf16To8::init(PCWSTR pcsz, ULONG cchWideChar)
{
	_str = 0;
	if (cchWideChar)
	{
		char* str = 0;
		ULONG cbMultiByte = 0;
		while (cbMultiByte = WideCharToMultiByte(CP_UTF8, 0, pcsz, cchWideChar, str, cbMultiByte, 0, 0))
		{
			if (str)
			{
				_str = str, str[cbMultiByte] = 0;
				return;
			}

			if (!(str = new char[cbMultiByte + 1]))
			{
				return;
			}
		}
		if (str) delete [] str;
	}
}

BOOL ifRegSz(PKEY_VALUE_PARTIAL_INFORMATION pkvpi)
{
	switch (pkvpi->Type)
	{
	case REG_SZ:
	case REG_EXPAND_SZ:
		ULONG DataLength = pkvpi->DataLength;
		return DataLength && !(DataLength & (sizeof(WCHAR) - 1));
	}
	return FALSE;
}

extern volatile const UCHAR guz = 0;

void DumpValue(HANDLE hKey, PCUNICODE_STRING ValueName)
{
	NTSTATUS status;
	union {
		PVOID buf;
		PKEY_VALUE_PARTIAL_INFORMATION pkvpi;
	};
	PVOID stack = alloca(guz);
	ULONG cb = 0, rcb = 0x80;
	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		status = ZwQueryValueKey(hKey, ValueName, KeyValuePartialInformation, buf, cb, &rcb);

	} while (STATUS_BUFFER_OVERFLOW == status);

	if (0 <= status && ifRegSz(pkvpi))
	{
		DbgPrint("\f \"%.*ws\"", pkvpi->DataLength / sizeof(WCHAR), pkvpi->Data);
	}
}

void PrintProviderInfo(const GUID *rgclsidProviders)
{
	DbgPrint("\f{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		rgclsidProviders->Data1, rgclsidProviders->Data2, rgclsidProviders->Data3,
		rgclsidProviders->Data4[0], rgclsidProviders->Data4[1], rgclsidProviders->Data4[2], rgclsidProviders->Data4[3], 
		rgclsidProviders->Data4[4], rgclsidProviders->Data4[5], rgclsidProviders->Data4[6], rgclsidProviders->Data4[7]);

	WCHAR buf[_countof("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{12345678-1234-1234-1234-1234567890AB}")];
	if (0 < swprintf_s(buf, _countof(buf),
		L"\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\CLSID\\{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}", 
		rgclsidProviders->Data1, rgclsidProviders->Data2, rgclsidProviders->Data3,
		rgclsidProviders->Data4[0], rgclsidProviders->Data4[1], rgclsidProviders->Data4[2], rgclsidProviders->Data4[3], 
		rgclsidProviders->Data4[4], rgclsidProviders->Data4[5], rgclsidProviders->Data4[6], rgclsidProviders->Data4[7]))
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		RtlInitUnicodeString(&ObjectName, buf);

		if (0 <= ZwOpenKey(&oa.RootDirectory, KEY_READ, &oa))
		{
			static const UNICODE_STRING Empty = {};

			DumpValue(oa.RootDirectory, &Empty);

			STATIC_UNICODE_STRING_(InProcServer32);

			HANDLE hKey;
			oa.ObjectName = const_cast<PUNICODE_STRING>(&InProcServer32);
			NTSTATUS status = ZwOpenKey(&hKey, KEY_READ, &oa);

			NtClose(oa.RootDirectory);

			if (0 <= status)
			{
				DumpValue(hKey, &Empty);
				NtClose(hKey);
			}
		}
	}
}

_NT_END