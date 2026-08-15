#pragma once

class Utf16To8
{
	PSTR _str = 0;

	void init(PCWSTR pcsz, ULONG cchWideChar);

public:
	~Utf16To8()
	{
		if (_str) delete [] _str;
	}

	Utf16To8(PCWSTR pcsz)
	{
		init(pcsz, pcsz ? (ULONG)wcslen(pcsz) : 0);
	}

	Utf16To8(PCUNICODE_STRING Name)
	{
		init(Name->Buffer, Name->Length / sizeof(WCHAR));
	}

};

C_ASSERT(sizeof(Utf16To8)==sizeof(PVOID));

void PrintProviderInfo(const GUID *rgclsidProviders);
HRESULT CoSidToString(_In_ PSID Sid, _Out_ PWSTR *ppsz);