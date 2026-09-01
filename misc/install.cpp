#include "stdafx.h"

_NT_BEGIN

#include "log.h"

extern const WCHAR _G_szProvider[] = L"MKsp";

STDAPI DllUnregisterServer()
{
	HRESULT hr;

	if (HMODULE hmod = LoadLibraryExW(L"bcrypt.dll", 0, LOAD_LIBRARY_SEARCH_SYSTEM32))
	{
		union {
			PVOID __imp_BCryptUnregisterProvider;

			NTSTATUS (WINAPI * BCryptUnregisterProvider)(
				_In_ PCWSTR pszProvider
				);
		};

		if (__imp_BCryptUnregisterProvider = GetProcAddress(hmod, "BCryptUnregisterProvider"))
		{
			hr = BCryptUnregisterProvider(_G_szProvider);
		}
		else
		{
			hr = GetLastError();
		}

		FreeLibrary(hmod);
	}
	else
	{
		hr = GetLastError();
	}

	return HRESULT_FROM_WIN32(hr);
}

STDAPI DllRegisterServer()
{
	HRESULT hr;

	if (HMODULE hmod = LoadLibraryExW(L"bcrypt.dll", 0, LOAD_LIBRARY_SEARCH_SYSTEM32))
	{
		union {
			PVOID __imp_BCryptUnregisterProvider;

			NTSTATUS (WINAPI * BCryptRegisterProvider)(
				_In_ PCWSTR pszProvider,
				_In_ ULONG dwFlags,
				_In_ PCRYPT_PROVIDER_REG pReq
				);
		};

		if (__imp_BCryptUnregisterProvider = GetProcAddress(hmod, "BCryptRegisterProvider"))
		{
			static const PCWSTR szFunction = NCRYPT_KEY_STORAGE_ALGORITHM;

			static const CRYPT_INTERFACE_REG Interface { 
				NCRYPT_KEY_STORAGE_INTERFACE, 0, 1, const_cast<PWSTR*>(&szFunction) 
			};

			static const PCRYPT_INTERFACE_REG rgpInterfaces = const_cast<PCRYPT_INTERFACE_REG>(&Interface);

			static const CRYPT_IMAGE_REG UM = { 
				const_cast<PWSTR>(L"MKsp.dll"), 1, const_cast<PCRYPT_INTERFACE_REG*>(&rgpInterfaces) 
			};

			static const PCWSTR szAlias = L"MKsp v1";
			
			static const CRYPT_PROVIDER_REG cpr = { 
				1, const_cast<PWSTR*>(&szAlias), const_cast<CRYPT_IMAGE_REG*>(&UM)
			};

			hr = BCryptRegisterProvider(_G_szProvider, CRYPT_OVERWRITE, const_cast<CRYPT_PROVIDER_REG*>(&cpr));
		}
		else
		{
			hr = GetLastError();
		}

		FreeLibrary(hmod);
	}
	else
	{
		hr = GetLastError();
	}

	return HRESULT_FROM_WIN32(hr);
}

#include "../inc/initterm.h"

BOOLEAN WINAPI DllMain( HMODULE hmod, DWORD ul_reason_for_call, PVOID p)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hmod);
		LOG(Init());
		DbgPrint("ATTACH:%x %S\r\n", GetCurrentProcessId(), GetCommandLineW());
		initterm();
		break;

	case DLL_PROCESS_DETACH:
		destroyterm();
		DbgPrint("DETACH:%x %p\r\n", GetCurrentProcessId(), p);
		LOG(Destroy());
		break;
	}

	return TRUE;
}

_NT_END