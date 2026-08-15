#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../qi/dump.h"
#include "Provider.h"
#include "WrappedCred.h"
#include "helpers.h"

ULONG GetSecondsSinceLoad();

void* CSampleProvider::operator new(size_t size, const MyAndWrappedGuids* pGuids)
{
	if (PVOID pv = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size))
	{
		if (reinterpret_cast<CSampleProvider*>(pv)->Init(pGuids))
		{
			return pv;
		}
		HeapFree(GetProcessHeap(), 0, pv);
	}

	return 0;
}

void CSampleProvider::operator delete(PVOID pv)
{
	HeapFree(GetProcessHeap(), 0, pv);
}

BEGIN_QI_MAP(CSampleProvider)
	IE2(IUnknown, ICredentialProvider),
	IE(ICredentialProvider),
	IE(ICredentialProviderSetUserArray),
	IE(IAutoLogonProvider),
	IE(ICredentialProviderWithDisplayState),
	IE(ICredentialProviderWithSessionContext)
END_QI_MAP(CSampleProvider)

HRESULT GetCngUI(_Out_ ICredentialProvider** ppcp, _Out_ HMODULE* phmod);

bool CSampleProvider::Init(const MyAndWrappedGuids* pGuids)
{
	_pGuids = pGuids;
	return 0 <= GetCngUI(&_pWrappedProvider, &_M_hmod);
}

CSampleProvider::~CSampleProvider()
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);

	if (_M_pszContext) CoTaskMemFree(_M_pszContext);
	if (_pWrappedProvider) _pWrappedProvider->Release();
	if (_M_hmod) FreeLibrary(_M_hmod);

	DllRelease();
}

CSampleProvider::CSampleProvider()
{
	DllAddRef();
	DbgPrint("[%u]:%hs<%p>{%02X}\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, _pGuids->clsidCredentialProvider->Data4[7]);
}

ULONG STDMETHODCALLTYPE CSampleProvider::AddRef()
{
	return InterlockedIncrementNoFence(&_cRef);
}

ULONG STDMETHODCALLTYPE CSampleProvider::Release()
{
	if (LONG cRef = InterlockedDecrement(&_cRef))
	{
		return cRef;
	}
	delete this;
	return 0;
}

HRESULT STDMETHODCALLTYPE CSampleProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags)
{
	HRESULT hr = _pWrappedProvider->SetUsageScenario(cpus, dwFlags);
	
	DbgPrint("[%u]:%hs<%p>(%X, %X) = %X\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, cpus, dwFlags, hr);

	if (0 > hr)
	{
		return hr;
	}

	_cpus = cpus, _dwFlags = dwFlags;

	return S_OK;
}

void Dump(const BYTE* pb, ULONG cb);

HRESULT STDMETHODCALLTYPE CSampleProvider::SetSerialization(
	__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
	)
{
	DbgPrint("[%u]:%hs<%p>(%08X {%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}\r\n", 
		GetSecondsSinceLoad(), __FUNCTION__, this, pcpcs->ulAuthenticationPackage,
		pcpcs->clsidCredentialProvider.Data1,
		pcpcs->clsidCredentialProvider.Data2,
		pcpcs->clsidCredentialProvider.Data3,
		pcpcs->clsidCredentialProvider.Data4[0],
		pcpcs->clsidCredentialProvider.Data4[1],
		pcpcs->clsidCredentialProvider.Data4[2],
		pcpcs->clsidCredentialProvider.Data4[3],
		pcpcs->clsidCredentialProvider.Data4[4],
		pcpcs->clsidCredentialProvider.Data4[5],
		pcpcs->clsidCredentialProvider.Data4[6],
		pcpcs->clsidCredentialProvider.Data4[7]
		);

	Dump(pcpcs->rgbSerialization, pcpcs->cbSerialization);

	if (CPUS_CREDUI == _cpus && CNG_CRED_UI_DATA::eAP == pcpcs->ulAuthenticationPackage )
	{
		if (sizeof(CNG_CRED_UI_DATA) <= pcpcs->cbSerialization )
		{
			CNG_CRED_UI_DATA* p = (CNG_CRED_UI_DATA*)pcpcs->rgbSerialization;
			if (sizeof(CNG_CRED_UI_DATA) == p->cbHeader)
			{
				switch (p->dwScenario)
				{
				case CNG_CREDUI_SCENARIO::Set:
					_bSet = TRUE;
				case CNG_CREDUI_SCENARIO::Get:
					if (pcpcs->cbSerialization == p->GetSize())
					{
						DbgPrint("CNG_CRED_UI_DATA {%x, %x, %x}\r\n", p->dwScenario, p->dwProtectionLevel, p->bCheckboxState);
						if (p->cchText && !p->szText[p->cchText - 1])
						{
							DbgPrint("CNG_CRED_UI_DATA: \"%ws\"\r\n", p->szText);
							_bMyKey = !wcscmp(L"SSO Authorization Key", p->szText);
						}
					}
					break;
				}
			}
		}
		//while (!IsDebuggerPresent()) { Sleep(1000);} __debugbreak();
	}

	return _pWrappedProvider->SetSerialization(pcpcs);
}

HRESULT STDMETHODCALLTYPE CSampleProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);
	return _pWrappedProvider->GetFieldDescriptorCount(pdwCount);
}

HRESULT STDMETHODCALLTYPE CSampleProvider::GetFieldDescriptorAt(
	DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
	//DbgPrint("[%u]:%hs<%p>(%x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwIndex);
	return _pWrappedProvider->GetFieldDescriptorAt(dwIndex, ppcpfd);
}

HRESULT STDMETHODCALLTYPE CSampleProvider::Advise(
	__in ICredentialProviderEvents* pcpe,
	__in UINT_PTR upAdviseContext
	)
{
	DbgPrint("[%u]:%hs<%p>(%p)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, upAdviseContext);
	return _pWrappedProvider->Advise(pcpe, upAdviseContext);
}

HRESULT STDMETHODCALLTYPE CSampleProvider::UnAdvise()
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);
	return _pWrappedProvider->UnAdvise();
}

HRESULT STDMETHODCALLTYPE CSampleProvider::GetCredentialCount(
	__out DWORD* pdwCount,
	__out_range(<,*pdwCount) DWORD* pdwDefault,
	__out BOOL* pbAutoLogonWithDefault
	)
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);

	if (_bMyKey)
	{
		*pdwCount = 1;
		*pdwDefault = 0;
		*pbAutoLogonWithDefault = FALSE;
		return S_OK;
	}

	return _pWrappedProvider->GetCredentialCount(pdwCount, pdwDefault, pbAutoLogonWithDefault);
}

HRESULT STDMETHODCALLTYPE CSampleProvider::GetCredentialAt(
	__in DWORD dwIndex, 
	__in ICredentialProviderCredential** ppcpc
	)
{
	DbgPrint("[%u]:%hs<%p>(%x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwIndex);

	if (_bMyKey)
	{
		if (CWrapperCredential* pMycpc = new CWrapperCredential(this, _bSet))
		{			
			*ppcpc = pMycpc;
			return S_OK;
		}

		return E_OUTOFMEMORY;
	}

	return _pWrappedProvider->GetCredentialAt(dwIndex, ppcpc);
}

HRESULT STDMETHODCALLTYPE CSampleProvider::SetUserArray(_In_ ICredentialProviderUserArray *users)
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);
	HRESULT hr = S_OK;
	ICredentialProviderSetUserArray* p;
	if (0 <= _pWrappedProvider->QueryInterface(IID_PPV_ARGS(&p)))
	{
		hr = p->SetUserArray(users);
		p->Release();
	}
	return hr;
}

HRESULT STDMETHODCALLTYPE CSampleProvider::SetDisplayState(_In_ CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS Flags)
{
	DbgPrint("[%u]:%hs<%p>(%08x %08x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, Flags, _dwDispFlags ^ (ULONG)Flags);
	_dwDispFlags = (ULONG)Flags;
	HRESULT hr = S_OK;
	ICredentialProviderWithDisplayState* p;
	if (0 <= _pWrappedProvider->QueryInterface(IID_PPV_ARGS(&p)))
	{
		hr = p->SetDisplayState(Flags);
		p->Release();
	}
	return hr;
}

HRESULT STDMETHODCALLTYPE CSampleProvider::SetAutoLogonManager(_In_ IAutoLogonManager *pAutoLogonManager)
{
	DbgPrint("[%u]:%hs<%p>(IsAutoLogon=%x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, pAutoLogonManager->IsAutoLogonMode());
	HRESULT hr = S_OK;
	IAutoLogonProvider* p;
	if (0 <= _pWrappedProvider->QueryInterface(IID_PPV_ARGS(&p)))
	{
		hr = p->SetAutoLogonManager(pAutoLogonManager);
		p->Release();
	}
	return hr;
}

HRESULT CoStrDup(_In_ PCWSTR psz, _Out_ PWSTR *ppwsz);

HRESULT STDMETHODCALLTYPE CSampleProvider::SetSessionContext(_In_ PCWSTR pszContext)
{
	DbgPrint("\r\n[%u]:%hs<%p>(\"%ws\")\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, pszContext);
	HRESULT hr = S_OK;
	ICredentialProviderWithSessionContext* p;
	if (0 <= _pWrappedProvider->QueryInterface(IID_PPV_ARGS(&p)))
	{
		hr = p->SetSessionContext(pszContext);
		p->Release();
	}

	if (_M_pszContext) CoTaskMemFree(_M_pszContext), _M_pszContext = 0;

	CoStrDup(pszContext, &_M_pszContext);

	return hr;
}

_NT_END