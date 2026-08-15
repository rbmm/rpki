#pragma once

#include "../QI/newiface.h"
#include "../QI/QI.h"
#include "CngUI.h"

void DllAddRef();
void DllRelease();

class DECLSPEC_UUID("559A3F37-F5D9-44c7-8D0F-098FD82B3E60") CMyFilter;
class DECLSPEC_UUID("559A3F37-F5D9-44c7-8D0F-098FD82B3E61") CMyCngCredUIProvider;

struct MyAndWrappedGuids 
{
	ULONG WrappedGuidsCount;
	const GUID* clsidCredentialProvider;
	const GUID* WrappedGuids[];
};

extern const MyAndWrappedGuids mPin, mPassword, mCngCredUI;

class CSampleProvider : public ICredentialProvider, 
				  ICredentialProviderSetUserArray, 
				  ICredentialProviderWithDisplayState,
				  ICredentialProviderWithSessionContext,
				  IAutoLogonProvider
{
	const MyAndWrappedGuids* _pGuids;
	UINT_PTR _upAdviseContext;
	PWSTR _M_pszContext;
	ICredentialProvider* _pWrappedProvider;
	HMODULE _M_hmod;
	
	LONG _cRef = 1;
	CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
	ULONG _dwFlags;
	ULONG _dwDispFlags;
	BOOLEAN _bMyKey, _bSet;

	DECLARE_QI(CSampleProvider);

	bool Init(const MyAndWrappedGuids* pGuids);

	~CSampleProvider();

public:

	BOOLEAN IsSet()
	{
		return _bSet;
	}

	CSampleProvider();

	void* operator new(size_t size, const MyAndWrappedGuids* pGuids);
	void operator delete(PVOID pv);

	//////////////////////////////////////////////////////////////////////////
	// IUnknown
	
	virtual ULONG STDMETHODCALLTYPE AddRef();
	virtual ULONG STDMETHODCALLTYPE Release();

	//////////////////////////////////////////////////////////////////////////
	// ICredentialProvider
	virtual HRESULT STDMETHODCALLTYPE SetUsageScenario(__in CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, __in DWORD dwFlags);
	virtual HRESULT STDMETHODCALLTYPE SetSerialization(__in const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

	virtual HRESULT STDMETHODCALLTYPE Advise(__in ICredentialProviderEvents* pcpe, __in UINT_PTR upAdviseContext);
	virtual HRESULT STDMETHODCALLTYPE UnAdvise();

	virtual HRESULT STDMETHODCALLTYPE GetFieldDescriptorCount(__out DWORD* pdwCount);
	virtual HRESULT STDMETHODCALLTYPE GetFieldDescriptorAt(__in DWORD dwIndex,  __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

	virtual HRESULT STDMETHODCALLTYPE GetCredentialCount(__out DWORD* pdwCount,
		__out_range(<,*pdwCount) DWORD* pdwDefault,
		__out BOOL* pbAutoLogonWithDefault);

	virtual HRESULT STDMETHODCALLTYPE GetCredentialAt(__in DWORD dwIndex, 
		__deref_out ICredentialProviderCredential** ppcpc);

	//////////////////////////////////////////////////////////////////////////
	// ICredentialProviderSetUserArray
	virtual HRESULT STDMETHODCALLTYPE SetUserArray( 
		/* [annotation][in] */ 
		_In_  ICredentialProviderUserArray *users);

	//////////////////////////////////////////////////////////////////////////
	// ICredentialProviderWithDisplayState
	virtual HRESULT STDMETHODCALLTYPE SetDisplayState(_In_ CREDENTIAL_PROVIDER_DISPLAY_STATE_FLAGS Flags);

	//////////////////////////////////////////////////////////////////////////
	// IAutoLogonProvider
	virtual HRESULT STDMETHODCALLTYPE SetAutoLogonManager(IAutoLogonManager *);

	//////////////////////////////////////////////////////////////////////////
	// ICredentialProviderWithSessionContext

	virtual HRESULT STDMETHODCALLTYPE SetSessionContext(PCWSTR pszContext);

	PCWSTR GetSessionContext()
	{
		return _M_pszContext;
	}
};