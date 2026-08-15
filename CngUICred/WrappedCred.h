#pragma once

#include "../QI/newIface.h"
#include "../QI/QI.h"
#include "CngUI.h"

class CSampleProvider;

class CWrapperCredential : public ICredentialProviderCredential
{
	union {
		ICredentialProviderCredentialEvents*  _pcpce = 0;
		ICredentialProviderCredentialEvents2* _pcpce2;
		ICredentialProviderCredentialEvents3* _pcpce3;
		ICredentialProviderCredentialEvents4* _pcpce4;
		ICredentialProviderCredentialEvents5* _pcpce5;
	};

	HWND _M_hwnd;
	CSampleProvider* _pMyProvider;
	CNG_CRED_UI_DATA* _pData;

	LONG _cRef = 1;
	ULONG _EventVer;
	BOOLEAN _bSet;

	DECLARE_QI(CWrapperCredential);

	~CWrapperCredential();

public:

	void* operator new(size_t size)
	{
		return LocalAlloc(LMEM_FIXED|LMEM_ZEROINIT, size);
	}

	void operator delete(PVOID pv)
	{
		LocalFree(pv);
	}


	CWrapperCredential(CSampleProvider* pMyProvider, BOOLEAN bSet);

	//////////////////////////////////////////////////////////////////////////
	// IUnknown
	virtual ULONG STDMETHODCALLTYPE AddRef();
	virtual ULONG STDMETHODCALLTYPE Release();

	//////////////////////////////////////////////////////////////////////////
	// ICredentialProviderCredential
	virtual HRESULT STDMETHODCALLTYPE Advise(__in ICredentialProviderCredentialEvents* pcpce);
	virtual HRESULT STDMETHODCALLTYPE UnAdvise();

	virtual HRESULT STDMETHODCALLTYPE SetSelected(__out BOOL* pbAutoLogon);
	virtual HRESULT STDMETHODCALLTYPE SetDeselected();

	virtual HRESULT STDMETHODCALLTYPE GetFieldState(__in DWORD dwFieldID,
		__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
		__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

	virtual HRESULT STDMETHODCALLTYPE GetStringValue(__in DWORD dwFieldID, __deref_out PWSTR* ppwsz);
	virtual HRESULT STDMETHODCALLTYPE GetBitmapValue(__in DWORD dwFieldID, __out HBITMAP* phbmp);
	virtual HRESULT STDMETHODCALLTYPE GetCheckboxValue(__in DWORD dwFieldID, __out BOOL* pbChecked, __deref_out PWSTR* ppwszLabel);
	virtual HRESULT STDMETHODCALLTYPE GetComboBoxValueCount(__in DWORD dwFieldID, __out DWORD* pcItems, __out_range(<,*pcItems) DWORD* pdwSelectedItem);
	virtual HRESULT STDMETHODCALLTYPE GetComboBoxValueAt(__in DWORD dwFieldID, __in DWORD dwItem, __deref_out PWSTR* ppwszItem);
	virtual HRESULT STDMETHODCALLTYPE GetSubmitButtonValue(__in DWORD dwFieldID, __out DWORD* pdwAdjacentTo);

	virtual HRESULT STDMETHODCALLTYPE SetStringValue(__in DWORD dwFieldID, __in PCWSTR pwz);
	virtual HRESULT STDMETHODCALLTYPE SetCheckboxValue(__in DWORD dwFieldID, __in BOOL bChecked);
	virtual HRESULT STDMETHODCALLTYPE SetComboBoxSelectedValue(__in DWORD dwFieldID, __in DWORD dwSelectedItem);
	virtual HRESULT STDMETHODCALLTYPE CommandLinkClicked(__in DWORD dwFieldID);

	virtual HRESULT STDMETHODCALLTYPE GetSerialization(__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, 
		__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
		__deref_out_opt PWSTR* ppwszOptionalStatusText, 
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

	virtual HRESULT STDMETHODCALLTYPE ReportResult(__in NTSTATUS ntsStatus, 
		__in NTSTATUS ntsSubstatus,
		__deref_out_opt PWSTR* ppwszOptionalStatusText, 
		__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

	void Set(CNG_CRED_UI_DATA* pData);
};
