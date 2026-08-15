#include "stdafx.h"
#include "UiContext.h"
_NT_BEGIN
#include "../log/log.h"
#include "../QI/dump.h"
#include "../QI/helpers.h"
#include "WrappedCred.h"
#include "Provider.h"
#include "helpers.h"

void Dump(const BYTE* pb, ULONG cb);

ULONG GetSecondsSinceLoad();

BEGIN_QI_MAP(CWrapperCredential)
	IE(ICredentialProviderCredential),
END_QI_MAP(CWrapperCredential)

CWrapperCredential::~CWrapperCredential()
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);
	_pMyProvider->Release();
	if (_pData) delete _pData;
	DllRelease();
}

CWrapperCredential::CWrapperCredential(CSampleProvider* pMyProvider, BOOLEAN bSet) : _bSet(bSet), _pMyProvider(pMyProvider) 
{
	DllAddRef();

	pMyProvider->AddRef();

	DbgPrint("[%u]:%hs<%p>()\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);
}

ULONG STDMETHODCALLTYPE CWrapperCredential::AddRef()
{
	return InterlockedIncrementNoFence(&_cRef);
}

ULONG STDMETHODCALLTYPE CWrapperCredential::Release()
{
	LONG cRef = InterlockedDecrement(&_cRef);
	if (!cRef)
	{
		delete this;
	}
	return cRef;
}

HWND ShowMyDlg(CWrapperCredential* pMycpc, ICredentialProviderCredentialEvents4* pEvent, BOOLEAN bSet);

HRESULT STDMETHODCALLTYPE CWrapperCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
	if (_pcpce) _pcpce->Release(), _pcpce = 0;

	if (0 <= pcpce->QueryInterface(IID_PPV(_pcpce5)))
	{
		_EventVer = 5;
	}
	else if (0 <= pcpce->QueryInterface(IID_PPV(_pcpce4)))
	{
		_EventVer = 4;
	}
	else if (0 <= pcpce->QueryInterface(IID_PPV(_pcpce3)))
	{
		_EventVer = 3;
	}
	else if (0 <= pcpce->QueryInterface(IID_PPV(_pcpce2)))
	{
		_EventVer = 2;
	}
	else
	{
		_pcpce = pcpce, pcpce->AddRef();
		_EventVer = 1;
	}

	DbgPrint("[%u]:%hs<%p>(%p, v=%x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, pcpce, _EventVer);

	if (3 < _EventVer)
	{
		_M_hwnd = ShowMyDlg(this, _pcpce4, _pMyProvider->IsSet());
	}
	//////////////////////////////////////////////////////////////////////////

	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::UnAdvise()
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);

	if (_M_hwnd)
	{
		PostMessageW(_M_hwnd, WM_CLOSE, 0, 0);
	}
	if (_pcpce) _pcpce->Release(), _pcpce = 0, _EventVer = 0;

	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::SetSelected(__out BOOL* pbAutoLogon)  
{
	*pbAutoLogon = FALSE;
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::SetDeselected()
{
	DbgPrint("[%u]:%hs<%p>\r\n", GetSecondsSinceLoad(), __FUNCTION__, this);

	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetFieldState(
	__in DWORD /*dwFieldID*/,
	__out CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
	__out CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
	)
{
	*pcpfis = CPFIS_NONE;
	*pcpfs = CPFS_HIDDEN;

	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	*ppwsz = 0;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetComboBoxValueCount(
	__in DWORD dwFieldID, 
	__out DWORD* pcItems, 
	__out_range(<,*pcItems) DWORD* pdwSelectedItem
	)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	*pcItems = 0;
	*pdwSelectedItem = 0;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetComboBoxValueAt(
	__in DWORD dwFieldID, 
	__in DWORD /*dwItem*/,
	__deref_out PWSTR* ppwszItem
	)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	*ppwszItem = 0;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD /*dwSelectedItem*/)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	*phbmp = 0;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	*pdwAdjacentTo = dwFieldID;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
	DbgPrint("[%u]:%hs<%p>(%02u \"%ws\")\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID, pwz);
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetCheckboxValue(
	__in DWORD dwFieldID, 
	__out BOOL* pbChecked,
	__deref_out PWSTR* ppwszLabel
	)
{
	DbgPrint("[%u]:%hs<%p>(%02u)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID);
	*pbChecked = FALSE;
	*ppwszLabel = 0;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::SetCheckboxValue(
	__in DWORD dwFieldID, 
	__in BOOL bChecked
	)
{
	DbgPrint("[%u]:%hs<%p>(%02u %x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, dwFieldID, bChecked);
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::CommandLinkClicked(__in DWORD /*dwFieldID*/)
{
	return S_OK;
}

HRESULT CWrapperCredential::ReportResult(
	__in NTSTATUS ntsStatus, 
	__in NTSTATUS ntsSubstatus,
	__deref_out_opt PWSTR* ppwszOptionalStatusText, 
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	DbgPrint("[%u]:%hs<%p>(%x,%x)\r\n", GetSecondsSinceLoad(), __FUNCTION__, this, ntsStatus, ntsSubstatus);

	*pcpsiOptionalStatusIcon = CPSI_NONE;
	*ppwszOptionalStatusText = 0;
	return S_OK;
}

HRESULT STDMETHODCALLTYPE CWrapperCredential::GetSerialization(
	__out CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
	__out CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, 
	__deref_out_opt PWSTR* ppwszOptionalStatusText, 
	__out CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
	)
{
	*ppwszOptionalStatusText = 0;
	*pcpsiOptionalStatusIcon = CPSI_NONE;

	if (CNG_CRED_UI_DATA* pData = (CNG_CRED_UI_DATA*)InterlockedExchangePointer((void**)&_pData, 0))
	{
		pcpcs->cbSerialization = pData->GetSize();
		pcpcs->rgbSerialization = (PBYTE)pData;
		pcpcs->ulAuthenticationPackage = CNG_CRED_UI_DATA::eAP;
		pcpcs->clsidCredentialProvider = __uuidof(CCngCredUIProvider);

		*pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
		return S_OK;
	}

	RtlZeroMemory(pcpcs, sizeof(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION));
	*pcpgsr = CPGSR_RETURN_NO_CREDENTIAL_FINISHED;
	return S_OK;
}

void CWrapperCredential::Set(CNG_CRED_UI_DATA* pData)
{
	if (pData = (CNG_CRED_UI_DATA*)InterlockedExchangePointer((void**)&_pData, pData))
	{
		delete pData;
	}
}
_NT_END