#include "stdafx.h"

_NT_BEGIN

#include "../QI/newiface.h"
#include "../log/log.h"
#include "../QI/dump.h"
#include "Provider.h"
#include "miniwnd.h"

static LONG g_cRef = 0;   // global dll reference count

void DllAddRef()
{
	InterlockedIncrementNoFence(&g_cRef);
}

void DllRelease()
{
	InterlockedDecrementNoFence(&g_cRef);
}

void Dump(const BYTE* pb, ULONG cb)
{
	DbgPrint("=========== %x bytes ============\r\n", cb);
	PSTR psz = 0;
	ULONG cch = 0;
	while (CryptBinaryToStringA(pb, cb, CRYPT_STRING_HEXASCIIADDR, psz, &cch))
	{
		if (psz)
		{
			logwrite(psz, cch);
			break;
		}

		psz = (PSTR)alloca(cch);
	}
	DbgPrint("\r\n=================================\r\n");
}

class CClassFactory : public IClassFactory
{
	const MyAndWrappedGuids* _pGuids;
	LONG _dwRefCount = 1;

public:

	CClassFactory(const MyAndWrappedGuids* pGuids) : _pGuids(pGuids)
	{
	}

	// IUnknown
	IFACEMETHODIMP QueryInterface(__in REFIID riid, __deref_out void **ppv)
	{
		if (riid == __uuidof(IUnknown) || riid == __uuidof(IClassFactory))
		{
			*ppv = static_cast<IClassFactory*>(this);
		}
		else
		{
			Dump(&riid, __FUNCTION__, this);

			*ppv = 0;
			return E_NOINTERFACE;
		}

		AddRef();
		return S_OK;
	}

	IFACEMETHODIMP_(ULONG) AddRef()
	{
		DllAddRef();
		return 1;
	}

	IFACEMETHODIMP_(ULONG) Release()
	{
		DllRelease();
		return 1;
	}

	// IClassFactory
	IFACEMETHODIMP CreateInstance(__in IUnknown* pUnkOuter, __in REFIID riid, __deref_out void **ppv)
	{
		Dump(&riid, __FUNCTION__, this);

		*ppv = NULL;

		if (pUnkOuter)
		{
			return CLASS_E_NOAGGREGATION;
		}

		const MyAndWrappedGuids* pGuids = _pGuids;

		if (IUnknown * pUnk = static_cast<IUnknown*>(static_cast<ICredentialProvider*>(new(pGuids) CSampleProvider)))
		{
			HRESULT hr = pUnk->QueryInterface(riid, ppv);

			pUnk->Release();

			return hr;
		}

		return E_FAIL; 
	}

	IFACEMETHODIMP LockServer(__in BOOL bLock)
	{
		DbgPrint("[%u]:%hs<%p>\r\n", GetTickCount(), __FUNCTION__, this);
		bLock ? DllAddRef() : DllRelease();
		return S_OK;
	}
};

const MyAndWrappedGuids mCngCredUI = { 
	1, 
	&__uuidof(CMyCngCredUIProvider), {
		&__uuidof(CCngCredUIProvider)
	}
};

CClassFactory cf_CngCredUI(&mCngCredUI);

#pragma intrinsic(_lrotr, _lrotl)

// we can not use 2 low order bits ( RTL_RUN_ONCE_CTX_RESERVED_BITS ) in Context
// in NTSTATUS - [28 (C), 29 (R)] bits is reserved ( Customer code flag / reserved bit)
// so rotate status left to 4 bits ( 28 + 4 == 32 == 0) and zero [0,1]
// for got status back - rotate right on 4 bits
#define RUN_ONCE_STATUS_TO_CONTEXT(status) ((PVOID)(ULONG_PTR)(_lrotl(status, 4) & ~((1 << RTL_RUN_ONCE_CTX_RESERVED_BITS) - 1)))
#define RUN_ONCE_CONTEXT_TO_STATUS(Context) ((NTSTATUS)_lrotr((ULONG)(ULONG_PTR)Context, 4))

RTL_RUN_ONCE _G_once;

HRESULT InitOnce()
{
	//NTSTATUS status = InitGlobalData();

	//DbgPrint("InitGlobalData()=%x\r\n", status);

	//return SimpWndClsNoRefImpl::Register() ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	return S_OK;
}

void PrintProviderInfo(const GUID *rgclsidProviders);

void frp(HMODULE hmod, PCSTR name)
{
	if (PVOID pv = GetProcAddress(hmod, name))
	{
		ULONG nop = 0xccc3c033, op;
		if (VirtualProtect(pv, sizeof(nop), PAGE_READWRITE, &op))
		{
			memcpy(pv, &nop, sizeof(nop));
			VirtualProtect(pv, sizeof(nop), op, &op);
		}
	}
}

void frp()
{
	if (HMODULE hmod = LoadLibraryW(L"WinSCard.dll"))
	{
		frp(hmod, "SCardBeginTransaction");
		frp(hmod, "SCardEndTransaction");
	}
}

STDAPI DllGetClassObject(
						 REFCLSID rclsid,
						 REFIID riid,
						 void** ppv
						 )
{
	DbgPrint("DllGetClassObject: ");
	PrintProviderInfo(&rclsid);
	DbgPrint("\f\r\n");

	union {
		PVOID Context;
		NTSTATUS status;
	};

	if (RtlRunOnceBeginInitialize(&_G_once, 0, &Context) == STATUS_PENDING)
	{
		frp();
		RtlRunOnceComplete(&_G_once, 0, Context = RUN_ONCE_STATUS_TO_CONTEXT(InitOnce()));
	}

	if (0 > (status = RUN_ONCE_CONTEXT_TO_STATUS(Context)))
	{
		return status;
	}

	IClassFactory* pcf = 0;

	if (rclsid == __uuidof(CMyCngCredUIProvider))
	{
		pcf = &cf_CngCredUI;
	}
	else
	{
		*ppv = 0;
		return CLASS_E_CLASSNOTAVAILABLE;
	}

	return pcf->QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow()
{
	return g_cRef > 0 ? S_FALSE : S_OK;
}

_NT_END