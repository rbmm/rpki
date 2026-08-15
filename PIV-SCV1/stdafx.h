#define SECURITY_WIN32
#define CRYPT_OID_INFO_HAS_EXTRA_FIELDS
#include "../inc/stdafx.h"
#include <commctrl.h>
#include <dbt.h>
#include <mountmgr.h>
#include <WINDOWSX.H>
#include <shlobj_core.h>
#include <shobjidl_core.h>
#include <Cryptuiapi.h>
#include <compressapi.h>
_NT_BEGIN
#include <cfgmgr32.h>
#include <ntddstor.h>
#include <devpkey.h>

HRESULT GetLastHresult(ULONG dwError = GetLastError());

inline HRESULT GetLastHresult(BOOL fOk)
{
	return fOk ? S_OK : GetLastHresult();
}

template <typename T> T HR(HRESULT& hr, T t)
{
	hr = t ? NOERROR : GetLastHresult(GetLastError());
	return t;
}

_NT_END