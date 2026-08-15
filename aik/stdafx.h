#define SECURITY_WIN32
#include "../inc/stdafx.h"

_NT_BEGIN
#include <ntlsa.h>

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