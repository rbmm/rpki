#pragma once

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

HMODULE GetNTDLL();

BOOLEAN IsFileExist(_In_ PCWSTR FileName);

PCWSTR GetProcessEnvironment();

PCWSTR GetTmpPath(_In_ PCWSTR Environment);

PCWSTR GetTmpPath();

LONG InitLog(_In_ PCWSTR name, _In_opt_ BOOL bUseFolder = FALSE);

NTSTATUS InitLogEx(_In_ PCWSTR name, _Out_ PHANDLE phRoot);

void DestroyLog();

extern LONG _G_logMask;
extern BOOLEAN _G_noTimePrefix;

void logwrite(_In_ const void* buf, _In_ ULONG cb, _In_ ULONG wDay);

void logwrite(_In_ const void* buf, _In_ ULONG cb);

void LogOutputNT(_In_ LONG mask, _In_ PCWSTR format, ...);

HRESULT I_LogError(WCHAR c, const void* prefix, HRESULT dwError = GetLastHresult());

inline HRESULT LogError(PCSTR prefix, HRESULT dwError = GetLastHresult())
{
	return I_LogError('h', prefix, dwError);
}

inline HRESULT LogError(PCWSTR prefix, HRESULT dwError = GetLastHresult())
{
	return I_LogError('w', prefix, dwError);
}

#ifdef _NTIFS_

#define DbgPrint(format, ...) LogOutputNT(~0, _CRT_WIDE(format), __VA_ARGS__ )

PCWSTR GetVarString(_In_ PCUNICODE_STRING pus);

PCWSTR GetVarString(_In_ PCWSTR Environment, _In_ PCUNICODE_STRING pus);

#else

#define DbgPrint(format, ...) NT::LogOutputNT(~0, _CRT_WIDE(format), __VA_ARGS__ )
#define LogOutput(format, ...) NT::LogOutputNT(~0, format, __VA_ARGS__ )

#define _NT_BEGIN namespace NT {
#define _NT_END }

#endif // _NTIFS_

EXTERN_C extern IMAGE_DOS_HEADER __ImageBase;

#pragma message("!!! NT::LOG >>>>>>")
