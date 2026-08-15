#include "stdafx.h"

void* __cdecl operator new[](size_t ByteSize)
{
	return HeapAlloc(GetProcessHeap(), 0, ByteSize);
}

void* __cdecl operator new(size_t ByteSize)
{
	return HeapAlloc(GetProcessHeap(), 0, ByteSize);
}

void __cdecl operator delete(void* Buffer)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete(void* Buffer, size_t)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete[](void* Buffer)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

void __cdecl operator delete[](void* Buffer, size_t)
{
	HeapFree(GetProcessHeap(), 0, Buffer);
}

_NT_BEGIN

HRESULT GetLastHresult(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();

	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

_NT_END