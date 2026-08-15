#pragma once

#define _NTDRIVER_
#define NOWINBASEINTERLOCK
#define _NTOS_
#define _KERNEL_MODE

#define SMARTCARD_POOL_TAG 'tpcs'

#include "../inc/StdAfx.h"

#include <intrin.h>
_NT_BEGIN
#include <SMCLIB.h>
#include <wdmguid.h>
#include <ntddstor.h>
_NT_END

#ifdef _WIN64
#define __movsp(x, y, n) __movsq((PULONG64)(x), (PULONG64)(y), n)
#else
#define __movsp(x, y, n) __movsd((PULONG)(x), (PULONG)(y), n)
#endif

#ifdef _WIN64
#define __stosp(x, y, n) __stosq((PULONG64)(x), (ULONG64)(y), n)
#else
#define __stosp(x, y, n) __stosd((PULONG)(x), (ULONG)(ULONG_PTR)(y), n)
#endif

#if 1
#define _DBG_
#else
#define DbgPrint /##/
#define DumpBytes /##/
#endif