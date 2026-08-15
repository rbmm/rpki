#include "stdafx.h"

_NT_BEGIN
#include "device.h"

KIRQL SC_DEVICE_EXTENSION::CsqAcquireLock()
{
	KeEnterCriticalRegion();
	ExfAcquirePushLockExclusive(&_lock);
	return 0;
}

void SC_DEVICE_EXTENSION::CsqReleaseLock(KIRQL /*Irql*/)
{
	ExfReleasePushLockExclusive(&_lock);
	KeLeaveCriticalRegion();
}

ULONG_PTR SC_DEVICE_EXTENSION::CsqInsertIrp(PIRP , PVOID bCompleteIfCardPresent)
{
	return (_pSC != 0) != (bool)bCompleteIfCardPresent;
}

void SC_DEVICE_EXTENSION::CompleteAll()
{
	CompleteAllPending(&_isAbsent, STATUS_CANCELLED);
	CompleteAllPending(&_isPresent, STATUS_CANCELLED);
}

_NT_END