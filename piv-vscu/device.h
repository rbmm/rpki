#pragma once

#include "cancelapi.h"
#include "Container.h"

struct SC_DEVICE_EXTENSION : IO_CSQ_ALT, EX_RUNDOWN_REF, UNICODE_STRING
{
	LIST_ENTRY _isPresent = { &_isPresent, &_isPresent };
	LIST_ENTRY _isAbsent  = { &_isAbsent , &_isAbsent  };
	PDEVICE_OBJECT _nextDeviceObject, _PhysicalDeviceObject;
	void* _NotificationEntryVolume;
	SMARTCARD* _pSC;
	EX_RUNDOWN_REF _scRP;
	EX_PUSH_LOCK _lock, _scLock;
	ULONG _dwCardState, _bInUse;

	// ++ cancel

	virtual KIRQL CsqAcquireLock();
	virtual void CsqReleaseLock(KIRQL Irql);
	virtual ULONG_PTR CsqInsertIrp(PIRP Irp, PVOID InsertContext);

	void CompleteAll();

	// -- cancel

	SC_DEVICE_EXTENSION() : _dwCardState(SCARD_SWALLOWED), _bInUse(FALSE), _pSC(0)
	{
		ExInitializeRundownProtection(this);
		ExRundownCompleted(&_scRP);
		RtlInitUnicodeString(this, 0);
		_lock = 0;
	}

	void* operator new(size_t, PDEVICE_OBJECT DeviceObject)
	{
		return DeviceObject->DeviceExtension;
	}

	void operator delete(void*) = delete;

	static NTSTATUS CALLBACK _OnDeviceInterfaceChange(PVOID Notification, PVOID fdo)
	{
		return static_cast<SC_DEVICE_EXTENSION*>(fdo)->
			OnDeviceInterfaceChange(static_cast<PDEVICE_INTERFACE_CHANGE_NOTIFICATION>(Notification)), 0;
	}

	void OnDeviceInterfaceChange(PDEVICE_INTERFACE_CHANGE_NOTIFICATION Notification);

	enum Action { Arrival, Removal };

	void OnDeviceInterfaceChange(Action a, PUNICODE_STRING SymbolicLinkName);

	void OnDeviceInterfaceChange(Action a, ULONG hash, PUNICODE_STRING SymbolicLinkName);

	NTSTATUS PnP(PDEVICE_OBJECT , PIRP Irp, PIO_STACK_LOCATION );

	NTSTATUS OnIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp);

	NTSTATUS Create(PDEVICE_OBJECT , PIRP Irp, PIO_STACK_LOCATION IrpSp);

	NTSTATUS Close(PDEVICE_OBJECT , PIRP Irp, PIO_STACK_LOCATION IrpSp);

	NTSTATUS Cleanup(PDEVICE_OBJECT , PIRP Irp, PIO_STACK_LOCATION IrpSp);

	NTSTATUS PassDown(PIRP Irp, PIO_STACK_LOCATION IrpSp);
	
	NTSTATUS PassDownSynchronous(PIRP Irp, PIO_STACK_LOCATION IrpSp);

	NTSTATUS CommonDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

	static NTSTATUS CALLBACK _CommonDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
	{
		return static_cast<SC_DEVICE_EXTENSION*>(DeviceObject->DeviceExtension)->CommonDispatch(DeviceObject, Irp);
	}
};