// vscr.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"

_NT_BEGIN
#include "device.h"
// GUID_DEVINTERFACE_SMARTCARD {084f9363-e31a-4bde-9ca5-6fa0d86e009f} for SmartCard

#ifdef _DBG_
PCSTR DeviceIoControlString(ULONG IoControlCode);
PCSTR SrbFunctionString(UCHAR Function);
PCSTR QueryIdString(int IdType);
PCSTR QueryDeviceRelationsString(DEVICE_RELATION_TYPE Type);
PCSTR MajorMinorFunctionString(UCHAR MajorFunction, UCHAR MinorFunction, PCSTR& mnstr);
PCSTR PnPMinorFunctionString(IN UCHAR MinorFunction);
void DumpBytes(const BYTE * pb, ULONG cb, PCSTR prefix = "");
#endif

NTSTATUS SC_DEVICE_EXTENSION::Create(PDEVICE_OBJECT , PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	DbgPrint("%p(%s):%s(%x %wZ)\n", PsGetCurrentProcessId(), PsGetProcessImageFileName(IoGetCurrentProcess()), __FUNCTION__, IrpSp->Parameters.Create.Options, &FileObject->FileName);

	if (FileObject->FileName.Length)
	{
		switch (IrpSp->Parameters.Create.Options)
		{
		case FILE_SYNCHRONOUS_IO_ALERT|(FILE_OPEN<<24):
			OnDeviceInterfaceChange(Removal, 0, 0);
			OnDeviceInterfaceChange(Arrival, &FileObject->FileName);
			[[fallthrough]];
		case FILE_DELETE_ON_CLOSE|(FILE_OPEN<<24):
			Irp->IoStatus.Information = 0;
			return STATUS_INVALID_LEVEL;
		default:
			break;
		}
	}

	Irp->IoStatus.Information = FILE_CREATED;
	return STATUS_SUCCESS;
}

NTSTATUS SC_DEVICE_EXTENSION::Close(PDEVICE_OBJECT , PIRP Irp, [[maybe_unused]] PIO_STACK_LOCATION IrpSp)
{
#ifdef _DBG_
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	DbgPrint("%p(%s):%s(%p %wZ)\n", PsGetCurrentProcessId(), PsGetProcessImageFileName(IoGetCurrentProcess()), __FUNCTION__, FileObject, &FileObject->FileName);
#endif

	Irp->IoStatus.Information = 0;

	return STATUS_SUCCESS;
}

NTSTATUS SC_DEVICE_EXTENSION::Cleanup(PDEVICE_OBJECT , PIRP Irp, [[maybe_unused]] PIO_STACK_LOCATION IrpSp)
{
#ifdef _DBG_
	PFILE_OBJECT FileObject = IrpSp->FileObject;

	DbgPrint("%p(%s):%s(%p %wZ)\n", PsGetCurrentProcessId(), PsGetProcessImageFileName(IoGetCurrentProcess()), __FUNCTION__, FileObject, &FileObject->FileName);
#endif

	Irp->IoStatus.Information = 0;

	return STATUS_SUCCESS;
}

NTSTATUS CALLBACK OnComplete([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp, SC_DEVICE_EXTENSION* fdo)
{
	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	if (Irp->PendingReturned) IoMarkIrpPending(Irp);

	ExReleaseRundownProtection(fdo);

	if (IrpSp->MajorFunction == IRP_MJ_PNP)
	{
		switch (IrpSp->MinorFunction)
		{
		case IRP_MN_QUERY_DEVICE_RELATIONS:

			DbgPrint("QueryDeviceRelations(%s) %p %x\n", QueryDeviceRelationsString(IrpSp->Parameters.QueryDeviceRelations.Type), Irp->IoStatus.Information, Irp->IoStatus.Status);

			if (0 <= Irp->IoStatus.Status)
			{
				if (PDEVICE_RELATIONS p = (PDEVICE_RELATIONS)Irp->IoStatus.Information)
				{
					if (ULONG n = p->Count)
					{
						PDEVICE_OBJECT* Objects = p->Objects;
						do 
						{
							DeviceObject = *Objects++;
							DbgPrint("  %p %wZ\n", DeviceObject, &DeviceObject->DriverObject->DriverName);
						} while (--n);
					}
				}
			}
			break;

		case IRP_MN_QUERY_CAPABILITIES:
			if (PDEVICE_CAPABILITIES deviceCapabilities = IrpSp->Parameters.DeviceCapabilities.Capabilities)
			{
#ifdef _DBG_
				DbgPrint("CAPABILITIES{%x}(%x %x %x %x %x %x %x %x %x)\n", Irp->IoStatus.Status,
					deviceCapabilities->Removable,
					deviceCapabilities->LockSupported,
					deviceCapabilities->EjectSupported,
					deviceCapabilities->SurpriseRemovalOK,
					deviceCapabilities->HardwareDisabled,
					deviceCapabilities->NoDisplayInUI,
					deviceCapabilities->UniqueID, 
					deviceCapabilities->SystemWake,
					deviceCapabilities->DeviceWake);
#endif

				//deviceCapabilities->Removable = TRUE;//!!!
				//deviceCapabilities->LockSupported = TRUE;//!!!
				//deviceCapabilities->EjectSupported = TRUE;//!!!
				//deviceCapabilities->SurpriseRemovalOK = FALSE;
				//deviceCapabilities->HardwareDisabled = FALSE;
				//deviceCapabilities->NoDisplayInUI = FALSE;
				//deviceCapabilities->UniqueID = TRUE;
			}
			break;
		}
	}

	return ContinueCompletion;
}

NTSTATUS SC_DEVICE_EXTENSION::PassDown(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	PIO_STACK_LOCATION nextIrpSp = IrpSp - 1;
	*nextIrpSp = *IrpSp;
	nextIrpSp->Control = SL_INVOKE_ON_SUCCESS|SL_INVOKE_ON_ERROR|SL_INVOKE_ON_CANCEL;
	nextIrpSp->Context = this;
	nextIrpSp->CompletionRoutine = (PIO_COMPLETION_ROUTINE)OnComplete;
	return IofCallDriver(_nextDeviceObject, Irp);
}

NTSTATUS CALLBACK OnCompleteSync([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp, PKEVENT Event)
{
	DbgPrint("OnCompleteSync(%x)\n", Irp->PendingReturned);

	if (Irp->PendingReturned) KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

	return StopCompletion;
}

NTSTATUS SC_DEVICE_EXTENSION::PassDownSynchronous(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	KEVENT Event;
	KeInitializeEvent(&Event, SynchronizationEvent, FALSE);

	PIO_STACK_LOCATION nextIrpSp = IrpSp - 1;
	*nextIrpSp = *IrpSp;
	nextIrpSp->Control = SL_INVOKE_ON_SUCCESS|SL_INVOKE_ON_ERROR|SL_INVOKE_ON_CANCEL;
	nextIrpSp->Context = &Event;
	nextIrpSp->CompletionRoutine = (PIO_COMPLETION_ROUTINE)OnCompleteSync;

	NTSTATUS status = IofCallDriver(_nextDeviceObject, Irp);

	if (STATUS_PENDING == status)
	{
		DbgPrint("PassDownSynchronous:Wait\n");

		KeWaitForSingleObject(&Event, WrExecutive, KernelMode, FALSE, 0);

		status = Irp->IoStatus.Status;
	}

	ExReleaseRundownProtection(this);

	return status;
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status)
{
	Irp->IoStatus.Status = status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS SC_DEVICE_EXTENSION::CommonDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status;

	PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

	switch(IrpSp->MajorFunction)
	{
	case IRP_MJ_CREATE:
		status = Create(DeviceObject, Irp, IrpSp);
		break;

	case IRP_MJ_CLOSE:
		status = Close(DeviceObject, Irp, IrpSp);
		break;

	case IRP_MJ_CLEANUP:
		status = Cleanup(DeviceObject, Irp, IrpSp);
		break;

	case IRP_MJ_QUERY_INFORMATION:
		DbgPrint("%p(%s):QUERY_INFORMATION(%x.%x)\n", PsGetCurrentProcessId(), PsGetProcessImageFileName(IoGetCurrentProcess()),IrpSp->Parameters.QueryFile.FileInformationClass, IrpSp->Parameters.QueryFile.Length);
		status = STATUS_NOT_IMPLEMENTED;
		break;

	case IRP_MJ_DEVICE_CONTROL:
	//case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		status = STATUS_DELETE_PENDING;
		if (ExAcquireRundownProtection(this))
		{
			status = OnIoctl(DeviceObject, Irp, IrpSp);
			ExReleaseRundownProtection(this);
		}
		break;

	case IRP_MJ_PNP:
		return PnP(DeviceObject, Irp, IrpSp);

	default:
		DbgPrint("%p(%s):%s(%x.%x)\n", PsGetCurrentProcessId(), PsGetProcessImageFileName(IoGetCurrentProcess()), __FUNCTION__, IrpSp->MajorFunction, IrpSp->MinorFunction);

		if (ExAcquireRundownProtection(this))
		{
			return PassDown(Irp, IrpSp);
		}
		status = STATUS_DELETE_PENDING;
	}

	if (status == STATUS_PENDING)
	{
		return STATUS_PENDING;
	}

	return CompleteIrp(Irp, status);
}

NTSTATUS SC_DEVICE_EXTENSION::PnP(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	DbgPrint("PnP(%s)\n", PnPMinorFunctionString(IrpSp->MinorFunction));

	if (!ExAcquireRundownProtection(this))
	{
		return CompleteIrp(Irp, STATUS_DELETE_PENDING);
	}

	NTSTATUS status;

	switch(IrpSp->MinorFunction)
	{
	case IRP_MN_REMOVE_DEVICE:

		DbgPrint("IRP_MN_REMOVE_DEVICE(%p <%p>)\n", Ptr, _pSC);

		CompleteAll();
		if (_NotificationEntryVolume) IoUnregisterPlugPlayNotification(_NotificationEntryVolume), _NotificationEntryVolume = 0;

		status = PassDown(Irp, IrpSp);

		ExWaitForRundownProtectionRelease(this);

		DbgPrint("-= delete FDO:%p(%p) %wZ =-\n", DeviceObject, _nextDeviceObject, static_cast<PCUNICODE_STRING>(this));

		if (_pSC) delete _pSC;
		RtlFreeUnicodeString(this);
		CompleteAll();
		IoDetachDevice(_nextDeviceObject);
		IoDeleteDevice(DeviceObject);

		return status;

	case IRP_MN_START_DEVICE:

		if (0 <= (status = PassDownSynchronous(Irp, IrpSp)))
		{
			status = IoRegisterDeviceInterface(_PhysicalDeviceObject, &SmartCardReaderGuid, 0, this);
			DbgPrint("START_DEVICE:%x %wZ\n", status, static_cast<PCUNICODE_STRING>(this));
			if (0 <= (status))
			{
				status = IoSetDeviceInterfaceState(this, TRUE);
			}
		}
		return CompleteIrp(Irp, status);

	case IRP_MN_SURPRISE_REMOVAL:
		CompleteAll();
		break;
	}

	return PassDown(Irp, IrpSp);
}

//////////////////////////////////////////////////////////////////////////

NTSTATUS SetUlong(PIRP Irp, ULONG OutputBufferLength, ULONG Value)
{
	if (OutputBufferLength < sizeof(ULONG))
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	*(ULONG*)Irp->AssociatedIrp.SystemBuffer = Value;
	Irp->IoStatus.Information = sizeof(ULONG);

	return STATUS_SUCCESS;
}

NTSTATUS SetBinary(PIRP Irp, ULONG OutputBufferLength, const void* pv, ULONG cb)
{
	Irp->IoStatus.Information = OutputBufferLength = min(OutputBufferLength, cb);
	memcpy(Irp->AssociatedIrp.SystemBuffer, pv, OutputBufferLength);
	DumpBytes((PBYTE)Irp->AssociatedIrp.SystemBuffer, OutputBufferLength);
	return STATUS_SUCCESS;
}

NTSTATUS SC_DEVICE_EXTENSION::OnIoctl([[maybe_unused]] PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp )
{
	static const UCHAR ATR[] = {
		0x3B, 0x06, 0x5F, 0x52, 0x42, 0x4D, 0x4D, 0x39
	};

	STATIC_ASTRING(VENDOR_NAME, "RBMM");
	STATIC_ASTRING(VENDOR_IFD_TYPE, "Smartcard Reader (PV1)");

	Irp->IoStatus.Information = 0;

	ULONG InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

	union {
		PVOID SystemBuffer;
		PULONG pminorIOCTL;
		PULONG pdwAttrId;
		PULONG pdProtocol;
		PBYTE pbAtr;
		SCARD_IO_REQUEST* pio;
	};
	
	NTSTATUS status;
	ULONG cbPciLength;

	SystemBuffer = Irp->AssociatedIrp.SystemBuffer;

	DbgPrint("// %x(%x)>IOCTL(%x.%x %X) %X %X <%p>\n", PsGetCurrentProcessId(), Irp->Flags, IrpSp->MajorFunction, IrpSp->MinorFunction, IrpSp->Parameters.DeviceIoControl.IoControlCode, InputBufferLength, OutputBufferLength, IrpSp->CompletionRoutine);

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	default:
		DbgPrint("!!!!! IOCTL NOT_IMPLEMENTED\n");
		return STATUS_NOT_IMPLEMENTED;

	case IOCTL_SMARTCARD_GET_FEATURE_REQUEST:
		DbgPrint("{GET_FEATURE_REQUEST}\n");
		return STATUS_SUCCESS;

	case IOCTL_SMARTCARD_SET_ATTRIBUTE:
		DbgPrint("{SET_ATTRIBUTE}\n");
		if (InputBufferLength < sizeof(ULONG))
		{
			return STATUS_INVALID_PARAMETER;
		}

		DumpBytes(pbAtr, InputBufferLength);

		switch (*pdwAttrId)
		{
		case SCARD_ATTR_DEVICE_IN_USE:
			if (InputBufferLength != 2*sizeof(ULONG))
			{
				return STATUS_INVALID_PARAMETER;
			}
			_bInUse = pdwAttrId[1];
			DbgPrint("[DEVICE_IN_USE]:=%x\n", _bInUse);

			if (ExAcquireRundownProtection(&_scRP))
			{
				_pSC->Lock();
				_pSC->Reset();
				_pSC->Unlock();

				ExReleaseRundownProtection(&_scRP);
			}

			break;
		}
		return STATUS_SUCCESS;

	case IOCTL_SMARTCARD_SET_PROTOCOL:
		if (InputBufferLength != sizeof(ULONG) || OutputBufferLength != sizeof(ULONG))
		{
			DbgPrint("!!!!!! {SET_PROTOCOL}(%x,%x)\n", InputBufferLength, OutputBufferLength);
			return STATUS_INVALID_PARAMETER;
		}
		_dwCardState = SCARD_SPECIFIC;
		DbgPrint("{SET_PROTOCOL}(%x)\n", *pdProtocol);
		*pdProtocol = SCARD_PROTOCOL_T0;
		Irp->IoStatus.Information = sizeof(ULONG);
		return STATUS_SUCCESS;

	case IOCTL_SMARTCARD_GET_ATTRIBUTE:
		if (InputBufferLength != sizeof(ULONG))
		{
			return STATUS_INVALID_PARAMETER;
		}

		switch (*pdwAttrId)
		{
		default:
			DbgPrint("!!! GET_ATTRIBUTE(%x) NOT_IMPLEMENTED\n", *pdwAttrId);
			return STATUS_NOT_IMPLEMENTED;

		case SCARD_ATTR_DEVICE_IN_USE:
			DbgPrint("[DEVICE_IN_USE]=%x\n", _bInUse);
			return SetUlong(Irp, OutputBufferLength, _bInUse);

		case SCARD_ATTR_VENDOR_NAME:
			DbgPrint("[VENDOR_NAME]\n");
			return SetBinary(Irp, OutputBufferLength, VENDOR_NAME, sizeof(VENDOR_NAME));

		case SCARD_ATTR_VENDOR_IFD_TYPE:
			DbgPrint("[VENDOR_IFD_TYPE]\n");
			return SetBinary(Irp, OutputBufferLength, VENDOR_IFD_TYPE, sizeof(VENDOR_IFD_TYPE));

		case SCARD_ATTR_DEVICE_UNIT:
			DbgPrint("[DEVICE_UNIT]\n");
			return SetUlong(Irp, OutputBufferLength, 0);

		case SCARD_ATTR_CHANNEL_ID:
			DbgPrint("[CHANNEL_ID]\n");
			return SetUlong(Irp, OutputBufferLength, SCARD_READER_TYPE_VENDOR << 16);//SCARD_READER_TYPE_USB //SCARD_READER_TYPE_TPM

		case SCARD_ATTR_CHARACTERISTICS:
			DbgPrint("[CHARACTERISTICS]\n");
			return SetUlong(Irp, OutputBufferLength, SCARD_READER_CONTACTLESS);//SCARD_READER_SWALLOWS //

		case SCARD_ATTR_CURRENT_PROTOCOL_TYPE:
			DbgPrint("[CURRENT_PROTOCOL_TYPE]\n");
			return SetUlong(Irp, OutputBufferLength, SCARD_PROTOCOL_T0);//!!!

		case SCARD_ATTR_ATR_STRING:
			DbgPrint("[ATR_STRING]\n");
			return SetBinary(Irp, OutputBufferLength, ATR, sizeof(ATR));
		}

	case IOCTL_SMARTCARD_POWER:
		DbgPrint("{POWER}\n");
		if (InputBufferLength != sizeof(ULONG))
		{
			return STATUS_INVALID_PARAMETER;
		}

		switch (*pminorIOCTL)
		{
		default:
			return STATUS_INVALID_PARAMETER;

		case SCARD_COLD_RESET:
		case SCARD_WARM_RESET:
			DbgPrint("SCARD_(%x)_RESET\n", *pminorIOCTL);
			_dwCardState = SCARD_SPECIFIC;
			return SetBinary(Irp, OutputBufferLength, ATR, sizeof(ATR));
		case SCARD_POWER_DOWN:
			_dwCardState = SCARD_SWALLOWED;
			DbgPrint("SCARD_POWER_DOWN\n");
			return STATUS_SUCCESS;
		}

	case IOCTL_SMARTCARD_TRANSMIT:
		if (InputBufferLength < sizeof(SCARD_IO_REQUEST))
		{
			return STATUS_INVALID_PARAMETER;
		}

		cbPciLength = pio->cbPciLength;
		DbgPrint("{TRANSMIT}<%x,%x> (%x-%x)\n", pio->dwProtocol, cbPciLength, InputBufferLength, OutputBufferLength);

		DumpBytes(pbAtr + sizeof(SCARD_IO_REQUEST), InputBufferLength - sizeof(SCARD_IO_REQUEST));

		// SCARD_IO_REQUEST + SCARD_T0_COMMAND + data
		if (pio->dwProtocol != SCARD_PROTOCOL_T0 || 
			cbPciLength < sizeof(SCARD_IO_REQUEST) ||		
			InputBufferLength < cbPciLength ||
			((InputBufferLength -= cbPciLength) < sizeof(SCARD_T0_COMMAND) - sizeof(BYTE) ||
			(OutputBufferLength < sizeof(SCARD_IO_REQUEST) + sizeof(USHORT)))
			)
		{
			DbgPrint("!!!!!!!!!!!!!!!!!!!!!!!! %x %x\n", InputBufferLength, OutputBufferLength);
			return STATUS_INVALID_PARAMETER;
		}

		OutputBufferLength -= sizeof(SCARD_IO_REQUEST) + sizeof(USHORT);

		// fix error in user mode code (SCardSvr.dll) !
		if (0x110 - (sizeof(SCARD_IO_REQUEST) + sizeof(USHORT)) == OutputBufferLength)
		{
			OutputBufferLength = 0x100;
		}

		status = STATUS_DELETE_PENDING;

		if (ExAcquireRundownProtection(&_scRP))
		{
			status = _pSC->Transmit(pbAtr + cbPciLength, InputBufferLength, 
				(PBYTE)(pio + 1), OutputBufferLength, &OutputBufferLength);

			ExReleaseRundownProtection(&_scRP);
		}

		if (0 <= status)
		{
			Irp->IoStatus.Information = sizeof(SCARD_IO_REQUEST) + OutputBufferLength;
			pio->cbPciLength = sizeof(SCARD_IO_REQUEST);
		}
		return status;

	case IOCTL_SMARTCARD_GET_STATE:
		DbgPrint("{GET_STATE}->%x\n", _dwCardState);
		return SetUlong(Irp, OutputBufferLength, _dwCardState);//SCARD_SPECIFIC

	case IOCTL_SMARTCARD_IS_PRESENT:
		DbgPrint("{IS_PRESENT}(%p, card=%p)\n", Irp, _pSC);
		return IoCsqInsertIrp(Irp, &_isPresent, (PVOID)true);
		
	case IOCTL_SMARTCARD_IS_ABSENT:
		DbgPrint("{IS_ABSENT}(%p, card=%p)\n", Irp, _pSC);
		return IoCsqInsertIrp(Irp, &_isAbsent, (PVOID)false);
	}
}

void SC_DEVICE_EXTENSION::OnDeviceInterfaceChange(Action a, ULONG hash, PUNICODE_STRING SymbolicLinkName)
{
	if (ExAcquireRundownProtection(this))
	{
		KeEnterCriticalRegion();
		ExfAcquirePushLockExclusive(&_scLock);

		switch (a)
		{
		case Arrival:

			if (!_pSC && 0 <= OpenContainer(SymbolicLinkName, hash, &_pSC))
			{
				DbgPrint("!! OpenContainer OK !!\n");
				_dwCardState = SCARD_SWALLOWED;

				ExReInitializeRundownProtection(&_scRP);
				CompleteAllPending(&_isPresent, STATUS_SUCCESS);
			}
			break;

		case Removal:

			if (_pSC && (!SymbolicLinkName || _pSC->m_hash == hash))
			{
				ExWaitForRundownProtectionRelease(&_scRP);
				DbgPrint("remove SC<%p>\n", _pSC);
				delete _pSC, _pSC = 0;
				ExRundownCompleted(&_scRP);
				CompleteAllPending(&_isAbsent, STATUS_SUCCESS);
			}
			break;

		default: __assume(false);
		}

		ExfReleasePushLockExclusive(&_scLock);
		KeLeaveCriticalRegion();

		ExReleaseRundownProtection(this);
	}
}

void SC_DEVICE_EXTENSION::OnDeviceInterfaceChange(Action a, PUNICODE_STRING SymbolicLinkName)
{
	ULONG hash;
	RtlHashUnicodeString(SymbolicLinkName, FALSE, HASH_STRING_ALGORITHM_DEFAULT, &hash);
	DbgPrint("OnDeviceInterfaceChange(%x [%08x] %wZ)\n", a, hash, SymbolicLinkName);

	OnDeviceInterfaceChange(a, hash, SymbolicLinkName);
}

void SC_DEVICE_EXTENSION::OnDeviceInterfaceChange(PDEVICE_INTERFACE_CHANGE_NOTIFICATION Notification)
{
	if (Notification->InterfaceClassGuid != GUID_DEVINTERFACE_VOLUME)
	{
		return ;
	}

	Action a;
	if (Notification->Event == GUID_DEVICE_INTERFACE_ARRIVAL)
	{
		a = Arrival;
	}
	else if (Notification->Event == GUID_DEVICE_INTERFACE_REMOVAL)
	{
		a = Removal;
	}
	else return ;

	OnDeviceInterfaceChange(a, Notification->SymbolicLinkName);
}

NTSTATUS CALLBACK AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject)
{
	DbgPrint("[%p]:AddDevice(%p, %p %x %x)\n", PsGetCurrentThreadId(), DriverObject, PhysicalDeviceObject, PhysicalDeviceObject->Characteristics, PhysicalDeviceObject->DeviceType);

	STATIC_UNICODE_STRING(name, "\\device\\{7C65CD5F-51A1-43a2-A558-D6B77AEFFD11}");
	
	NTSTATUS status;
	PDEVICE_OBJECT DeviceObject;

	if (0 <= (status = IoCreateDevice(DriverObject, sizeof(SC_DEVICE_EXTENSION), 
		const_cast<PUNICODE_STRING>(&name), FILE_DEVICE_SMARTCARD, 
		PhysicalDeviceObject->Characteristics & FILE_DEVICE_SECURE_OPEN, 
		FALSE, &DeviceObject)))
	{
		DeviceObject->Flags |= PhysicalDeviceObject->Flags & 
			(DO_BUFFERED_IO|DO_DIRECT_IO|DO_SUPPORTS_TRANSACTIONS|DO_POWER_PAGABLE|DO_POWER_INRUSH);

		SC_DEVICE_EXTENSION* fdo = new(DeviceObject) SC_DEVICE_EXTENSION;

		fdo->_PhysicalDeviceObject = PhysicalDeviceObject;

		if (0 <= (status = IoAttachDeviceToDeviceStackSafe(DeviceObject, PhysicalDeviceObject, &fdo->_nextDeviceObject)))
		{
			if (0 <= (status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange,
				PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES, 
				const_cast<GUID*>(&GUID_DEVINTERFACE_VOLUME), DriverObject, 
				SC_DEVICE_EXTENSION::_OnDeviceInterfaceChange, fdo, 
				&fdo->_NotificationEntryVolume)))
			{
				DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

				DbgPrint("AttachDevice(my=%p(%x),to=%p)\n", DeviceObject, DeviceObject->Characteristics, fdo->_nextDeviceObject);

				return STATUS_SUCCESS;
			}

			IoDetachDevice(fdo->_nextDeviceObject);
		}

		IoDeleteDevice(DeviceObject);
	}

	return status;
}

VOID CALLBACK DriverUnload([[maybe_unused]] PDRIVER_OBJECT DriverObject)
{
	DbgPrint("DriverUnload(%p)\n", DriverObject);
}

NTSTATUS NTAPI DriverEntry(PDRIVER_OBJECT DriverObject, [[maybe_unused]] PUNICODE_STRING RegistryPath)
{
	DbgPrint("%wZ %p %s\n", RegistryPath, DriverObject, __TIMESTAMP__);

	__stosp(DriverObject->MajorFunction, SC_DEVICE_EXTENSION::_CommonDispatch, RTL_NUMBER_OF(DriverObject->MajorFunction));

	DriverObject->DriverExtension->AddDevice = AddDevice;
	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}

_NT_END
