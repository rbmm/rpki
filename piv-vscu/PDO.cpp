#include "StdAfx.h"

_NT_BEGIN

#include "common.h"

NTSTATUS PDO::PnP(PDEVICE_OBJECT DeviceObject, PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
	ULONG_PTR Information = Irp->IoStatus.Information;

	Irp->IoStatus.Information = 0;

	DbgPrint("%p>PDO::PnP(%x)- %s [%p] %p %p\n", Irp, IrpSp->MinorFunction, 
		PnPMinorFunctionString(IrpSp->MinorFunction), Information,
		Irp->Tail.Overlay.Thread, KeGetCurrentThread());

	NTSTATUS status = STATUS_NOT_IMPLEMENTED;

	LPWSTR Id = 0;
	PPNP_BUS_INFORMATION pbi;

	PDEVICE_CAPABILITIES deviceCapabilities;

	switch(IrpSp->MinorFunction)
	{
	case IRP_MN_START_DEVICE:

		status = IoRegisterDeviceInterface(DeviceObject, &SmartCardReaderGuid, 0, this);
		DbgPrint("IoRegisterDeviceInterface(%x %wZ)\n", status, static_cast<PCUNICODE_STRING>(this));
		if (0 <= status)
		{
			status = IoSetDeviceInterfaceState(this, TRUE);
		}
		break;

	case IRP_MN_STOP_DEVICE:
		DbgPrint("pdo<%p>:STOP_DEVICE\n", DeviceObject);
		break;
	
	case IRP_MN_SURPRISE_REMOVAL:
		DbgPrint("SURPRISE_REMOVAL:%p\n", DeviceObject);
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_REMOVE_DEVICE:

		DbgPrint("QUERY_REMOVE_DEVICE(%x)\n", _RemoveOk);
		CancelAllPending();
		if (!_RemoveOk)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}
		status = STATUS_SUCCESS;
		DbgPrint("remove can!\n");
		break;

	case IRP_MN_EJECT:
	case IRP_MN_CANCEL_REMOVE_DEVICE:
	case IRP_MN_QUERY_STOP_DEVICE:
	case IRP_MN_CANCEL_STOP_DEVICE:
	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
	case IRP_MN_QUERY_RESOURCES:
	case IRP_MN_QUERY_PNP_DEVICE_STATE:
	case IRP_MN_DEVICE_ENUMERATED:
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_BUS_INFORMATION:
		status = STATUS_INSUFFICIENT_RESOURCES;
		if (pbi = (PPNP_BUS_INFORMATION)ExAllocatePool(PagedPool, sizeof(PNP_BUS_INFORMATION)))
		{
			status = STATUS_SUCCESS;
			Irp->IoStatus.Information = (ULONG_PTR)pbi;
			pbi->LegacyBusType = PNPBus;
			pbi->BusTypeGuid = GUID_BUS_TYPE_USB;
		}
		break;

	case IRP_MN_QUERY_DEVICE_TEXT:

		switch(IrpSp->Parameters.QueryDeviceText.DeviceTextType)
		{
		case DeviceTextDescription:
			IrpSp->Parameters.QueryId.IdType=(BUS_QUERY_ID_TYPE)~DeviceTextDescription;
			break;
		case DeviceTextLocationInformation:
			IrpSp->Parameters.QueryId.IdType=(BUS_QUERY_ID_TYPE)~DeviceTextLocationInformation;
			break;
		}

	case IRP_MN_QUERY_ID:

		DbgPrint("%s\n", QueryIdString(IrpSp->Parameters.QueryId.IdType));

		status = STATUS_INSUFFICIENT_RESOURCES;

		if (Id = (PWSTR)ExAllocatePool(PagedPool, 128))
		{
			status = STATUS_SUCCESS;
			Irp->IoStatus.Information = (ULONG_PTR)Id;

#define SET_ID(str) memcpy(Id, L##str, sizeof(L##str));break

			switch ((int)IrpSp->Parameters.QueryId.IdType) 
			{
			case BusQueryCompatibleIDs:
				SET_ID("GenDisk\0");
				break;
			case BusQueryHardwareIDs:
				SET_ID("(BBC)\0");
			case BusQueryInstanceID:
				swprintf(Id, L"%08X#%04X#%04X#%016I64X", Data1, Data2, Data3, *(PULONGLONG)Data4);
				break;
			case BusQueryDeviceID:
				SET_ID("USBSTOR\\(BBC)");
			case ~DeviceTextDescription:
				SET_ID("Compatible USB storage device");
			case ~DeviceTextLocationInformation:
				SET_ID("(BBC) USB Flash drive");
			default:
				SET_ID("DEVICE_TEXT\0");
				break;
			}
		}
		break;

	case IRP_MN_QUERY_CAPABILITIES:
		deviceCapabilities = IrpSp->Parameters.DeviceCapabilities.Capabilities;
		deviceCapabilities->Removable = TRUE;//!!!
		deviceCapabilities->LockSupported = TRUE;//!!!
		deviceCapabilities->EjectSupported = TRUE;//!!!
		deviceCapabilities->SurpriseRemovalOK = FALSE;
		deviceCapabilities->HardwareDisabled = FALSE;
		deviceCapabilities->NoDisplayInUI = FALSE;
		deviceCapabilities->UniqueID = TRUE;
		status = STATUS_SUCCESS;
		break;

	case IRP_MN_QUERY_DEVICE_RELATIONS:

		DbgPrint("%p>PDO:QueryDeviceRelations(%s) %p\n", Irp, QueryDeviceRelationsString(IrpSp->Parameters.QueryDeviceRelations.Type),Irp->IoStatus.Information);

		switch (IrpSp->Parameters.QueryDeviceRelations.Type)
		{
		case EjectionRelations:
			_RemoveOk = TRUE;
		case RemovalRelations:
			if (!Information)
			{
				status = STATUS_NOT_SUPPORTED;
				break;
			}
			goto DEFAULT;
		case TargetDeviceRelation:
			free((PDEVICE_RELATIONS)Information);
			status = STATUS_INSUFFICIENT_RESOURCES;

			if (PDEVICE_RELATIONS p = (PDEVICE_RELATIONS)ExAllocatePool(PagedPool, sizeof(DEVICE_RELATIONS)))
			{
				p->Count = 1;
				p->Objects[0] = DeviceObject;
				ObfReferenceObject(DeviceObject);

				Irp->IoStatus.Information = (ULONG_PTR)p;
				status = STATUS_SUCCESS;
			}
			break;
		default: DEFAULT:
			status = Irp->IoStatus.Status;
			Irp->IoStatus.Information = Information;
			break;
		}

		break;

	case IRP_MN_REMOVE_DEVICE:
		DbgPrint("IRP_MN_REMOVE_DEVICE:%p %u %u\n", DeviceObject, _RemovePending, _Enumerated);

		_RemovePending = TRUE;

		if (!_Enumerated)
		{
			DbgPrint("%p>++ExWaitForRundownProtectionRelease(%p)\n", PsGetCurrentThread(), Ptr);
			ExWaitForRundownProtectionRelease(this);
			DbgPrint("%p>--ExWaitForRundownProtectionRelease(%p)\n", PsGetCurrentThread(), Ptr);

			DbgPrint("-= delete PDO =-\n");
			IoDeleteDevice(DeviceObject);
		}

		status = STATUS_SUCCESS;
		break;
	} 

	Irp->IoStatus.Status = status;
	IofCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

_NT_END