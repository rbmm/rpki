#include "stdafx.h"
#ifdef _DBG_

_NT_BEGIN
#undef MAKE_CASE
#define MAKE_CASE(scsiOpCode) case scsiOpCode: return #scsiOpCode;

PCSTR MajorMinorFunctionString(UCHAR MajorFunction, UCHAR MinorFunction, PCSTR& mnstr);

PCSTR PnPMinorFunctionString(IN UCHAR MinorFunction) { 
	switch (MinorFunction) { 
	case IRP_MN_START_DEVICE:                 return "START_DEVICE"; 
	case IRP_MN_QUERY_REMOVE_DEVICE:          return "QUERY_REMOVE_DEVICE"; 
	case IRP_MN_REMOVE_DEVICE:                return "REMOVE_DEVICE"; 
	case IRP_MN_CANCEL_REMOVE_DEVICE:         return "CANCEL_REMOVE_DEVICE"; 
	case IRP_MN_STOP_DEVICE:                  return "STOP_DEVICE"; 
	case IRP_MN_QUERY_STOP_DEVICE:            return "QUERY_STOP_DEVICE"; 
	case IRP_MN_CANCEL_STOP_DEVICE:           return "CANCEL_STOP_DEVICE"; 
	case IRP_MN_QUERY_DEVICE_RELATIONS:       return "QUERY_DEVICE_RELATIONS"; 
	case IRP_MN_QUERY_INTERFACE:              return "QUERY_INTERFACE"; 
	case IRP_MN_QUERY_CAPABILITIES:           return "QUERY_CAPABILITIES"; 
	case IRP_MN_QUERY_RESOURCES:              return "QUERY_RESOURCES"; 
	case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:  return "QUERY_RESOURCE_REQUIREMENTS"; 
	case IRP_MN_QUERY_DEVICE_TEXT:            return "QUERY_DEVICE_TEXT"; 
	case IRP_MN_FILTER_RESOURCE_REQUIREMENTS: return "FILTER_RESOURCE_REQUIREMENTS"; 
	case IRP_MN_READ_CONFIG:                  return "READ_CONFIG"; 
	case IRP_MN_WRITE_CONFIG:                 return "WRITE_CONFIG"; 
	case IRP_MN_EJECT:                        return "EJECT"; 
	case IRP_MN_SET_LOCK:                     return "SET_LOCK"; 
	case IRP_MN_QUERY_ID:                     return "QUERY_ID"; 
	case IRP_MN_QUERY_PNP_DEVICE_STATE:       return "QUERY_PNP_DEVICE_STATE"; 
	case IRP_MN_QUERY_BUS_INFORMATION:        return "QUERY_BUS_INFORMATION"; 
	case IRP_MN_DEVICE_USAGE_NOTIFICATION:    return "DEVICE_USAGE_NOTIFICATION"; 
	case IRP_MN_SURPRISE_REMOVAL:             return "SURPRISE_REMOVAL"; 
	case IRP_MN_QUERY_LEGACY_BUS_INFORMATION: return "QUERY_LEGACY_BUS_INFORMATION"; 
	default:                                  return "UNKNOWN"; 
	} 
} 

PCSTR SystemControlMinorFunctionString(IN UCHAR MinorFunction) { 
	switch (MinorFunction) { 
	case IRP_MN_QUERY_ALL_DATA:         return "QUERY_ALL_DATA"; 
	case IRP_MN_QUERY_SINGLE_INSTANCE:  return "QUERY_SINGLE_INSTANCE"; 
	case IRP_MN_CHANGE_SINGLE_INSTANCE: return "CHANGE_SINGLE_INSTANCE"; 
	case IRP_MN_CHANGE_SINGLE_ITEM:     return "CHANGE_SINGLE_ITEM"; 
	case IRP_MN_ENABLE_EVENTS:          return "ENABLE_EVENTS"; 
	case IRP_MN_DISABLE_EVENTS:         return "DISABLE_EVENTS"; 
	case IRP_MN_ENABLE_COLLECTION:      return "ENABLE_COLLECTION"; 
	case IRP_MN_DISABLE_COLLECTION:     return "DISABLE_COLLECTION"; 
	case IRP_MN_REGINFO:                return "REGINFO"; 
	case IRP_MN_EXECUTE_METHOD:         return "EXECUTE_METHOD"; 
		//    case IRP_MN_REGINFO_EX:             return "REGINFO_EX"; 
	default:                            return "UNKNOWN"; 
	} 
} 

PCSTR PowerMinorFunctionString(IN UCHAR MinorFunction) { 
	switch (MinorFunction) { 
	case IRP_MN_WAIT_WAKE:      return "WAIT_WAKE"; 
	case IRP_MN_POWER_SEQUENCE: return "POWER_SEQUENCE"; 
	case IRP_MN_SET_POWER:      return "SET_POWER"; 
	case IRP_MN_QUERY_POWER:    return "QUERY_POWER"; 
	default:                    return "UNKNOWN"; 
	} 
} 

PCSTR MajorMinorFunctionString(UCHAR MajorFunction, UCHAR MinorFunction, PCSTR& mnstr) {
	static PCSTR empty = "";
	mnstr = empty;
	switch (MajorFunction) { 
	case IRP_MJ_CREATE:                   return "CREATE"; 
	case IRP_MJ_CLOSE:                    return "CLOSE"; 
	case IRP_MJ_READ:                     return "READ"; 
	case IRP_MJ_WRITE:                    return "WRITE"; 
	case IRP_MJ_QUERY_INFORMATION:        return "QUERY_INFORMATION"; 
	case IRP_MJ_SET_INFORMATION:          return "SET_INFORMATION"; 
	case IRP_MJ_QUERY_EA:                 return "QUERY_EA"; 
	case IRP_MJ_SET_EA:                   return "SET_EA"; 
	case IRP_MJ_FLUSH_BUFFERS:            return "FLUSH_BUFFERS"; 
	case IRP_MJ_QUERY_VOLUME_INFORMATION: return "QUERY_VOLUME_INFORMATION"; 
	case IRP_MJ_SET_VOLUME_INFORMATION:   return "SET_VOLUME_INFORMATION"; 
	case IRP_MJ_DIRECTORY_CONTROL:        return "DIRECTORY_CONTROL"; 
	case IRP_MJ_FILE_SYSTEM_CONTROL:      return "FILE_SYSTEM_CONTROL"; 
	case IRP_MJ_DEVICE_CONTROL:           return "DEVICE_CONTROL"; 
	case IRP_MJ_SCSI:                     return "SCSI"; 
	case IRP_MJ_SHUTDOWN:                 return "SHUTDOWN"; 
	case IRP_MJ_LOCK_CONTROL:             return "LOCK_CONTROL"; 
	case IRP_MJ_CLEANUP:                  return "CLEANUP"; 
	case IRP_MJ_QUERY_SECURITY:           return "QUERY_SECURITY"; 
	case IRP_MJ_SET_SECURITY:             return "SET_SECURITY"; 
	case IRP_MJ_POWER:        
		mnstr = PowerMinorFunctionString(MinorFunction);
		return "POWER"; 
	case IRP_MJ_SYSTEM_CONTROL:           
		mnstr = SystemControlMinorFunctionString(MinorFunction);
		return "SYSTEM_CONTROL"; 
	case IRP_MJ_DEVICE_CHANGE:            return "DEVICE_CHANGE"; 
	case IRP_MJ_QUERY_QUOTA:              return "QUERY_QUOTA"; 
	case IRP_MJ_SET_QUOTA:                return "SET_QUOTA"; 
	case IRP_MJ_PNP:                      
		mnstr = PnPMinorFunctionString(MinorFunction);
		return "PNP"; 
	default:                              return "UNKNOWN"; 
	} 
} 

PCSTR QueryDeviceRelationsString(DEVICE_RELATION_TYPE Type) { 
	switch (Type) { 
	case BusRelations:         return "BusRelations"; 
	case EjectionRelations:    return "EjectionRelations"; 
	case PowerRelations:       return "PowerRelations"; 
	case RemovalRelations:     return "RemovalRelations"; 
	case TargetDeviceRelation: return "TargetDeviceRelation"; 
	default:                   return "UnknownRelation"; 
	} 
} 

PCSTR QueryIdString(int IdType) { 
	switch (IdType) { 
	case BusQueryDeviceID:           return "BusQueryDeviceID"; 
	case BusQueryHardwareIDs:        return "BusQueryHardwareIDs"; 
	case BusQueryCompatibleIDs:      return "BusQueryCompatibleIDs"; 
	case BusQueryInstanceID:         return "BusQueryInstanceID"; 
	case BusQueryDeviceSerialNumber: return "BusQueryDeviceSerialNumber"; 
	case ~DeviceTextDescription:         return "DeviceTextDescription"; 
	case ~DeviceTextLocationInformation: return "DeviceTextLocationInformation"; 
	default:                         return "BusQueryUnknown"; 
	} 
} 

void DumpBytes(const BYTE* pb, ULONG cb, PCSTR prefix)
{
	if (cb)
	{
		DbgPrint("%s<![CDATA[ // [%x]\n", prefix, cb);

		size_t len = strlen(prefix);

		if (len < 16)
		{
			do 
			{
				ULONG m = min(16, cb);
				cb -= m;
				char buf[16+3*16+2], *sz = buf + len;
				memcpy(buf, prefix, len);

				do 
				{
					if (3 != sprintf_s(sz, 4, "%02x ",*pb++))
					{
						return;
					}
					sz += 3;
				} while (--m);

				*sz++ = '\n', *sz++ = 0;

				DbgPrint(buf);

			} while (cb);
		}
		DbgPrint("%s]]>\n", prefix);
	}
}

_NT_END

#endif // _DBG_