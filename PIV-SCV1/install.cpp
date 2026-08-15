#include "stdafx.h"
#include "zip.h"
#include "resource.h"

#define DbgPrint /##/

EXTERN_C extern UCHAR drv_begin[], drv_end[], mini_begin[], mini_end[];

#include <initguid.h>
#include <devguid.h>

#define _Owner_ Rbmm
#define _OwnerA_ _CRT_STRINGIZE(_Owner_)
#define _OwnerW_ _CRT_WIDE(_OwnerA_)

_NT_BEGIN
//struct __declspec(uuid("d86354cc-a2ac-4223-95b9-2e48ce154434")) GUID_DEVINTERFACE_SCFILTER;
//struct __declspec(uuid("084f9363-e31a-4bde-9ca5-6fa0d86e009f")) GUID_DEVINTERFACE_SMARTCARD;

#define EXTERN_WSTRING(name, str) extern const WCHAR name[] = echo(L)str

STATIC_WSTRING(_S_, "\\");
STATIC_WSTRING(_R_, "#");
STATIC_WSTRING(__Y_, "##?#");
STATIC_WSTRING(CID_ATR, "CID_e2f748f9-db8b-4c08-a258-583d8955d94a");
EXTERN_WSTRING(MyId, "{7C65CD5F-51A1-43a2-A558-D6B77AEFFD11}");
EXTERN_WSTRING(Device, "\\Device\\");
STATIC_WSTRING(CurrentControlSet, "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\");
STATIC_WSTRING(Services, "Services\\");
STATIC_WSTRING(Enum, "Enum\\");
STATIC_WSTRING(Control, "Control\\");
STATIC_WSTRING(Class, "Class\\");
STATIC_WSTRING(DeviceClasses, "DeviceClasses\\");
STATIC_WSTRING(DeviceContainers, "DeviceContainers\\");
STATIC_WSTRING_(SCFILTER);

STATIC_WSTRING(_892EDE5E_BE49_443c_A0B3_005D74F2D69C_, "{892EDE5E-BE49-443c-A0B3-005D74F2D69C}");
STATIC_WSTRING(_084f9363_e31a_4bde_9ca5_6fa0d86e009f_, "{084f9363-e31a-4bde-9ca5-6fa0d86e009f}");
STATIC_WSTRING(_d86354cc_a2ac_4223_95b9_2e48ce154434_, "{d86354cc-a2ac-4223-95b9-2e48ce154434}");
STATIC_WSTRING(_50dd5230_ba8a_11d1_bf5d_0000f805f530_, "{50dd5230-ba8a-11d1-bf5d-0000f805f530}");

STATIC_WSTRING(system32, "\\systemroot\\system32\\");
STATIC_WSTRING(drivers, "drivers\\");
STATIC_WSTRING(sys, ".sys");
STATIC_WSTRING(dll, ".dll");
STATIC_WSTRING(Description, "RBMM Virtual Smart Card Reader PV1");
STATIC_WSTRING_(SCPolicySvc);
STATIC_WSTRING_(CertPropSvc);
STATIC_WSTRING_(SCardSvr);

// ##?# SCFILTER # CID_5F52424D4D32 #
#define DeviceClasses_SMARTCARD      __Y_, SCFILTER, _R_, CID_ATR, _R_, 0

// ##?# {892EDE5E-BE49-443c-A0B3-005D74F2D69C} # ScFilter # *&*&*&
#define DeviceClasses_SCFILTER(id)   __Y_, _892EDE5E_BE49_443c_A0B3_005D74F2D69C_, _R_, SCFILTER, _R_, id, 0

#define DriverKey(id)                CurrentControlSet, Control, Class, id, 0
#define Control_DeviceContainers(id) CurrentControlSet, Control, DeviceContainers, id, 0
#define DeviceClass_Sc               CurrentControlSet, Control, DeviceClasses, _084f9363_e31a_4bde_9ca5_6fa0d86e009f_, 0
#define DeviceClass_Filter           CurrentControlSet, Control, DeviceClasses, _d86354cc_a2ac_4223_95b9_2e48ce154434_, 0

#define ScFilter                     CurrentControlSet, Enum, _892EDE5E_BE49_443c_A0B3_005D74F2D69C_, 0
#define Enum_SCFILTER                CurrentControlSet, Enum, SCFILTER, 0
#define Enum_SCFILTER_CID            CurrentControlSet, Enum, SCFILTER, _S_, CID_ATR, 0

#define MySrvKey                     CurrentControlSet, Services, MyId, 0

#define MyDriverFile                 system32, drivers, MyId, sys, 0
#define MyMiniFile                   system32, MyId, dll, 0

#define MyDevice                     Device, MyId, _S_, 0

USHORT MyDevicePathLen()
{
	return sizeof(Device) + sizeof(MyId) - 2 * sizeof(WCHAR);
}

int FormatDeviceID(PWSTR buf, ULONG cch)
{
	return swprintf_s(buf, cch, L"Root\\%ws\\0000", MyId);
}

NTSTATUS AdjustPrivileges()
{
	HANDLE hToken;

	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (0 <= status)
	{
		BEGIN_PRIVILEGES(tp, 4)
			LAA(SE_BACKUP_PRIVILEGE),
			LAA(SE_RESTORE_PRIVILEGE),
			LAA(SE_DEBUG_PRIVILEGE),
			LAA(SE_LOAD_DRIVER_PRIVILEGE)
		END_PRIVILEGES	
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(&tp), 0, 0, 0);
		NtClose(hToken);
	}
	return status;
}

struct SB : public OBJECT_ATTRIBUTES, UNICODE_STRING 
{
	SB(PWSTR Buf = reinterpret_cast<_TEB*>(NtCurrentTeb())->StaticUnicodeBuffer);
	SB* operator()(PCWSTR str, ...);
};

SB::SB(PWSTR Buf)
{
	Buffer = Buf;
	OBJECT_ATTRIBUTES::Length = sizeof(OBJECT_ATTRIBUTES);
	UNICODE_STRING::Length = 0;
	RootDirectory = 0;
	ObjectName = this;
	Attributes = OBJ_CASE_INSENSITIVE;
	SecurityDescriptor = 0;
	SecurityQualityOfService = 0;
}

SB* SB::operator()(PCWSTR str, ...)
{
	PCWSTR* ppsz = &str;
	PBYTE Buf = (PBYTE)Buffer;
	size_t cb;

	do 
	{
		memcpy(Buf, str, cb = wcslen(str) * sizeof(WCHAR)), Buf += cb;
	} while (str = *++ppsz);

	*(PWSTR)Buf = 0;
	cb = Buf - (PBYTE)Buffer;
	MaximumLength = (USHORT)cb;
	UNICODE_STRING::Length = (USHORT)cb;

	return this;
}

BOOL StopService(SC_HANDLE hSCManager, PCWSTR lpServiceName, BOOL bDelete = FALSE)
{
	BOOL fOk = FALSE;

	DbgPrint("StopService(%ws)...\r\n", lpServiceName);

	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, 
		bDelete ? DELETE|SERVICE_STOP|SERVICE_QUERY_STATUS : SERVICE_STOP|SERVICE_QUERY_STATUS))
	{
		union {
			FILETIME ft;
			LARGE_INTEGER CurrentTime;
		};

		GetSystemTimeAsFileTime(&ft);

		union {
			SERVICE_STATUS ss;
			SERVICE_STATUS_PROCESS ssp;
		};

		ULONG cbBytesNeeded;

		if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PUCHAR)&ssp, sizeof(ssp), &cbBytesNeeded))
		{
			DbgPrint("SS(%x %u %x(%x))\r\n", ss.dwServiceType, ssp.dwCurrentState, ssp.dwWin32ExitCode, ssp.dwServiceSpecificExitCode);

			if (ssp.dwCurrentState != SERVICE_STOPPED)
			{
				if (ControlService(hService, SERVICE_CONTROL_STOP, &ss))
				{
					if (SERVICE_WIN32_OWN_PROCESS == ss.dwServiceType)
					{
						if (HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE, 0, ssp.dwProcessId))
						{
							DbgPrint("process opened\r\n");
							KERNEL_USER_TIMES kut;
							if (0 <= NtQueryInformationProcess(hProcess, ProcessTimes, &kut, sizeof(kut), &cbBytesNeeded))
							{
								if (kut.CreateTime.QuadPart < CurrentTime.QuadPart)
								{
									DbgPrint("process is correct\r\n");

									cbBytesNeeded = GetTickCount();

									if (WAIT_OBJECT_0 == WaitForSingleObject(hProcess, 3000))
									{
										DbgPrint("wait ok[%u]\r\n", GetTickCount() - GetTickCount());
										fOk = TRUE;
									}
								}
							}

							NtClose(hProcess);
						}
						else
						{
							DbgPrint("openprocess = %x\r\n", RtlGetLastNtStatus());
						}
					}
					else
					{
						ULONG64 t = GetTickCount64() + 2000;
						do 
						{
							Sleep(50);
						} while (QueryServiceStatus(hService, &ss) && 
							ss.dwCurrentState != SERVICE_STOPPED &&
							GetTickCount64() < t);

						DbgPrint("SS(%u %x(%x))\r\n", ss.dwCurrentState, ss.dwWin32ExitCode, ss.dwServiceSpecificExitCode);

						fOk = (ss.dwCurrentState == SERVICE_STOPPED);
					}
				}
				else
				{
					DbgPrint("SERVICE_CONTROL_STOP=%u\r\n", GetLastError());
				}
			}
		}

		if (bDelete && !DeleteService(hService))
		{
			DbgPrint("DeleteService = %u\r\n", GetLastError());
		}

		CloseServiceHandle(hService);
	}

	return fOk;
}

void StopServices(PLONG mask)
{
	if (SC_HANDLE hSCManager = OpenSCManager(0, 0, 0))
	{
		if (StopService(hSCManager, SCPolicySvc)) _bittestandset(mask, 0);
		if (StopService(hSCManager, CertPropSvc)) _bittestandset(mask, 1);
		if (StopService(hSCManager, SCardSvr)) _bittestandset(mask, 2);
		CloseServiceHandle(hSCManager);
	}
}

void StartService(SC_HANDLE hSCManager, PCWSTR lpServiceName)
{
	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, SERVICE_START))
	{
		StartServiceW(hService, 0, 0);
		CloseServiceHandle(hService);
	}
}

void RestartServices(LONG mask)
{
	if (SC_HANDLE hSCManager = OpenSCManager(0, 0, 0))
	{
		if (_bittest(&mask, 2)) StartService(hSCManager, SCardSvr);
		if (_bittest(&mask, 1)) StartService(hSCManager, CertPropSvc);
		if (_bittest(&mask, 0)) StartService(hSCManager, SCPolicySvc);
		CloseServiceHandle(hSCManager);
	}
}

void UnloadDriver()
{
	DEVINST dnDevInst, dnChild;
	WCHAR buf[0x40];

	FormatDeviceID(buf, _countof(buf));

	CONFIGRET cr = CM_Locate_DevNodeW(&dnDevInst, buf, CM_LOCATE_DEVNODE_NORMAL);

	DbgPrint("Locate_DevNode=%x\r\n", cr);

	if (cr == CR_SUCCESS)
	{
		PNP_VETO_TYPE VetoType;
		WCHAR szVetoName[0x100];

		cr = CM_Get_Child(&dnChild, dnDevInst, 0);

		DbgPrint("CM_Get_Child=%x\r\n", cr);

		if (CR_SUCCESS == cr)
		{		
			cr = CM_Query_And_Remove_SubTreeW(dnChild, &VetoType, szVetoName, _countof(szVetoName), CM_REMOVE_NO_RESTART);			

			DbgPrint("Query_And_Remove(child)=%x\r\n", cr);

			if (cr)
			{
				DbgPrint("Veto: %x %ws\r\n", VetoType, szVetoName);
			}

			cr = CM_Uninstall_DevNode(dnChild, 0);

			DbgPrint("Uninstall_DevNode(child)=%x\r\n", cr);
		}

		cr = CM_Disable_DevNode(dnDevInst, 0);

		DbgPrint("Disable_DevNode=%x\r\n", cr);

		cr = CM_Query_And_Remove_SubTreeW(dnDevInst, &VetoType, szVetoName, _countof(szVetoName), CM_REMOVE_NO_RESTART);

		DbgPrint("Query_And_Remove=%x\r\n", cr);

		if (cr)
		{
			DbgPrint("Veto: %x %ws\r\n", VetoType, szVetoName);
		}

		cr = CM_Uninstall_DevNode(dnDevInst, 0);

		DbgPrint("Uninstall_DevNode=%x\r\n", cr);
	}
}

STATIC_ASTRING(_G_prefix, "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t");

#define PF(Level) &_G_prefix[_countof(_G_prefix) - 1 - Level]

BOOL GetKeyInfo(HANDLE hKey, ULONG& SubKeys, ULONG& MaxNameLen)
{
	KEY_FULL_INFORMATION kfi;

	switch (ZwQueryKey(hKey, KeyFullInformation, &kfi, sizeof(kfi), &kfi.TitleIndex))
	{
	case 0:
	case STATUS_BUFFER_OVERFLOW:
		SubKeys = kfi.SubKeys, MaxNameLen = kfi.MaxNameLen;
		return TRUE;
	}

	return FALSE;
}

enum { fl_EmumSubKeys = 1, fl_DeleteKey = 2 };

NTSTATUS DeleteKey(PCOBJECT_ATTRIBUTES poa,
				   ULONG Level = 0, 
				   LONG (*fn)(PCUNICODE_STRING ObjectName, HANDLE hKey, ULONG Level, PVOID Context) = 0, 
				   PVOID Context = 0)
{
	UNICODE_STRING ObjectName;

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = ZwOpenKeyEx(&oa.RootDirectory, KEY_READ|DELETE|KEY_WOW64_64KEY, const_cast<POBJECT_ATTRIBUTES>(poa), REG_OPTION_BACKUP_RESTORE);

	DbgPrint("%hsopen(%wZ) = %x\r\n", PF(Level), poa->ObjectName, status);

	if (0 <= status)
	{
		LONG f = fn ? fn(poa->ObjectName, oa.RootDirectory, Level, Context) : fl_EmumSubKeys | fl_DeleteKey;

		if (f & fl_EmumSubKeys)
		{
			ULONG SubKeys, MaxNameLen;

			if (GetKeyInfo(oa.RootDirectory, SubKeys, MaxNameLen) && SubKeys)
			{
				ObjectName.MaximumLength = (USHORT)MaxNameLen;

				if (PKEY_BASIC_INFORMATION pkni = (PKEY_BASIC_INFORMATION)_malloca(
					MaxNameLen += FIELD_OFFSET(KEY_BASIC_INFORMATION, Name)))
				{
					ObjectName.Buffer = pkni->Name;

					Level++;

					do 
					{
						if (0 <= ZwEnumerateKey(oa.RootDirectory, 
							--SubKeys, KeyBasicInformation, pkni, MaxNameLen, (PULONG)&status))
						{
							ObjectName.Length = (USHORT)pkni->NameLength;
							DeleteKey(&oa, Level, fn, Context);
						}

					} while (SubKeys);

					--Level;

					_freea(pkni);
				}
			}
		}

		if (f & fl_DeleteKey)
		{
			status = ZwDeleteKey(oa.RootDirectory);
			DbgPrint("%hsdelete(%wZ) = %x\r\n", PF(Level), poa->ObjectName, status);
		}

		NtClose(oa.RootDirectory);
	}

	return status;
}

LONG Delete_ScFilter_Key(PCUNICODE_STRING ObjectName, HANDLE hKey, ULONG Level, PVOID Context);

void Process_ScFilter_Key(PCWSTR Prefix)
{
	SB oa;
	UNICODE_STRING str;
	RtlInitUnicodeString(&str, Prefix);

	DbgPrint("\t++ Delete_ScFilter_Key(%ws)\r\n", Prefix);

	DeleteKey(oa(ScFilter), 0, Delete_ScFilter_Key, &str);

	DbgPrint("\t-- Delete_ScFilter_Key(%ws)\r\n", Prefix);
}

BOOL IsRegSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	ULONG DataLength;
	return pkvpi->Type == REG_SZ && (DataLength = pkvpi->DataLength) && 
		!(DataLength & (sizeof(WCHAR) - 1)) &&
		!*(PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength - sizeof(WCHAR));
}

PCWSTR QuerySz(HANDLE hKey, PCWSTR pszValueName, PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi, ULONG cb)
{
	UNICODE_STRING ValueName;
	RtlInitUnicodeString(&ValueName, pszValueName);

	ULONG rcb;
	if (0 <= ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformationAlign64, pkvpi, cb, &rcb) &&
		IsRegSz(pkvpi))
	{
		return (PCWSTR)pkvpi->Data;
	}

	return 0;
}

LONG DeleteByKeyInfo(PCUNICODE_STRING /*ObjectName*/, HANDLE hKey, ULONG Level, PVOID /*Context*/)
{
	if (Level == 1)
	{
		PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi = (PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64)alloca(0x100);

		PCWSTR pcsz;
		SB oa;

		if (pcsz = QuerySz(hKey, L"ContainerID", pkvpi, 0x100))
		{
			GUID guid;
			UNICODE_STRING GuidString;
			RtlInitUnicodeString(&GuidString, pcsz);
			if (0 <= RtlGUIDFromString(&GuidString, &guid))
			{
				DbgPrint("\t++ ContainerID (%ws)\r\n", pcsz);
				DeleteKey(oa(Control_DeviceContainers(pcsz)));
				DbgPrint("\t-- ContainerID (%ws)\r\n", pcsz);
			}
		}

		if (pcsz = QuerySz(hKey, L"Driver", pkvpi, 0x100))
		{
			if (wcslen(pcsz) <= MAX_GUID_STRING_LEN + 4)
			{
				DbgPrint("\t++ DeleteDriverKey (%ws)\r\n", pcsz);
				DeleteKey(oa(DriverKey(pcsz)));
				DbgPrint("\t-- DeleteDriverKey (%ws)\r\n", pcsz);
			}
		}

		if (pcsz = QuerySz(hKey, L"ParentIdPrefix", pkvpi, 0x100))
		{
			Process_ScFilter_Key(pcsz);
		}
	}

	return fl_EmumSubKeys | fl_DeleteKey;
}

LONG Delete_ScFilter_Key(PCUNICODE_STRING ObjectName, HANDLE hKey, ULONG Level, PVOID Context)
{
	switch (Level)
	{
	case 2:
		if (!RtlPrefixUnicodeString(reinterpret_cast<PCUNICODE_STRING>(Context), ObjectName, FALSE))
		{
			return 0;
		}

		DeleteByKeyInfo(0, hKey, 1, 0);
		break;
	}

	return fl_EmumSubKeys | fl_DeleteKey;
}

// \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{084f9363-e31a-4bde-9ca5-6fa0d86e009f}

LONG Delete_DeviceClasses_Sc(PCUNICODE_STRING ObjectName, HANDLE /*hKey*/, ULONG Level, PVOID /*Context*/)
{
	switch (Level)
	{
	case 0:
		return fl_EmumSubKeys;

	case 1:

		SB oa;
		if (!RtlPrefixUnicodeString(oa(DeviceClasses_SMARTCARD), ObjectName, TRUE))
		{
			return 0;
		}
	}

	return fl_EmumSubKeys | fl_DeleteKey;
}

// \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\DeviceClasses\{d86354cc-a2ac-4223-95b9-2e48ce154434}

LONG Delete_DeviceClasses_Filter(PCUNICODE_STRING ObjectName, HANDLE /*hKey*/, ULONG Level, PVOID Context)
{

	switch (Level)
	{
	case 0:
		return fl_EmumSubKeys;

	case 1:
		SB oa;
		if (!RtlPrefixUnicodeString(oa(DeviceClasses_SCFILTER(Context)), ObjectName, TRUE))
		{
			return 0;
		}
	}
	return fl_EmumSubKeys | fl_DeleteKey;
}

LONG Delete_CID_Key(PCUNICODE_STRING ObjectName, HANDLE hKey, ULONG Level, PVOID Context)
{
	if (Level == 1)
	{
		DeleteByKeyInfo(0, hKey, 1, Context);

		if (ULONG cch = ObjectName->Length / sizeof(WCHAR))
		{
			PWSTR pcsz = ObjectName->Buffer;
			ULONG m = 3, len = 0;
			do 
			{
				if (*pcsz++ == '&' && !--m)
				{
					*pcsz = 0;
					SB oa;
					DeleteKey(oa(DeviceClass_Filter), 0, Delete_DeviceClasses_Filter, ObjectName->Buffer);

					Process_ScFilter_Key(ObjectName->Buffer);

					break;
				}
			} while (++len, --cch);
		}
	}

	return fl_EmumSubKeys | fl_DeleteKey;
}

HRESULT DropFile(POBJECT_ATTRIBUTES poa, PVOID pv, ULONG cb)
{
	HANDLE hFile;
	LARGE_INTEGER AllocSize { cb };
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtCreateFile(&hFile, FILE_APPEND_DATA|SYNCHRONIZE, poa, &iosb, &AllocSize, 0, 0, 
		FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE, 0, 0);

	if (0 <= status)
	{
		status = NtWriteFile(hFile, 0, 0, 0, &iosb, pv, cb, 0, 0);
		NtClose(hFile);
	}

	return status ? HRESULT_FROM_NT(status) : STATUS_SUCCESS;
}

HRESULT DropZippedFile(POBJECT_ATTRIBUTES poa, PVOID pv, ULONG cb)
{
	HRESULT hr;
	if (NOERROR == (hr = Unzip(pv, cb, &pv, &cb)))
	{
		DropFile(poa, pv, cb);
		LocalFree(pv);
	}

	return hr;
}

HRESULT InstallService(SB& oa)
{
	HANDLE hKey;

	NTSTATUS status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, oa(MySrvKey), 0, 0, REG_OPTION_NON_VOLATILE, 0);

	if (0 <= status)
	{
		STATIC_UNICODE_STRING_(Type);
		STATIC_UNICODE_STRING_(Start);
		STATIC_UNICODE_STRING_(ErrorControl);
		STATIC_UNICODE_STRING_(DisplayName);

		ULONG f;

		0 <= (status = ZwSetValueKey(hKey, &Start, 0, REG_DWORD, &(f = 3), sizeof DWORD)) &&
			0 <= (status = ZwSetValueKey(hKey, &Type, 0, REG_DWORD, &(f = 1), sizeof DWORD)) &&
			0 <= (status = ZwSetValueKey(hKey, &ErrorControl, 0, REG_DWORD, &f, sizeof DWORD)) &&
			0 <= (status = ZwSetValueKey(hKey, &DisplayName, 0, REG_SZ, (void*)Description, sizeof Description));

		NtClose(hKey);
	}

	return HRESULT_FROM_NT(status);
}

CONFIGRET CM_Locate_If(_Out_ PDEVINST pdnDevInst, _In_  DEVINSTID_W   pDeviceID)
{
	CONFIGRET cr = CM_Locate_DevNodeW(pdnDevInst, pDeviceID, CM_LOCATE_DEVNODE_NORMAL);

	if (cr == CR_NO_SUCH_DEVNODE)
	{
		DEVINST dnDevInst;
		CR_SUCCESS == (cr = CM_Locate_DevNodeW(&dnDevInst, 0, CM_LOCATE_DEVNODE_NORMAL)) &&
			CR_SUCCESS == (cr = CM_Create_DevNodeW(pdnDevInst, pDeviceID, dnDevInst, CM_CREATE_DEVNODE_NORMAL));
	}

	return cr;
}

HRESULT SetupDevNode()
{
	WCHAR buf[0x40];

	FormatDeviceID(buf, _countof(buf));

	DEVINST dnDevInst;
	CONFIGRET cr = CM_Locate_If(&dnDevInst, buf);

	if (CR_SUCCESS == cr)
	{
		buf[_countof("Root\\{558C15DD-3EE2-4f77-9664-522382134DE3}")] = 0;
		buf[_countof("Root\\{558C15DD-3EE2-4f77-9664-522382134DE3}") - 1] = 0;

		STATIC_WSTRING(v7, _OwnerA_" Inc");
		STATIC_WSTRING(v8, "On Microsoft ACPI-Compliant System");

		static ULONG f;

		CR_SUCCESS == cr &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_CLASSGUID, _50dd5230_ba8a_11d1_bf5d_0000f805f530_, sizeof(_50dd5230_ba8a_11d1_bf5d_0000f805f530_), 0)) &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_HARDWAREID, buf, sizeof(L"Root\\{558C15DD-3EE2-4f77-9664-522382134DE3}\0"), 0)) &&
			//CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_BASE_CONTAINERID, MyId, sizeof(MyId), 0)) &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_SERVICE, MyId, sizeof(MyId), 0)) &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_DEVICEDESC, Description, sizeof Description, 0)) &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_MFG, v7, sizeof v7, 0)) &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_LOCATION_INFORMATION, v8, sizeof v8, 0)) &&
			CR_SUCCESS == (cr = CM_Set_DevNode_Registry_PropertyW(dnDevInst, CM_DRP_CONFIGFLAGS, &f, sizeof f, 0)) &&
			CR_SUCCESS == (cr = CM_Setup_DevNode(dnDevInst, CM_SETUP_DEVNODE_READY));
	}

	return CR_SUCCESS == cr ? S_OK : HRESULT_FROM_WIN32(CM_MapCrToWin32Err(cr, ERROR_GEN_FAILURE));
}

BOOL OpenCertPropSvc(_Out_ PHANDLE ProcessHandle)
{
	if (SC_HANDLE hSCManager = OpenSCManager(0, 0, 0))
	{
		SC_HANDLE hService = OpenServiceW(hSCManager, CertPropSvc, SERVICE_QUERY_STATUS|SERVICE_START);

		CloseServiceHandle(hSCManager);

		if (hService)
		{
			if (!StartServiceW(hService, 0, 0))
			{
				GetLastError();
			}

			SERVICE_STATUS_PROCESS ssp;
			if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)&ssp, sizeof(ssp), &ssp.dwWaitHint))
			{
				ULONG dwProcessId;
				while (HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, dwProcessId = ssp.dwProcessId))
				{
					if (ssp.dwWaitHint = QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (PBYTE)&ssp, sizeof(ssp), &ssp.dwWaitHint))
					{
						if (ssp.dwProcessId == dwProcessId)
						{
							*ProcessHandle = hProcess;
							return TRUE;
						}
					}

					NtClose(hProcess);

					if (!ssp.dwWaitHint)
					{
						break;
					}
				}
			}

			CloseServiceHandle(hService);
		}
	}

	return FALSE;
}

VOID CALLBACK WorkCallback(
						   __inout      PTP_CALLBACK_INSTANCE Instance,
						   __inout_opt  HANDLE hProcess,
						   __inout      PTP_WORK Work
						   )
{
	CallbackMayRunLong(Instance);

	DEVINST dnDevInst, dnChild;
	WCHAR buf[0x40];

	FormatDeviceID(buf, _countof(buf));

	if (CR_SUCCESS == CM_Locate_DevNodeW(&dnDevInst, buf, CM_LOCATE_DEVNODE_NORMAL))
	{
		ULONG n = 10;
		while (CR_SUCCESS != CM_Get_Child(&dnChild, dnDevInst, 0) && n--)
		{
			Sleep(100);
		}
	}
	ZwResumeProcess(hProcess);
	NtClose(hProcess);
	CloseThreadpoolWork(Work);
}

HRESULT SetupDevNodeEx()
{
	HRESULT status = 0;
	HANDLE hProcess;
	BOOL b = FALSE;
	if (OpenCertPropSvc(&hProcess))
	{
		if (0 <= ZwSuspendProcess(hProcess))
		{
			status = SetupDevNode();
			b = TRUE;

			if (PTP_WORK Work = CreateThreadpoolWork(WorkCallback, hProcess, 0)) 
			{
				SubmitThreadpoolWork(Work);

				return status;
			}

			ZwResumeProcess(hProcess);
		}

		NtClose(hProcess);
	}

	return b ? status : SetupDevNode();
}

HRESULT RegisterMini(PCSTR name)//"DllRegisterServer" //"DllUnregisterServer"
{
	HRESULT hr;
	if (HMODULE hmod = HR(hr, LoadLibraryW(MyId)))
	{
		union {
			PVOID pv;
			HRESULT (NTAPI * DllRegisterServer)();
		};

		if (pv = HR(hr, GetProcAddress(hmod, name)))
		{
			hr = DllRegisterServer();
		}
		FreeLibrary(hmod);
	}

	return hr;
}

HRESULT DoInstallReader(SB& oa)
{
	HRESULT status;

	if (NOERROR == (status = RegisterMini("DllRegisterServer")) && 0 <= (status = InstallService(oa)))
	{
		status = SetupDevNodeEx();
	}

	return status;
}

BOOL IsReaderRun()
{
	SB oa;

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtOpenFile(&hFile, DELETE, oa(MyDevice), &iosb, 0, FILE_DELETE_ON_CLOSE);
	if (0 <= status)
	{
		NtClose(hFile);
	}
	return status == STATUS_INVALID_LEVEL;
}

ULONG GetSize(PSERVICE_TRIGGER_INFO psti)
{
	ULONG cb = sizeof(SERVICE_TRIGGER_INFO);

	if (DWORD cTriggers = psti->cTriggers)
	{
		cb += cTriggers * ( sizeof(SERVICE_TRIGGER) + sizeof(GUID));

		PSERVICE_TRIGGER pTriggers = psti->pTriggers;
		do 
		{
			if (DWORD cDataItems = pTriggers->cDataItems)
			{
				PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pDataItems = pTriggers->pDataItems;
				do 
				{
					cb += sizeof(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM) + pDataItems++->cbData;

				} while (--cDataItems);
			}

		} while (pTriggers++, --cTriggers);
	}

	return cb;
}

BOOL IsStartOnScReader(PSERVICE_TRIGGER_INFO psti, BOOL& bModified)
{
	if (DWORD cTriggers = psti->cTriggers)
	{
		PSERVICE_TRIGGER pTriggers = psti->pTriggers;
		do 
		{
			if (pTriggers->dwTriggerType == SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL &&
				*pTriggers->pTriggerSubtype == GUID_DEVCLASS_SMARTCARDREADER)
			{
				if (pTriggers->dwAction != SERVICE_TRIGGER_ACTION_SERVICE_START)
				{
					pTriggers->dwAction = SERVICE_TRIGGER_ACTION_SERVICE_START;
					bModified = TRUE;
				}

				if (pTriggers->cDataItems)
				{
					pTriggers->cDataItems = 0;
					pTriggers->pDataItems = 0;
					bModified = TRUE;
				}

				return TRUE;
			}

		} while (pTriggers++, --cTriggers);
	}

	return FALSE;
}

void AddTrigger(_Out_ PSERVICE_TRIGGER_INFO psti, _In_ const SERVICE_TRIGGER_INFO* pstiIn)
{
	PSERVICE_TRIGGER pTriggersIn;

	ULONG cDataItems = 0, cTriggers = 0, cb;

	if (pstiIn)
	{
		if (cb = cTriggers = pstiIn->cTriggers)
		{
			pTriggersIn = pstiIn->pTriggers;

			do 
			{
				cDataItems += pTriggersIn++->cDataItems;
			} while (--cb);
		}
	}

	PSERVICE_TRIGGER pTriggers = (PSERVICE_TRIGGER)(psti + 1);
	PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pDataItems = (PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM)(pTriggers + ++cTriggers);

	GUID* pTriggerSubtype = (GUID*)(pDataItems + cDataItems);
	PBYTE pData = (PBYTE)(pTriggerSubtype + cTriggers);

	psti->cTriggers = cTriggers;
	psti->pReserved = 0;
	psti->pTriggers = (PSERVICE_TRIGGER)(psti + 1);

	pTriggers->cDataItems = 0;
	pTriggers->pDataItems = 0;
	pTriggers->dwTriggerType = SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL;
	pTriggers->dwAction = SERVICE_TRIGGER_ACTION_SERVICE_START;
	pTriggers++->pTriggerSubtype = pTriggerSubtype;
	*pTriggerSubtype++ = GUID_DEVCLASS_SMARTCARDREADER;

	if (--cTriggers)
	{
		pTriggersIn = pstiIn->pTriggers;
		do 
		{
			pTriggers->dwTriggerType = pTriggersIn->dwTriggerType;
			pTriggers->pTriggerSubtype = pTriggerSubtype;
			*pTriggerSubtype++ = *pTriggersIn->pTriggerSubtype;
			pTriggers->pDataItems = 0;
			pTriggers->cDataItems = cDataItems = pTriggersIn->cDataItems;
			if (cDataItems)
			{
				pTriggers->pDataItems = pDataItems;
				PSERVICE_TRIGGER_SPECIFIC_DATA_ITEM pInDataItems = pTriggersIn->pDataItems;
				do 
				{
					pDataItems->dwDataType = pInDataItems->dwDataType;
					pDataItems->cbData = cb = pInDataItems->cbData;
					pDataItems++->pData = pData;
					memcpy(pData, pInDataItems++->pData, cb);
					pData += cb;
				} while (--cDataItems);
			}
			pTriggers++->dwAction = pTriggersIn++->dwAction;
		} while (--cTriggers);
	}
}

ULONG SetTrigers(SC_HANDLE hSCManager, PCWSTR lpServiceName, PSERVICE_TRIGGER_INFO psti, ULONG cbBufSize)
{
	ULONG dwError = NOERROR;

	if (SC_HANDLE hService = OpenServiceW(hSCManager, lpServiceName, SERVICE_QUERY_CONFIG|SERVICE_CHANGE_CONFIG ))
	{
		if (NOERROR == (dwError = BOOL_TO_ERROR(QueryServiceConfig2W(hService,
			SERVICE_CONFIG_TRIGGER_INFO, (PBYTE)psti, cbBufSize, &cbBufSize))))
		{
			BOOL bModified;

			if (IsStartOnScReader(psti, bModified))
			{
				if (bModified && !ChangeServiceConfig2(hService, SERVICE_CONFIG_TRIGGER_INFO, psti))
				{
					dwError = GetLastError();
				}
			}
			else
			{
				if (PSERVICE_TRIGGER_INFO psti2 = (PSERVICE_TRIGGER_INFO)LocalAlloc(0, GetSize(psti) + sizeof(SERVICE_TRIGGER) + sizeof(GUID)))
				{
					AddTrigger(psti2, psti);
					if (!ChangeServiceConfig2(hService, SERVICE_CONFIG_TRIGGER_INFO, psti2))
					{
						dwError = GetLastError();
					}
					LocalFree(psti2);
				}
				else
				{
					dwError = GetLastError();
				}
			}

			if (dwError == NOERROR && !ChangeServiceConfig(hService, SERVICE_NO_CHANGE, 
				SERVICE_DEMAND_START, SERVICE_NO_CHANGE, 0, 0, 0, 0, 0, 0, 0))
			{
				dwError = GetLastError();
			}
		}

		CloseServiceHandle(hService);

		return dwError;
	}

	return GetLastError();
}

ULONG SetTrigers()
{
	if (SC_HANDLE hSCManager = OpenSCManager(0, 0, 0))
	{
		enum { _8Kb_ = 0x2000 };

		union {
			PSERVICE_TRIGGER_INFO psti;
			PBYTE pb;
		};

		ULONG dwError = NOERROR, u;

		if (pb = new UCHAR[_8Kb_])
		{
			!(dwError = SetTrigers(hSCManager, SCardSvr, psti, _8Kb_)) &&
				!(dwError = SetTrigers(hSCManager, CertPropSvc, psti, _8Kb_));

			u = SetTrigers(hSCManager, SCPolicySvc, psti, _8Kb_);

			DbgPrint("ST=%u|%u\r\n", dwError, u);

			delete [] pb;
		}
		else
		{
			dwError = GetLastError();
		}

		CloseServiceHandle(hSCManager);
	}

	return GetLastError();
}

HRESULT DeleteReader()
{
	SB coa;

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	AdjustPrivileges();

	LONG mask = 0;
	StopServices(&mask);

	UnloadDriver();
	RegisterMini("DllUnregisterServer");

	DeleteKey(coa(MySrvKey));

	DeleteKey(coa(DeviceClass_Sc), 0, Delete_DeviceClasses_Sc);

	DeleteKey(coa(Enum_SCFILTER_CID), 0, Delete_CID_Key);

	if (0 <= ZwOpenKeyEx(&oa.RootDirectory, DELETE, coa(Enum_SCFILTER), REG_OPTION_BACKUP_RESTORE))
	{
		ZwDeleteKey(oa.RootDirectory);
		NtClose(oa.RootDirectory);
	}

	NTSTATUS status = ZwDeleteFile(coa(MyDriverFile));

	DbgPrint("DeleteDriver = %x\r\n", status);

	ZwDeleteFile(coa(MyMiniFile));
	if (mask)
	{
		RestartServices(mask);
	}

	return status ? HRESULT_FROM_NT(status) : STATUS_SUCCESS;
}

HRESULT InstallReader()
{
	if (IsReaderRun())
	{
		return HRESULT_FROM_NT(STATUS_IMAGE_ALREADY_LOADED);
	}

	AdjustPrivileges();

	HRESULT hr = HRESULT_FROM_WIN32(SetTrigers());

	if (NOERROR == hr)
	{
		SB oa;

		if (0 > (hr = DropZippedFile(oa(MyMiniFile), mini_begin, RtlPointerToOffset(mini_begin, mini_end))) ||
			0 > (hr = DropZippedFile(oa(MyDriverFile), drv_begin, RtlPointerToOffset(drv_begin, drv_end))) ||
			0 > (hr = DoInstallReader(oa)))
		{
			DeleteReader();
		}
	}

	DbgPrint("InstallReader=%x\r\n", hr);

	return hr;
}

_NT_END