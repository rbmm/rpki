#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../inc/initterm.h"
#include "../QI/newiface.h"

volatile UCHAR guz;
STATIC_WSTRING_(TestProvider);

STATIC_WSTRING(RegSrv32, "RegSvr32.exe /u /s \"");
STATIC_WSTRING(GLOBAL, "\\GLOBAL??\\");

STATIC_WSTRING(SOFTWARE, "\\registry\\MACHINE\\SOFTWARE\\");
STATIC_WSTRING(Classes, "Classes\\CLSID\\");
STATIC_WSTRING(Uninstall, "Microsoft\\Windows\\CurrentVersion\\Uninstall\\");
STATIC_WSTRING(TreatAs, "TreatAs");
STATIC_WSTRING(CngUIGuid, "{600e7adb-da3e-41a4-9225-3c0399e88c0c}\\");
extern const WCHAR My[] = L"{559A3F37-F5D9-44c7-8D0F-098FD82B3E61}";

#define LENGTH_OF(s) (RTL_NUMBER_OF(s) - 1)
#define SIZE_OF(s) (sizeof(s) - sizeof(s[0]))

static const UNICODE_STRING g_emptyUS {};

HRESULT GetLastStatus()
{
	NTSTATUS status = RtlGetLastNtStatus();
	ULONG dwError = GetLastError();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

struct SB : public OBJECT_ATTRIBUTES, UNICODE_STRING 
{
	SB(PWSTR Buf = reinterpret_cast<_TEB*>(NtCurrentTeb())->StaticUnicodeBuffer)
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

	OBJECT_ATTRIBUTES* operator()(PCWSTR str, ...)
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
};

NTSTATUS DeleteKey(PCOBJECT_ATTRIBUTES poa)
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = ZwOpenKey(&oa.RootDirectory, KEY_ALL_ACCESS|KEY_WOW64_64KEY, const_cast<POBJECT_ATTRIBUTES>(poa));

	if (0 <= status)
	{
		KEY_FULL_INFORMATION kfi;

		switch (ZwQueryKey(oa.RootDirectory, KeyFullInformation, &kfi, sizeof(kfi), &kfi.TitleIndex))
		{
		case 0:
		case STATUS_BUFFER_OVERFLOW:

			if (kfi.SubKeys)
			{
				PKEY_BASIC_INFORMATION pkni = (PKEY_BASIC_INFORMATION)alloca(
					kfi.MaxNameLen += sizeof(KEY_BASIC_INFORMATION));

				ObjectName.Buffer = pkni->Name;
				ObjectName.MaximumLength = (USHORT)kfi.MaxNameLen - sizeof(ULONG);

				do 
				{
					if (0 <= ZwEnumerateKey(oa.RootDirectory, 
						--kfi.SubKeys, KeyBasicInformation, pkni, 
						kfi.MaxNameLen, &kfi.TitleIndex))
					{
						ObjectName.Length = (USHORT)pkni->NameLength;
						DeleteKey(&oa);
					}

				} while (kfi.SubKeys);
			}
		}

		status = ZwDeleteKey(oa.RootDirectory);

		NtClose(oa.RootDirectory);
	}

	return status;
}

#ifdef _WIN64
#define __movsp __movsq
#else
#define __movsp __movsd
#endif

typedef PVOID (WINAPI * VIRTUALALLOC)( PVOID , SIZE_T , DWORD , DWORD  );

void RemapSelfInternal(PVOID ImageBase, PVOID TempBase, ULONG SizeOfImage, VIRTUALALLOC VirtualAlloc)
{
	if (UnmapViewOfFile(ImageBase))
	{
		if (ImageBase == VirtualAlloc(ImageBase, SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE))
		{
			__movsp((ULONG_PTR*)ImageBase, (ULONG_PTR*)TempBase, SizeOfImage / sizeof(ULONG_PTR));
			return ;
		}

		__debugbreak();
	}
}

void RemapSelf()
{
	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(&__ImageBase))
	{
		ULONG SizeOfImage = pinth->OptionalHeader.SizeOfImage;
		if (PVOID pv = VirtualAlloc(0, SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE))
		{
			memcpy(pv, &__ImageBase, SizeOfImage);

			reinterpret_cast<void (*) (PVOID , PVOID , ULONG , VIRTUALALLOC)>
				(RtlOffsetToPointer(pv, RtlPointerToOffset(&__ImageBase, RemapSelfInternal)))
				(&__ImageBase, pv, SizeOfImage, VirtualAlloc);

			VirtualFree(pv, 0, MEM_RELEASE);
		}
	}
}

void DeleteKeys(PCWSTR szGuid)
{
	SB oa;
	DeleteKey(oa(SOFTWARE, Classes, szGuid, 0));
}

HRESULT UnHookCngUI();

void DeleteKeys()
{
	UnHookCngUI();

	SB oa;
	DeleteKey(oa(SOFTWARE, Classes, My, 0));
	DeleteKey(oa(SOFTWARE, Uninstall, My, 0));
}

void DeleteFiles()
{
	RemapSelf();

	// format InstallLocation path

	PWSTR pwz = GetCommandLineW();

	while (pwz = wcschr(pwz, '/'))
	{
		if (*++pwz != 's' || *++pwz != ' ' || *++pwz != '\"')
		{
			continue;
		}

		if (PWSTR c = wcsrchr(++pwz, '\\'))
		{
			c[1] = 0;

			UNICODE_STRING ObjectName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };

			IO_STATUS_BLOCK iosb;
			NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(pwz, &ObjectName, 0, 0);
			PWSTR err;
			HMODULE hNTDLL = GetModuleHandle(L"ntdll");
			int ret;

			if (0 <= status)
			{
				while (0 > (status = NtOpenFile(&oa.RootDirectory, DELETE, &oa, &iosb, 
					FILE_SHARE_VALID_FLAGS, FILE_DELETE_ON_CLOSE|FILE_DIRECTORY_FILE)) && 
					(status != STATUS_OBJECT_NAME_NOT_FOUND))
				{
					ret = IDABORT;

					if (FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ALLOCATE_BUFFER,
						hNTDLL, status, 0, (PWSTR)&err, 0, 0))
					{
						ret = MessageBox(0, err, ObjectName.Buffer, MB_RETRYCANCEL|MB_ICONWARNING);
						LocalFree(err);
					}

					if (ret != IDRETRY) break;
				}

				RtlFreeUnicodeString(&ObjectName);
			}

			if (0 <= status)
			{
				static PCWSTR files[] = {
					L".exe", L".dll"
				};

				int n = RTL_NUMBER_OF(files);
				do 
				{
					RtlInitUnicodeString(&ObjectName, files[--n]);

					while (0 > (status = ZwDeleteFile(&oa)) && (status != STATUS_OBJECT_NAME_NOT_FOUND))
					{
						ret = IDABORT;

						if (FormatMessageW(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_ALLOCATE_BUFFER,
							hNTDLL, status, 0, (PWSTR)&err, 0, 0))
						{
							ret = MessageBox(0, err, ObjectName.Buffer, MB_RETRYCANCEL|MB_ICONWARNING);
							LocalFree(err);
						}

						if (ret != IDRETRY) break;
					}

				} while (n);

				NtClose(oa.RootDirectory);
			}
		}

		break;
	}
}

#include "../impersonate/impersonate.h"

BEGIN_PRIVILEGES(tp_br, 2)
LAA(SE_BACKUP_PRIVILEGE),
LAA(SE_RESTORE_PRIVILEGE),
END_PRIVILEGES

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

STDAPI DllUnregisterServer()
{
	if (PCWSTR pc = wcschr(GetCommandLine(), '*'))
	{
		if (HMODULE hmod = GetModuleHandle(L"user32"))
		{
			if (FARPROC fp = GetProcAddress(hmod, "SetProcessDPIAware"))
			{
				fp();
			}
		}

		if (MessageBox(0, L"Are you sure ?", L"Uninstall Test Provider", MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2) == IDYES)
		{
			if (STATUS_SUCCESS == AdjustPrivileges(&tp_br))
			{
				DeleteKeys();
				DeleteFiles();
				RtlRevertToSelf();
			}
		}
	}

	return 0;
}

ULONG gTime = 0;

ULONG GetSecondsSinceLoad()
{
	return GetTickCount() / 1000 - gTime;
}

LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter;
PVOID gVex;

VOID PrintException(::PEXCEPTION_RECORD ExceptionRecord)
{
	DbgPrint("!!!!! UnhandledException(%x) %x at %p\r\n", ExceptionRecord->ExceptionFlags,
		ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress);

	if (ULONG NumberParameters = ExceptionRecord->NumberParameters)
	{
		if (NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS)
		{
			NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
		}

		PSTR buf = (PSTR)alloca(8 + NumberParameters * 20), psz = buf;
		PULONG_PTR ExceptionInformation = ExceptionRecord->ExceptionInformation;
		*psz++ = '[';
		do 
		{
			psz += sprintf(psz, "%p, ", (PVOID)*ExceptionInformation++);
		} while (--NumberParameters);
		strcpy(psz - 2, "]\r\n");
		logwrite(buf, 1 + RtlPointerToOffset(buf, psz));
	}
}

static void WaitDebugger()
{
	static const LARGE_INTEGER li = { (ULONG)(-10000000*60*5),  - 1};
	ZwDelayExecution(TRUE, const_cast<PLARGE_INTEGER>(&li));

	if (IsDebuggerPresent())
	{
		__debugbreak();
	}
}

LONG WINAPI OnException(_In_ ::PEXCEPTION_POINTERS ExceptionInfo)
{
	PrintException(ExceptionInfo->ExceptionRecord);

	WaitDebugger();

	return g_prevFilter ? g_prevFilter(ExceptionInfo) : EXCEPTION_CONTINUE_SEARCH;
}

LONG NTAPI Vex(::PEXCEPTION_POINTERS ExceptionInfo)
{
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;

	switch (ExceptionRecord->ExceptionCode)
	{
	case DBG_PRINTEXCEPTION_WIDE_C:
		DbgPrint("%x>++WIDE_C:\r\n", GetCurrentThreadId());
		if (1 < ExceptionRecord->NumberParameters)
		{
			SIZE_T cch = ExceptionRecord->ExceptionInformation[0];

			if (--cch < MAXSHORT)
			{
				PWSTR pwz = (PWSTR)ExceptionRecord->ExceptionInformation[1];

				ULONG cb = 0;
				PSTR psz = 0;
				while (cb = WideCharToMultiByte(CP_UTF8, 0, pwz, (ULONG)cch, psz, cb, 0, 0))
				{
					if (psz)
					{
						logwrite(psz, cb);
						DbgPrint("\r\n--WIDE_C:\r\n");
						return EXCEPTION_CONTINUE_EXECUTION;
					}

					if (!(psz = new char[cb]))
					{
						break;
					}
				}

				if (psz)
				{
					delete [] psz;
				}
			}
		}

		if (4 > ExceptionRecord->NumberParameters)
		{
			break;
		}

		ExceptionRecord->ExceptionInformation[0] = ExceptionRecord->ExceptionInformation[2];
		ExceptionRecord->ExceptionInformation[1] = ExceptionRecord->ExceptionInformation[3];
		[[fallthrough]];
	case DBG_PRINTEXCEPTION_C:
		DbgPrint("%x>++PRINT_C:\r\n", GetCurrentThreadId());
		if (1 < ExceptionRecord->NumberParameters)
		{
			SIZE_T cch = ExceptionRecord->ExceptionInformation[0];

			if (--cch < MAXSHORT)
			{
				logwrite((PVOID)ExceptionRecord->ExceptionInformation[1], (ULONG)cch);
				DbgPrint("\r\n--PRINT_C:\r\n");
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		break;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

#include "miniwnd.h"

BOOLEAN APIENTRY DllMain( HMODULE hModule,
						 DWORD  ul_reason_for_call,
						 PVOID lpReserved
						 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		InitLog(L"CngUI.log");
		{
			KERNEL_USER_TIMES kut;
			STATIC_WSTRING(fmt, "\r\n[v10.0]: "__TIMESTAMP__"\r\n%hs %p (%ws) | [%x.%x]\r\n");
			LogOutputNT(~0, fmt, __FUNCTION__, GetShellWindow(), GetCommandLineW(), RtlGetCurrentPeb()->SessionId, GetCurrentProcessId());
			if (0 <= NtQueryInformationProcess(NtCurrentProcess(), ProcessTimes, &kut, sizeof(kut), 0))
			{
				TIME_FIELDS tf;
				FileTimeToLocalFileTime((PFILETIME)&kut.CreateTime, (PFILETIME)&kut.CreateTime);
				RtlTimeToTimeFields(&kut.CreateTime, &tf);
				DbgPrint("CreateTime %u-%02u-%02u %02u:%02u:%02u.%03u\r\n", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);
			}
		}
		g_prevFilter = SetUnhandledExceptionFilter(OnException);
		gVex = AddVectoredExceptionHandler(TRUE, Vex);
		gTime = GetSecondsSinceLoad();
		initterm();
		break;
	case DLL_PROCESS_DETACH:
		if (gVex)
		{
			RemoveVectoredExceptionHandler(gVex);
		}
		SetUnhandledExceptionFilter(g_prevFilter);
		DbgPrint("PROCESS_DETACH [%p]\r\n", lpReserved);
		destroyterm();
		break;
	}
	return TRUE;
}

//////////////////////////////////////////////////////////////////////////
//

inline NTSTATUS RegSetSzValue(HANDLE hKey, PCUNICODE_STRING ValueName, PCWSTR Value, ULONG Size)
{
	return ZwSetValueKey(hKey, ValueName, 0, REG_SZ, const_cast<PWSTR>(Value), Size);
}

inline NTSTATUS RegSetDwValue(HANDLE hKey, PCUNICODE_STRING ValueName, ULONG Value)
{
	return ZwSetValueKey(hKey, ValueName, 0, REG_DWORD, &Value, sizeof(ULONG));
}

#define SAVE_DW(name, val) STATIC_UNICODE_STRING_(name); RegSetDwValue(hKey, &name, (val))

#define SAVE__SZ(name, val, len) STATIC_UNICODE_STRING_(name); RegSetSzValue(hKey, &name, (val), (len))
#define SAVE_CSZ(name, val) static const WCHAR label(c)[] = val; SAVE__SZ(name, label(c), sizeof(label(c)))
#define SAVE_SZ(name, val) SAVE__SZ(name, (val), ((ULONG)wcslen(val) + 1) * sizeof(WCHAR))

NTSTATUS CreateCLSIDKeyRoot(_Out_ PHANDLE KeyHandle, PCWSTR szGuid)
{
	SB oa;

	return ZwCreateKey(KeyHandle, KEY_ALL_ACCESS|KEY_WOW64_64KEY, 
		oa(SOFTWARE, Classes, szGuid, 0), 0, 0, 0, 0);
}

NTSTATUS CreateCLSIDKey(PWSTR DllPath, ULONG cb, PCWSTR szGuid)
{
	STATIC_UNICODE_STRING_(InprocServer32);
	STATIC_UNICODE_STRING_(ThreadingModel);
	STATIC_WSTRING_(Apartment);

	NTSTATUS status;
	HANDLE hKey;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, (PUNICODE_STRING)&InprocServer32, OBJ_CASE_INSENSITIVE };

	if (0 <= (status = CreateCLSIDKeyRoot(&oa.RootDirectory, szGuid)))
	{
		ZwSetValueKey(oa.RootDirectory, &g_emptyUS, 0, REG_SZ, const_cast<PWSTR>(TestProvider), sizeof(TestProvider));

		if (0 <= (status = ZwCreateKey(&hKey, KEY_ALL_ACCESS, &oa, 0, 0, 0, 0)))
		{
			status = ZwSetValueKey(hKey, &g_emptyUS, 0, REG_SZ, DllPath, cb);

			ZwSetValueKey(hKey, &ThreadingModel, 0, REG_SZ, const_cast<PWSTR>(Apartment), sizeof(Apartment));

			NtClose(hKey);
		}
		NtClose(oa.RootDirectory);
	}

	return status;
}

NTSTATUS RegisterUninstall(POBJECT_ATTRIBUTES poa, PWSTR CmdLine, PWSTR Name, ULONG size)
{
	HANDLE hKey;
	NTSTATUS status = ZwCreateKey(&hKey, KEY_ALL_ACCESS|KEY_WOW64_64KEY, poa, 0, 0, 0, 0);
	if (0 <= status)
	{
		SAVE_DW(EstimatedSize, size);
		SAVE_DW(VersionMajor, 4);
		SAVE_DW(VersionMinor, 0);
		SAVE_CSZ(DisplayVersion, L"5.0");
		SAVE_CSZ(DisplayName, L"Rbmm Test");
		SAVE_CSZ(Publisher, L"© yYy");
		SAVE_CSZ(URLInfoAbout, L"https://www.rbmm.com/");

		memcpy(Name, L"\" *", 8);
		SAVE_SZ(UninstallString, CmdLine);

		*Name = 0;
		SAVE_SZ(DisplayIcon, CmdLine + LENGTH_OF(RegSrv32));

		NtClose(hKey);
	}

	return status;
}

HRESULT HookCngUI();

NTSTATUS RegisterProvider(PWSTR DllPath, ULONG cb, PCWSTR szGuid)
{
	SB oa;

	NTSTATUS status;

	if (0 <= (status = CreateCLSIDKey(DllPath, cb, szGuid)))
	{
		if (0 <= (status = HookCngUI()))
		{
			return STATUS_SUCCESS;
		}

		DeleteKey(oa(SOFTWARE, Classes, szGuid, 0));
	}

	return status;
}

NTSTATUS DllRegisterServer(PWSTR CmdLine, PWSTR Name, ULONG size)
{
	NTSTATUS status;

	SB oa;

	if (0 <= (status = RegisterUninstall(oa(SOFTWARE, Uninstall, My, 0), CmdLine, Name, size)))
	{
		CmdLine += LENGTH_OF(RegSrv32);

		ULONG cb = RtlPointerToOffset(CmdLine, Name);

		return RegisterProvider(CmdLine, cb, My);
	}

	return status;
}

HRESULT HookCngUI()
{
	SB sb;
	HANDLE hKey;
	NTSTATUS status;

	if (0 <= (status = ZwCreateKey(&hKey, KEY_SET_VALUE, sb(SOFTWARE, Classes, CngUIGuid, TreatAs, 0), 0, 0, REG_OPTION_BACKUP_RESTORE, 0)))
	{
		UNICODE_STRING ObjectName = {};
		status = ZwSetValueKey(hKey, &ObjectName, 0, REG_SZ, const_cast<PWSTR>(My), sizeof(My));
		NtClose(hKey);
	}

	DbgPrint("HookCngUI=%x\r\n", status);

	return status;
}

HRESULT UnHookCngUI()
{
	SB sb;
	HANDLE hKey;
	NTSTATUS status;

	if (0 <= (status = ZwOpenKeyEx(&hKey, DELETE, sb(SOFTWARE, Classes, CngUIGuid, TreatAs, 0), REG_OPTION_BACKUP_RESTORE)))
	{
		ZwDeleteKey(hKey);
		NtClose(hKey);
	}

	return status;
}

HRESULT GetCngUI(_Out_ ICredentialProvider** ppcp, _Out_ HMODULE* phmod)
{
	SB sb;
	HANDLE hKey;
	NTSTATUS status;

	if (0 <= (status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, sb(SOFTWARE, Classes, CngUIGuid, L"InProcServer32", 0))))
	{
		UNICODE_STRING ObjectName = {};
		PVOID stack = alloca(guz);
		ULONG cb = 0, rcb = 0x10;
		union {
			PVOID buf;
			PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi;
		};
		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}
			status = ZwQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, buf, cb, &rcb);
		} while (STATUS_BUFFER_OVERFLOW == status);

		NtClose(hKey);

		if (0 <= status)
		{
			status = STATUS_INTERNAL_ERROR;

			BOOL bExpand = FALSE;
			switch (pkvpi->Type)
			{
			case REG_EXPAND_SZ:
				bExpand = TRUE;
			case REG_SZ:
				if (ULONG DataLength = pkvpi->DataLength)
				{
					if (!(DataLength & (sizeof(WCHAR) - 1)) && 
						!*(WCHAR*)RtlOffsetToPointer(pkvpi->Data, DataLength - sizeof(WCHAR)))
					{
						PWSTR lpLibFileName = (PWSTR)pkvpi->Data;
						if (bExpand)
						{
							PWSTR pwz = 0;
							ULONG cch = 0;
							while (cch = ExpandEnvironmentStringsW(lpLibFileName, pwz, cch))
							{
								if (pwz)
								{
									lpLibFileName = pwz;
									goto __ok;
								}

								pwz = (PWSTR)alloca(cch * sizeof(WCHAR));
							}

							return GetLastHresult();
						}

__ok:
						if (HMODULE hmod = HR(status, LoadLibraryW(lpLibFileName)))
						{
							union {
								PVOID pv;
								HRESULT (WINAPI* DllGetClassObject)(_In_ REFCLSID rclsid, _In_ REFIID riid, _Outptr_ PVOID* ppv);
							};
							if (pv = HR(status, GetProcAddress(hmod, "DllGetClassObject")))
							{
								IClassFactory* pcf;
								if (S_OK == (status = DllGetClassObject(__uuidof(CCngCredUIProvider), IID_PPV_ARGS(&pcf))))
								{
									status = pcf->CreateInstance(0, __uuidof(ICredentialProvider), (void**)ppcp);
									pcf->Release();
									if (S_OK == status)
									{
										*phmod = hmod;
										return S_OK;
									}
								}
							}
							FreeLibrary(hmod);
						}
					}
				}
				break;
			}
		}
	}
	return status;
}

using namespace LSA;

void PrintTime(PLARGE_INTEGER time, PCSTR prefix="--")
{
	TIME_FIELDS tf;
	RtlTimeToTimeFields(time, &tf);
	DbgPrint("%hs\n\t%u-%02u-%02u %02u:%02u:%02u\n", prefix, tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);
	union {
		LARGE_INTEGER li;
		FILETIME ft;
	};

	GetSystemTimeAsFileTime(&ft);
	RtlTimeToTimeFields(&li, &tf);
	DbgPrint("\t%u-%02u-%02u %02u:%02u:%02u\n", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);
}

STDAPI DllRegisterServer()
{
	//MessageBoxW(0,0,0,0);__debugbreak();

	NTSTATUS status;

	enum { mylen = SIZE_OF("\\{559A3F37-F5D9-44c7-8D0F-098FD82B3E60}\\.***\" *") };

	WCHAR buf[RTL_NUMBER_OF(RegSrv32) + MAX_PATH + mylen], *c, ExistingFileName[MAX_PATH], 
		*NewFileName = buf + LENGTH_OF(RegSrv32),
		*NewNtFileName = NewFileName - LENGTH_OF(GLOBAL);

	GetModuleFileName((HMODULE)&__ImageBase, ExistingFileName, RTL_NUMBER_OF(ExistingFileName));

	if (ULONG dwError = GetLastError())
	{
		return GetLastStatus();
	}

	ULONG cch = GetEnvironmentVariable(L"ProgramFiles", NewFileName, MAX_PATH);

	if (!cch)
	{
		return GetLastStatus();
	}

	if (cch > MAX_PATH)
	{
		return STATUS_BUFFER_TOO_SMALL;
	}

	memcpy(NewNtFileName, GLOBAL, SIZE_OF(GLOBAL));
	NewFileName[cch++] = '\\';
	memcpy(NewFileName + cch, My, sizeof(My));

	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	if (STATUS_SUCCESS == (status = AdjustPrivileges(&tp_br)))
	{
		RtlInitUnicodeString(&ObjectName, NewNtFileName);

		IO_STATUS_BLOCK iosb;

		if (0 <= (status = NtCreateFile(&oa.RootDirectory, FILE_ADD_FILE|DELETE, &oa, &iosb, 0, 
			FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0)))
		{
			c = NewFileName + cch + LENGTH_OF(My);
			*c++ = '\\', *c++ = '.', *c++ = 'd', *c++ = 'l', *c++ = 'l', *c = 0;

			struct lambda 
			{
				ULONG ExeSize;

				static DWORD CALLBACK CopyProgressRoutine(
					__in      ::LARGE_INTEGER TotalFileSize,
					__in      ::LARGE_INTEGER /*TotalBytesTransferred*/,
					__in      ::LARGE_INTEGER /*StreamSize*/,
					__in      ::LARGE_INTEGER /*StreamBytesTransferred*/,
					__in      DWORD /*dwStreamNumber*/,
					__in      DWORD /*dwCallbackReason*/,
					__in      HANDLE /*hSourceFile*/,
					__in      HANDLE /*hDestinationFile*/,
					__in_opt  LPVOID lpData
					)
				{
					reinterpret_cast<lambda*>(lpData)->ExeSize = TotalFileSize.LowPart;

					return PROGRESS_QUIET;
				}
			} e;

			if (CopyFileExW(ExistingFileName, NewFileName, lambda::CopyProgressRoutine, &e, 0, COPY_FILE_NO_BUFFERING))
			{
				memcpy(buf, RegSrv32, SIZE_OF(RegSrv32));
				status = DllRegisterServer(buf, c, e.ExeSize >> 10 ) ;

				if (0 > status)
				{
					STATIC_UNICODE_STRING(EXE, ".dll");
					oa.ObjectName = const_cast<PUNICODE_STRING>(&EXE);
					ZwDeleteFile(&oa);
				}
			}
			else
			{
				status = GetLastStatus();
			}

			static FILE_DISPOSITION_INFORMATION fdi = { TRUE };

			if (0 > status)
			{
				NtSetInformationFile(oa.RootDirectory, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);
			}

			NtClose(oa.RootDirectory);
		}

		RtlRevertToSelf();
	}

	return status;
}

_NT_END