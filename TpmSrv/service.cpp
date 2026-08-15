#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "SvcBase.h"

NTSTATUS AdjustPrivileges(const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)))
	{
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0);

		NtClose(hToken);
	}

	return status;
}

void ExecClient(PCLIENT_ID ClientId);

BEGIN_PRIVILEGES(tp_a_i, 2)
	LAA(SE_ASSIGNPRIMARYTOKEN_PRIVILEGE),
	LAA(SE_INCREASE_QUOTA_PRIVILEGE),
END_PRIVILEGES;

PCWSTR GetPortName()
{
	return L"\\RPC Control\\LRPC-219C15752DF2420898";
}

class CSvc : public CSvcBase
{
	HANDLE m_hPort;

	NTSTATUS Create(_Out_ PHANDLE PortHandle)
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

		RtlInitUnicodeString(&ObjectName, GetPortName());

		return NtCreatePort(PortHandle, &oa, 0, sizeof(PORT_MESSAGE), 0);
	}

	virtual HRESULT Run()
	{
		DbgPrint("++ Run\r\n");

		HANDLE PortHandle, hPort;

		NTSTATUS status;
		if (0 == (status = AdjustPrivileges(&tp_a_i)) && 0 <= (status = Create(&PortHandle)))
		{
			m_hPort = PortHandle;

			SetState(SERVICE_RUNNING, SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE);

			DbgPrint("+++ Run\r\n");

			PORT_MESSAGE ReceiveMessage;
			LARGE_INTEGER Timeout = { (ULONG) - 600000000, -1};
			while (0 == (status = NtReplyWaitReceivePortEx(PortHandle, 0, 0, &ReceiveMessage, &Timeout)))
			{
				DbgPrint("state -> %x\r\n", ReceiveMessage.u2.s2.Type);
				switch ((UCHAR)ReceiveMessage.u2.s2.Type)
				{
				case LPC_DATAGRAM:
					return NOERROR;

				case LPC_CONNECTION_REQUEST:
					ExecClient(&ReceiveMessage.ClientId);
					NtAcceptConnectPort(&hPort, 0, &ReceiveMessage, FALSE, 0, 0);
					return NOERROR;

				default: __debugbreak();
				}
			}

			DbgPrint("WaitReceivePort = %x\r\n", status);
		}

		return status;
	}

	virtual ULONG Handler(
		ULONG    dwControl,
		ULONG    /*dwEventType*/,
		PVOID   /*lpEventData*/
	)
	{
		switch (dwControl)
		{
		case SERVICE_CONTROL_CONTINUE:
		case SERVICE_CONTROL_PAUSE:
		case SERVICE_CONTROL_STOP:
			PORT_MESSAGE msg{};
			msg.u1.s1.TotalLength = sizeof(PORT_MESSAGE);
			return RtlNtStatusToDosError(NtRequestPort(m_hPort, &msg));
		}

		return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
	}
public:
	virtual ~CSvc()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};

void NTAPI ServiceMain(DWORD argc, PWSTR argv[])
{
	if (argc)
	{
		CSvc o;
		o.ServiceMain(argv[0]);
	}
}

HRESULT UnInstallService(PCWSTR lpServiceName);
HRESULT   InstallService(PCWSTR lpServiceName);

#include "../inc/initterm.h"

static const WCHAR s_ServiceName[] = L"TPM20_IDACTIVATION";

HRESULT RunNormal();
void RunElevated(HANDLE hToken);

void WINAPI ep(void*)
{
	InitLog(s_ServiceName, TRUE);
	initterm();

	HRESULT hr = S_OK;

	PWSTR cmd = GetCommandLineW();
	if ('\r' == *cmd)
	{
		HANDLE hToken = (HANDLE)(ULONG_PTR)_wcstoui64(cmd + 1, &cmd, 16);
		if (!*cmd)
		{
			RunElevated(hToken);
			NtClose(hToken);
		}
	}
	else if (wcschr(cmd, '\n'))
	{
		SERVICE_TABLE_ENTRY ste[] = {
			{ const_cast<PWSTR>(s_ServiceName), ServiceMain }, {}
		};

		if (!StartServiceCtrlDispatcher(ste))
		{
			hr = LogError("SERVICE_CONTROL_STOP");
		}

		DbgPrint("Service Exit\r\n");
	}
	else if (cmd = wcschr(cmd, '*'))
	{
		switch (cmd[1])
		{
		case 'i':
			hr = LogError("install", InstallService(s_ServiceName));
			break;
		case 'u':
			hr = LogError("uninstall", UnInstallService(s_ServiceName));
			break;
		default:
			hr = LogError("cmd line", STATUS_INVALID_PARAMETER);
			break;
		}
	}
	else
	{
		if (SC_HANDLE hSCManager = HR(hr, OpenSCManagerW(0, 0, 0)))
		{
			SC_HANDLE hService = HR(hr, OpenServiceW(hSCManager, s_ServiceName, SERVICE_START));
			CloseServiceHandle(hSCManager);
			if (hService)
			{
				HR(hr, StartServiceW(hService, 0, 0));
				switch (hr)
				{
				case NOERROR:
				case ERROR_SERVICE_ALREADY_RUNNING:
					hr = RunNormal();
					break;
				}
				CloseServiceHandle(hService);
			}
		}

		LogError("RunNormal", hr);
	}

	destroyterm();
	DbgPrint("## ExitProcess(%x) ##\r\n", hr);
	DestroyLog();
	ExitProcess(hr);
}

_NT_END