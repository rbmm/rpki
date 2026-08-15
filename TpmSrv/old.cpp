#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "SvcBase.h"
#include "AlertByThreadId.h"
#include "../asio/pipe.h"

// Cryptui.dll;crypt32.dll;ncrypt.dll;bcrypt.dll;credui.dll;dnsapi.dll;ws2_32.dll;mswsock.dll;secur32.dll;user32.dll
//////////////////////////////////////////////////////////////////////////

struct TACTIVATION
{
	union {
		HRESULT hr;
		ULONG cbKey;
	};
	ULONG cbSecret;
	UCHAR buf[];//key+secret
};

static
HRESULT DecryptSecret(
	_In_ PBYTE pbKey,
	_In_ ULONG cbKey,
	_Inout_ PBYTE pbSecret,
	_In_ ULONG cbSecret,
	_Out_ PULONG pcbSecret)
{
	*pcbSecret = 0;

	NCRYPT_PROV_HANDLE hProvider;
	NTSTATUS status;

	if (NOERROR == (status = NCryptOpenStorageProvider(&hProvider, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0)))
	{
		NCRYPT_KEY_HANDLE hKey;
		status = NCryptImportKey(hProvider, 0, BCRYPT_OPAQUE_KEY_BLOB, 0, &hKey, pbKey, cbKey, 0);

		NCryptFreeObject(hProvider);

		if (NOERROR == status)
		{
			if (NOERROR == (status = NCryptSetProperty(hKey, NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY, pbSecret, cbSecret, 0)))
			{
				status = NCryptGetProperty(hKey, NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY, pbSecret, cbSecret, pcbSecret, 0);
			}

			NCryptFreeObject(hKey);
		}
	}

	return status;
}

class CTS : public CPipeEnd
{
	virtual BOOL IsServer()
	{
		return TRUE;
	}

	virtual BOOL OnRead(PVOID Buffer, ULONG cbTransferred)
	{
		DbgPrint("%hs<%p>(%x)\r\n", __FUNCTION__, this, cbTransferred);

		if (sizeof(TACTIVATION) < cbTransferred)
		{
			TACTIVATION* pa = (TACTIVATION*)Buffer;
			ULONG cbKey = pa->cbKey, cbSecret;
			if (cbKey < (cbTransferred -= sizeof(TACTIVATION)))
			{
				PBYTE pbKey = pa->buf, pbSecret = pbKey + cbKey;
				if ((cbSecret = pa->cbSecret) == cbTransferred - cbKey)
				{
					HRESULT hr = DecryptSecret(pbKey, cbKey, pbSecret, cbSecret, &cbSecret);

					DbgPrint("DecryptSecret = %x [%x]\r\n", hr, cbSecret);
					if (hr)
					{
						cbSecret = 0;
						LogError("DecryptSecret", hr);
					}

					if (CDataPacket* packet = new(sizeof(TACTIVATION) + cbSecret) CDataPacket)
					{
						pa = (TACTIVATION*)packet->getData();
						pa->hr = hr;
						pa->cbSecret = cbSecret;
						if (cbSecret) memcpy(pa->buf, pbSecret, cbSecret);
						packet->setDataSize(sizeof(TACTIVATION) + cbSecret);
						Write(packet);
						packet->Release();
					}
				}
			}
		}
		return FALSE;
	}

	virtual BOOL OnConnect(NTSTATUS status)
	{
		DbgPrint("%hs<%p>(%x)\r\n", __FUNCTION__, this, status);
		if (status)
		{
			LogError("connect", status);
		}
		return 0 <= status;
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
		Listen();
	}

	~CTS()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}

public:

	CTS()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};
//////////////////////////////////////////////////////////////////////////

class CSvc : public CSvcBase
{
	TIDFA m_tid;

	virtual HRESULT Run()
	{
		DbgPrint("+++ Run\r\n");

		do
		{
			ULONG dwState = m_dwTargetState;

			DbgPrint("state:= %x\r\n", dwState);

			SECURITY_DESCRIPTOR sd = { SECURITY_DESCRIPTOR_REVISION, 0, SE_DACL_PRESENT };
			UNICODE_STRING ObjectName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE, &sd };
			RtlInitUnicodeString(&ObjectName, L"\\Device\\NamedPipe\\D1A2A28D-2CA8-40EA-B815-7743319ED695");
			if (CTS* s = new CTS)
			{
				NTSTATUS status;
				if (0 <= (status = s->SetBuffer(0x1000)) &&
					0 <= (status = s->Create(&oa, 0, PIPE_UNLIMITED_INSTANCES, FILE_PIPE_MESSAGE_TYPE)))
				{
					SetState(dwState, SERVICE_ACCEPT_STOP);

					DbgPrint("++ active\r\n");

					m_tid.WaitForAlert();

					DbgPrint("-- active\r\n");
				}
				else
				{
					LogError(L"init pipe", status);
				}

				s->Close();
				s->Release();
			}

		} while (SERVICE_STOPPED != m_dwTargetState);

		DbgPrint("--- Run\r\n");

		return S_OK;
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
			return m_tid.Alert(), NOERROR;
		}

		return ERROR_SERVICE_CANNOT_ACCEPT_CTRL;
	}
public:
	virtual ~CSvc()
	{
		DbgPrint("%hs<%p>\r\n", __FUNCTION__, this);
	}
};

TIDFA g_tid;

void IO_RUNDOWN::RundownCompleted()
{
	g_tid.Alert();
}

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

void WINAPI ep(void*)
{
	InitLog(s_ServiceName, TRUE);
	initterm();

	HRESULT hr = S_OK;

	PWSTR cmd = GetCommandLineW();
	if (wcschr(cmd, '\n'))
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

	IO_RUNDOWN::g_IoRundown.BeginRundown();
	g_tid.WaitForAlert();
	destroyterm();
	DbgPrint("## ExitProcess(%x) ##\r\n", hr);
	DestroyLog();
	ExitProcess(hr);
}

_NT_END