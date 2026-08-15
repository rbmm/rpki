#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "../asio/port.h"
#include "../inc/initterm.h"
#include "AlertByThreadId.h"

TIDFA g_tid;

void IO_RUNDOWN::RundownCompleted()
{
	g_tid.Alert();
}

BOOL CreateTLSContext(_Out_ PortContext** ppctx,
					  _In_ PCWSTR pwszCaURL, 
					  _In_ PCWSTR pwszOcspURL,
					  _In_ PCWSTR lpFileName, 
					  _In_ PCWSTR szPassword, 
					  _In_ PCWSTR pcszTlsHash);

void StartContext(PortList* pl, PortContext* ctx, USHORT sin_port)
{
	Port* port;
	SOCKADDR_INET sa {};

	sa.si_family = AF_INET;
	sa.Ipv4.sin_port = _byteswap_ushort(sin_port);
	if (!pl->CreatePort(&port, ctx, (sockaddr*)&sa, sizeof(sa.Ipv4)))
	{
		port->Start(2, 4);
		port->Release();
	}

	sa.si_family = AF_INET6;
	sa.Ipv6.sin6_port = _byteswap_ushort(sin_port);
	if (!pl->CreatePort(&port, ctx, (sockaddr*)&sa, sizeof(sa.Ipv6)))
	{
		port->Start(2, 4);
		port->Release();
	}

	ctx->Release();
}

void CheckDB();

class MyPortList : public PortList
{
	virtual void OnTimer()
	{
		__super::OnTimer();
		CheckDB();
	}
};

void Run(_In_ PCWSTR pwszCaURL, 
		 _In_ PCWSTR pwszOcspURL,
		 _In_ USHORT PortNumber,
		 _In_ PCWSTR enc_name, 
		 _In_ PCWSTR sign_name, 
		 _In_opt_ PCWSTR pszPassword = 0)
{
	DbgPrint("%hs(%u, \"%ws\", \"%ws\", \"%ws\")\r\n", __FUNCTION__, PortNumber, enc_name, sign_name, pszPassword);
	initterm();

	if (PortList* pl = new MyPortList)
	{
		WSADATA wd;
		if (!WSAStartup(WINSOCK_VERSION, &wd))
		{
			PortContext* ctx;
			if (CreateTLSContext(&ctx, pwszCaURL, pwszOcspURL, sign_name, pszPassword, enc_name))
			{
				StartContext(pl, ctx, 444);
			}

			//pl->Start(1);

			MessageBoxW(0, 0, L"server running...", MB_ICONINFORMATION);
			DbgPrint("begin stop...\r\n");
			IO_RUNDOWN::g_IoRundown.BeginRundown();
			WSACleanup();

			pl->Stop();
		}

		pl->Release();
	}

	g_tid.WaitForAlert();
	DbgPrint("stopped\r\n");
	destroyterm();
}

void WINAPI ep(PWSTR pszCommandLine)
{
	InitLog(L"PKCS#10s.log");

	// *http://DESKTOP-2N5ODLB/file/C/RBMM-ECC-384.cer*http://DESKTOP-2N5ODLB:28018/ocsp*O:\vc\x64\PFX\DESKTOP-2N5ODLB.pfx*33333?O:\vc\x64\PFX\RBMM-ECC-384.pfx*0
	// *pwszCaURL*pwszOcspURL*file*port?file*password
	// *pwszCaURL*pwszOcspURL*hash*port*hash
	// *http://DESKTOP-2N5ODLB/file/C/RBMM-ECC-384.cer*http://DESKTOP-2N5ODLB:28018/ocsp*a0c0d880350e3fb4b3ba30b5669a03728c95d871*444?O:\vc\x64\PFX\RBMM-ECC-384.pfx*0

	if (PWSTR pwszCaURL = wcschr(GetCommandLineW(), '*'))
	{
		if (PWSTR pwszOcspURL = wcschr(++pwszCaURL, '*'))
		{
			*pwszOcspURL++ = 0;

			if (PWSTR enc_name = wcschr(pwszOcspURL, '*'))
			{
				*enc_name++ = 0;

				if (pszCommandLine = wcschr(enc_name, '*'))
				{
					*pszCommandLine++ = 0;

					if (ULONG Port = wcstoul(pszCommandLine, &pszCommandLine, 10))
					{
						if (Port < MAXUSHORT)
						{
							switch (*pszCommandLine++)
							{
							case '*':
								Run(pwszCaURL, pwszOcspURL, (USHORT)Port, enc_name, pszCommandLine);
								break;
							case '?':
								PWSTR sign_name = pszCommandLine;
								if (pszCommandLine = wcschr(pszCommandLine, '*'))
								{
									*pszCommandLine++ = 0;
									Run(pwszCaURL, pwszOcspURL, (USHORT)Port, enc_name, sign_name, pszCommandLine);
								}
								break;
							}
						}
					}
				}
			}
		}
	}

	DestroyLog();
	ExitProcess(0);
}

_NT_END