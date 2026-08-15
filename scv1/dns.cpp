#include "stdafx.h"

_NT_BEGIN

#include "../log/log.h"
#include "dns.h"

ULONG GetCount(PDNS_RECORD pQueryRecords)
{
	ULONG n = 0;
	do
	{
		switch (pQueryRecords->wType)
		{
		case DNS_TYPE_A:
		case DNS_TYPE_AAAA:
			n++;
		}
	} while (pQueryRecords = pQueryRecords->pNext);

	return n;
}

void ProcessRecords(PDNS_RECORD pQueryRecords, PSOCKADDR_INET psi)
{
	static const WORD ip4to6[] = { 0, 0, 0, 0, 0, 0xffff };

	do
	{
		switch (pQueryRecords->wType)
		{
		case DNS_TYPE_AAAA:
			if (memcmp(ip4to6, pQueryRecords->Data.AAAA.Ip6Address.IP6Word, sizeof(ip4to6)))
			{
				psi->Ipv6.sin6_addr = pQueryRecords->Data.AAAA.Ip6Address.In6;
				psi->Ipv6.sin6_family = AF_INET6;
				psi->Ipv6.sin6_flowinfo = 0;
				psi->Ipv6.sin6_scope_id = 0;
				psi++->Ipv6.sin6_port = SERVER_PORT;
				continue;
			}
			pQueryRecords->Data.A.IpAddress = *(PULONG)(pQueryRecords->Data.AAAA.Ip6Address.IP6Word + 6);
			[[fallthrough]];
		case DNS_TYPE_A:
			psi->Ipv4.sin_addr.s_addr = pQueryRecords->Data.A.IpAddress;
			psi->Ipv4.sin_family = AF_INET;
			psi++->Ipv4.sin_port = SERVER_PORT;
			continue;
		}
	} while (pQueryRecords = pQueryRecords->pNext);
}

PDNS_RECORDW FindLostRecords(PDNS_RECORDW pRecords)
{
	if (!pRecords)
	{
		PDNS_RECORDW pTestRecord;

		HANDLE hHeap = GetProcessHeap();
		if (HeapLock(hHeap))
		{
			PDNS_RECORDW a[32];
			ULONG n = 0;
			PROCESS_HEAP_ENTRY he{};

			while (HeapWalk(hHeap, &he))
			{
				if ((he.wFlags & PROCESS_HEAP_ENTRY_BUSY) &&
					RTL_SIZEOF_THROUGH_FIELD(DNS_RECORDW, Data.AAAA) <= he.cbData)
				{
					pTestRecord = (PDNS_RECORDW)he.lpData;

					if (DNS_TYPE_AAAA == pTestRecord->wType &&
						pTestRecord->wDataLength == sizeof(DNS_AAAA_DATA) &&
						pTestRecord->pName &&
						pTestRecord->dwTtl)
					{
						if (n < _countof(a))
						{
							a[n++] = pTestRecord;
						}
					}
				}
			}

			if (n - 1 < _countof(a) - 1)
			{
				ULONG m = n, z = 0;
				LONG bits = (1 << n) - 1;

				do
				{
					pTestRecord = a[--n];
					if (PDNS_RECORDW pNext = pTestRecord->pNext)
					{
						ULONG i = m;
						do
						{
							if (pNext == a[--i])
							{
								_bittestandreset(&bits, i);
								break;
							}
						} while (i);
					}
					else
					{
						z++;
					}
				} while (n);

				if (1 == z && !(bits & (bits - 1)))
				{
					do
					{
						pRecords = a[n++];
					} while (bits >>= 1);
				}
			}

			HeapUnlock(hHeap);
		}
	}

	return pRecords;
}

class DNS_QUERY_CONTEXT : public DNS_QUERY_CANCEL, public DNS_QUERY_RESULT
{
	HWND _M_hwnd;
	ULONG _M_dwThreadId = GetCurrentThreadId();
public:

	DNS_QUERY_CONTEXT(_In_ HWND hwnd) : _M_hwnd(hwnd)
	{
		RtlZeroMemory(static_cast<DNS_QUERY_RESULT*>(this), sizeof(DNS_QUERY_RESULT));

		Version = DNS_QUERY_REQUEST_VERSION1;

		DbgPrint("%hs<%p>()\r\n", __FUNCTION__, this);
	}

	~DNS_QUERY_CONTEXT()
	{
		DbgPrint("%hs<%p>()\r\n", __FUNCTION__, this);
	}

	static void CALLBACK DnsQueryCompletionRoutine(PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
	{
		reinterpret_cast<DNS_QUERY_CONTEXT*>(pQueryContext)->DnsQueryCompleted(pQueryResults);
	}

	void DnsQueryCompleted(PDNS_QUERY_RESULT pQueryResults)
	{
		DNS_STATUS status = pQueryResults->QueryStatus;

		DbgPrint("%hs<%p>=%u, %p\n", __FUNCTION__, this, status, pQueryResults->pQueryRecords);

		PSOCKADDR_INET psi = 0;
		ULONG n = 0;

		if (NOERROR == status)
		{
			status = DNS_ERROR_RECORD_DOES_NOT_EXIST;

			if (PDNS_RECORDW pRecords = FindLostRecords(pQueryResults->pQueryRecords))
			{
				if (n = GetCount(pRecords))
				{
					status = E_OUTOFMEMORY;

					if (psi = new SOCKADDR_INET[n])
					{
						status = n;

						ProcessRecords(pRecords, psi);
					}
				}

				DnsRecordListFree(pRecords, DnsFreeRecordList);
			}
		}

		if (GetCurrentThreadId() == _M_dwThreadId)
		{
			SendMessageW(_M_hwnd, WM_DNS, (WPARAM)psi, status);
		}
		else
		{
			PostMessageW(_M_hwnd, WM_DNS, (WPARAM)psi, status);
		}

		delete this;
	}
};

void QueryServer(_In_ PCWSTR QueryName, _In_ HWND hwnd)
{
	if (DNS_QUERY_CONTEXT* pQueryContext = new DNS_QUERY_CONTEXT(hwnd))
	{
		DNS_QUERY_REQUEST request = {
			DNS_QUERY_REQUEST_VERSION1,
			QueryName,
			DNS_TYPE_AAAA,
			DNS_QUERY_ADDRCONFIG | DNS_QUERY_DUAL_ADDR,
			0,
			0,
			DNS_QUERY_CONTEXT::DnsQueryCompletionRoutine,
			pQueryContext
		};

		DNS_STATUS status = DnsQueryEx(&request, pQueryContext, pQueryContext);

		DbgPrint("%p>DnsQueryEx(%ws)=%u\r\n", pQueryContext, QueryName, status);

		if (status != DNS_REQUEST_PENDING)
		{
			pQueryContext->QueryStatus = status;
			pQueryContext->DnsQueryCompleted(pQueryContext);
		}
	}
	else
	{
		SendMessageW(hwnd, WM_DNS, 0, E_OUTOFMEMORY);
	}
}

_NT_END