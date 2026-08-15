#pragma once

#include "../asio/packet.h"

struct __declspec(novtable) YCS 
{
	inline static const WCHAR s_name[] = L"{B8869F43-758F-40fb-A24D-82F7D36CC87C}";

	HWND m_link_hwnd;
	PLONG m_pCount;
	PCSTR m_name;

	YCS(PLONG pCount, PCSTR name) : m_name(name), m_pCount(pCount)
	{
	}

	HWND Create()
	{
		return CreateWindowExW(0, s_name, 0, 0, 0, 0, 0, 0, HWND_MESSAGE, 0, 0, this);
	}

	BOOL post(CDataPacket* packet);

	virtual BOOL OnConnect() = 0;
	virtual void OnDisconnect() = 0;
	virtual BOOL OnData(PBYTE pb, ULONG cb) = 0;

	LRESULT WndProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam);

	static LRESULT CALLBACK s_WndProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam)
	{
		return reinterpret_cast<YCS*>(GetWindowLongPtrW(hwnd, GWLP_USERDATA))->WndProc(hwnd, umsg, wParam, lParam);
	}

	static LRESULT CALLBACK StartWndProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam);

	static BOOL Register();

	static void Unregister();
};

void client_server_test(PLONG r, YCS* client, YCS* server);