#include "stdafx.h"

_NT_BEGIN

#include "cs-test-w.h"

BOOL YCS::post(CDataPacket* packet)
{
	packet->AddRef();
	if (PostMessageW(m_link_hwnd, WM_NULL, 0, (LPARAM)packet))
	{
		return TRUE;
	}
	packet->Release();
	return FALSE;
}

LRESULT YCS::WndProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam)
{
	switch (umsg)
	{
	case WM_NCDESTROY:
		OnDisconnect();
		PostMessageW(m_link_hwnd, WM_CLOSE, 0, 0);
		if (!InterlockedDecrement(m_pCount))
		{
			PostQuitMessage(0);
		}
		break;
	case WM_NULL:
		umsg = OnData((PBYTE)reinterpret_cast<CDataPacket*>(lParam)->getData(), 
			reinterpret_cast<CDataPacket*>(lParam)->getDataSize());
		reinterpret_cast<CDataPacket*>(lParam)->Release();
		if (!umsg)
		{
			DestroyWindow(hwnd);
		}
		return 0;
	}
	return DefWindowProcW(hwnd, umsg, wParam, lParam);
}

LRESULT CALLBACK YCS::StartWndProc(HWND hwnd, UINT umsg, WPARAM wParam, LPARAM lParam)
{
	if (WM_NCCREATE == umsg)
	{
		YCS* This = (YCS*)reinterpret_cast<LPCREATESTRUCTW>(lParam)->lpCreateParams;
		SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)This);
		SetWindowLongPtrW(hwnd, GWLP_WNDPROC, (LONG_PTR)s_WndProc);
		InterlockedIncrement(This->m_pCount);
		return This->WndProc(hwnd, umsg, wParam, lParam);
	}
	return 0;
}

BOOL YCS::Register()
{
	WNDCLASSW cls = { 0, StartWndProc, 0, 0, (HINSTANCE)&__ImageBase, 0, 0, 0, 0, s_name };
	return RegisterClassW(&cls);
}

void YCS::Unregister()
{
	if (!UnregisterClassW(s_name, (HINSTANCE)&__ImageBase))
	{
		__debugbreak();
	}
}

void client_server_test(PLONG r, YCS* client, YCS* server)
{
	*r = 1;

	client->m_link_hwnd = server->Create();
	server->m_link_hwnd = client->Create();

	if (InterlockedDecrement(r))
	{
		if (!server->OnConnect())
		{
			DestroyWindow(client->m_link_hwnd);
		}

		if (!client->OnConnect())
		{
			DestroyWindow(server->m_link_hwnd);
		}

		MSG msg;
		while (GetMessageW(&msg, 0, 0, 0))
		{
			DispatchMessageW(&msg);
		}
	}
}

_NT_END