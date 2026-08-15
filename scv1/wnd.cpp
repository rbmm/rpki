#include "stdafx.h"

_NT_BEGIN

#include "wnd.h"

INT_PTR CALLBACK SimpDlg::_DialogProc(
	HWND hwnd, 
	UINT uMsg, 
	WPARAM wParam, 
	LPARAM lParam 
	)
{
	return reinterpret_cast<SimpDlg*>(GetWindowLongPtrW(hwnd, DWLP_USER))->wDialogProc(hwnd, uMsg, wParam, lParam);
}

INT_PTR SimpDlg::wDialogProc(
								HWND hwnd, 
								UINT uMsg, 
								WPARAM wParam, 
								LPARAM lParam 
								)
{
	++_M_dwMessageCount;

	lParam = DialogProc(hwnd, uMsg, wParam, lParam);

	if (!--_M_dwMessageCount)
	{
		AfterLastMessage();
		Release();
	}

	return lParam;
}

INT_PTR CALLBACK SimpDlg::__DialogProc(
	HWND hwnd, 
	UINT uMsg, 
	WPARAM /*wParam*/, 
	LPARAM lParam )
{
	if (uMsg == WM_INITDIALOG)
	{
		SetWindowLongPtrW(hwnd, DWLP_USER, lParam);
		SetWindowLongPtrW(hwnd, DWLP_DLGPROC, reinterpret_cast<LPARAM>(_DialogProc));
		reinterpret_cast<SimpDlg*>(lParam)->AddRef();
		reinterpret_cast<SimpDlg*>(lParam)->_M_dwMessageCount = 1 << 31;
		return reinterpret_cast<SimpDlg*>(lParam)->OnInitDialog(hwnd);
	}

	return 0;
}

INT_PTR SimpDlg::DialogProc(
							HWND /*hwnd*/, 
							UINT uMsg, 
							WPARAM /*wParam*/, 
							LPARAM /*lParam*/ 
							)
{
	switch (uMsg)
	{
	case WM_NCDESTROY:
		_bittestandreset(&_M_dwMessageCount, 31);
		break;
	}

	return 0;
}

HWND SimpDlg::Create(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent)
{
	return CreateDialogParamW(hInstance, lpTemplateName, hWndParent, __DialogProc, (LPARAM)this);
}

INT_PTR SimpDlg::DoModal(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent)
{
	return DialogBoxParamW(hInstance, lpTemplateName, hWndParent, __DialogProc, (LPARAM)this);
}

ULONG STDMETHODCALLTYPE SimpDlg::AddRef()
{
	return InterlockedIncrementNoFence(&_M_dwRef);
}

ULONG STDMETHODCALLTYPE SimpDlg::Release()
{
	if (ULONG dwRef = InterlockedDecrement(&_M_dwRef))
	{
		return dwRef;
	}
	delete this;
	return 0;
}

_NT_END