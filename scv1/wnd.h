#pragma once

class __declspec(novtable) SimpDlg 
{
	LONG _M_dwRef = 1;
	LONG _M_dwMessageCount;

	static INT_PTR CALLBACK __DialogProc(
		HWND hwnd, 
		UINT uMsg, 
		WPARAM wParam, 
		LPARAM lParam 
		);

	static INT_PTR CALLBACK _DialogProc(
		HWND hwnd, 
		UINT uMsg, 
		WPARAM wParam, 
		LPARAM lParam 
		);

	INT_PTR wDialogProc(
		HWND hwnd, 
		UINT uMsg, 
		WPARAM wParam, 
		LPARAM lParam 
		);

protected:
	virtual ~SimpDlg() = default;

	virtual INT_PTR DialogProc(
		HWND hwnd, 
		UINT uMsg, 
		WPARAM wParam, 
		LPARAM lParam 
		);

	virtual void AfterLastMessage()
	{
	}

	virtual INT_PTR OnInitDialog(HWND hwnd) = 0;

public:
	virtual ULONG STDMETHODCALLTYPE AddRef();

	virtual ULONG STDMETHODCALLTYPE Release();

	HWND Create(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent);

	INT_PTR DoModal(HINSTANCE hInstance, PCWSTR lpTemplateName, HWND hWndParent);
};