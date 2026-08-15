#pragma once

HRESULT PFXImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _In_ PCSTR pin,
				  _In_ HWND hwndDlg,
				  _In_ UCHAR SerialMD5[],
				  _In_ ULONG DeviceNumber);

HRESULT PEMImport(_In_ PCWSTR lpFileName, 
				  _In_ PCWSTR szPassword, 
				  _In_ PCSTR pin,
				  _In_ HWND hwndDlg,
				  _In_ UCHAR SerialMD5[],
				  _In_ ULONG DeviceNumber);