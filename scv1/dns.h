#pragma once

enum { WM_DNS = WM_APP, WM_RETURN_KEY, WM_CERT, SERVER_PORT = 13698 };

void QueryServer(_In_ PCWSTR QueryName, _In_ HWND hwnd);
