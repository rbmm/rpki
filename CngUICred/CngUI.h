#pragma once

enum class CNG_CREDUI_SCENARIO {
	Set, Get
};
enum class CNG_KEY_PROTECTION_LEVEL 
{
	Query, NoPassword, RequirePassword, FingerPrint
};

struct CNG_CRED_UI_DATA 
{
	enum : ULONG { eAP = 0xffffdd48 };

	ULONG cbHeader; /*00*/
	CNG_CREDUI_SCENARIO dwScenario; /*04*/
	ULONG cchText; /*08*/
	ULONG cbData; /*0c*/
	BOOL bCheckboxState; /*10*/
	CNG_KEY_PROTECTION_LEVEL dwProtectionLevel; /*14*/

	WCHAR szText[/*cchText*/];
	//	BYTE pbData[/*cbData*/];

	void* operator new(size_t s, PCWSTR pszText)
	{
		if (sizeof(CNG_CRED_UI_DATA) == s)
		{
			ULONG cchText = (ULONG)wcslen(pszText) + 1, cbText = cchText * sizeof(WCHAR);

			if (CNG_CRED_UI_DATA* p = (CNG_CRED_UI_DATA*)CoTaskMemAlloc(sizeof(CNG_CRED_UI_DATA) + cbText))
			{
				p->cbData = 0, p->cchText = cchText;
				memcpy(p->szText, pszText, cbText);
				return p;
			}
		}

		return 0;
	}

	void* operator new(size_t s, PBYTE pbData, ULONG cbData)
	{
		if (sizeof(CNG_CRED_UI_DATA) == s)
		{
			if (CNG_CRED_UI_DATA* p = (CNG_CRED_UI_DATA*)CoTaskMemAlloc(sizeof(CNG_CRED_UI_DATA) + cbData))
			{
				p->cbData = cbData, p->cchText = 0;
				memcpy(p->szText, pbData, cbData);
				return p;
			}
		}

		return 0;
	}

	void operator delete(void* pv)
	{
		CoTaskMemFree(pv);
	}

	PBYTE GetData()
	{
		return (PBYTE)(szText + cchText + 1);
	}

	ULONG GetSize()
	{
		return sizeof(CNG_CRED_UI_DATA) + cchText * sizeof(WCHAR) + cbData;
	}

	CNG_CRED_UI_DATA(CNG_CREDUI_SCENARIO dwScenario, BOOL bCheckboxState, CNG_KEY_PROTECTION_LEVEL dwProtectionLevel) 
		: bCheckboxState(bCheckboxState), dwProtectionLevel(dwProtectionLevel), 
		cbHeader(sizeof(CNG_CRED_UI_DATA)), dwScenario(dwScenario)
	{
	}
};

C_ASSERT(sizeof(CNG_CRED_UI_DATA) == offsetof(CNG_CRED_UI_DATA, szText));