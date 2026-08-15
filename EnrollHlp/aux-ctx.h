#pragma once

#include "../inc/rtlframe.h"
#include "cert.h"

struct ACB  
{
	BCRYPT_KEY_HANDLE m_hEkKey = 0;
	BCRYPT_KEY_HANDLE m_hSignKey;
	BCRYPT_KEY_HANDLE m_hUserKey = 0;// encrypt
	PCWSTR m_pszEccAlgId = 0;
	CERT_BUID* m_cert;
	PWSTR m_pszUserName;
	PBYTE m_pbMachine;
	PBYTE m_pbKeyAttestationStatement = 0;
	ULONG m_cbKeyAttestationStatement = 0;
	ULONG m_cchUserName;
	HRESULT m_hr = NOERROR;
	BOOLEAN m_IsTPM = FALSE;

	enum { e_need_PKI , e_need_UPN, e_need_machine, e_need_user, e_need_provider };
	LONG m_dwFlags = (1 << e_need_PKI) | (1 << e_need_UPN) | (1 << e_need_machine) | (1 << e_need_user) | (1 << e_need_provider);

	ACB(BCRYPT_KEY_HANDLE hSignKey, CERT_BUID* cert, PBYTE pbMachine, PWSTR pszUserName, ULONG cchUserName)
		: m_hSignKey(hSignKey), m_cert(cert), m_pbMachine(pbMachine), m_cchUserName(cchUserName), m_pszUserName(pszUserName)
	{
	}

	~ACB()
	{
		if (m_pbKeyAttestationStatement)
		{
			delete [] m_pbKeyAttestationStatement;
		}

		if (m_hEkKey)
		{
			BCryptDestroyKey(m_hEkKey);
		}

		if (m_hUserKey)
		{
			BCryptDestroyKey(m_hUserKey);
		}
	}

	void checkFinish(HRESULT hr);

	void I_SetProviderName(_In_ PCWSTR ProviderName);
	void I_SetPublicKey(_In_ PCERT_PUBLIC_KEY_INFO pInfo);
	void I_SetUPN(_In_ PCWSTR pcszUPN);
	void I_SetMachine(_In_ PCWSTR pcszMachine);
	void I_SetUser(_In_ PCWSTR pcszUser);
	void I_SetEKCert(_In_ const BYTE* pbCertEncoded, _In_ DWORD cbCertEncoded);
	void I_SetKAS(_In_ const BYTE* pbKAS, _In_ DWORD cbKAS);

#define DEFINE_FORWARDER(Func) \
	template <typename... Args> static void Func(Args&&... args) { \
	if (ACB* This = RTL_FRAME<ACB>::get()) This->I_##Func(args...); \
	}

	DEFINE_FORWARDER(SetProviderName);
	DEFINE_FORWARDER(SetPublicKey);
	DEFINE_FORWARDER(SetUPN);
	DEFINE_FORWARDER(SetMachine);
	DEFINE_FORWARDER(SetUser);
	DEFINE_FORWARDER(SetEKCert);
	DEFINE_FORWARDER(SetKAS);
};