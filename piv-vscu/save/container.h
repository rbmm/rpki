#pragma once

#define SKUM(km, api) (km ? Nt##api : Zw##api)

#include "piv_iso7816.h"

struct SMARTCARD 
{
	inline static const ULONG s_Tags[] = {
		// ----- mandatory -----
		PIV_OBJ_CHID, PIV_OBJ_CCC, 
		PIV_OBJ_CERT_PIV_ATH, KEY_PIV_AUTH,
		// ----- optional -----
		PIV_OBJ_CERT_CARD_ATH, KEY_CARD_AUTH,
		PIV_OBJ_CERT_SIGN, KEY_DIGITAL_SIG, 
		PIV_OBJ_CERT_KM, KEY_KEY_MGMT, 
	};

	BCRYPT_SECRET_HANDLE m_hSecret[4] = {};
	DATA_BLOB m_files[_countof(s_Tags)];
	EX_PUSH_LOCK m_lock = {};
	PBYTE m_pbIn = m_buf;
	PBYTE m_pbData = 0;
	ULONG m_cbData = 0;
	ULONG m_hash;

	USHORT m_P1P2;
	BYTE m_bIns;
	BOOLEAN m_bChain = FALSE;
	BOOLEAN m_PinSet = FALSE;
	BYTE m_pad[3];
	BYTE m_KeyMaterial[0x20];
	BYTE m_Salt[0x20];
	BYTE m_buf[0x4000];

	enum { maxInDataSize = 0x400 };

	void Reset();

	BOOLEAN InitFiles(HANDLE hFile);

	NTSTATUS KeyFromPin(
		_Out_ BCRYPT_KEY_HANDLE* phKey,
		_In_ PBYTE pbPin, 
		_In_ ULONG cbPin, 
		_Out_ PBYTE pbKeyMaterial, 
		_In_ ULONG cbKeyMaterial);

	NTSTATUS VerifyPin(PBYTE pbPin, ULONG cbPin);

	USHORT PivProcess(
		_In_ BYTE bCla,
		_In_ BYTE bIns,
		_In_ USHORT P1P2,
		_In_ PBYTE pb,
		_In_ ULONG cb,
		_Out_ PBYTE pbRecvBuffer,
		_In_ ULONG cbRecvBuffer,
		_Out_ PULONG pcbRecvLength);

	USHORT GetData(
		_Out_ PBYTE pbRecvBuffer,
		_In_ ULONG cbRecvBuffer,
		_Out_ PULONG pcbRecvLength);

	NTSTATUS DecryptKey(
		_In_ UCHAR iKey, 
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0,
		_Out_opt_ BCRYPT_KEY_HANDLE* phPubKey = 0,
		_In_opt_ PBYTE pbPublicKey = 0, 
		_In_opt_ ULONG cbPublicKey = 0);

	NTSTATUS ImportKey(
		_In_ PBYTE pb,
		_In_ ULONG cb,
		_Out_ BCRYPT_KEY_HANDLE* phKey,
		_Out_opt_ BCRYPT_KEY_HANDLE* phPubKey,
		_In_opt_ PBYTE pbPublicKey, 
		_In_opt_ ULONG cbPublicKey);

	NTSTATUS Sign(
		_In_ UCHAR iKey,
		_In_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_Out_ PBYTE pbBuffer, 
		_In_ ULONG OutputBufferLength, 
		_Out_ PULONG ReturnBufferLength
		);

	USHORT Decrypt(
		_In_ UCHAR iKey,
		_In_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_Out_ PBYTE pbBuffer, 
		_In_ ULONG OutputBufferLength, 
		_Out_ PULONG ReturnBufferLength
		);

	NTSTATUS CreateSecretAgreement(
		_In_ UCHAR iKey, 
		_In_ PBYTE pbPublicKey, 
		_In_ ULONG cbPublicKey, 
		_Out_ PUCHAR bSecretAgreementIndex);

	SMARTCARD(ULONG hash) : m_hash(hash)
	{
		DbgPrint("%hs<%p>(%x, %p)\n", __FUNCTION__, this, hash);
	}

	~SMARTCARD();

	NTSTATUS Transmit(
		_In_ PBYTE pbSendBuffer,
		_In_ ULONG cbSendLength,
		_Out_ PBYTE pbRecvBuffer,
		_In_ ULONG cbRecvBuffer, // + sizeof(USHORT)
		_Out_ PULONG pcbRecvLength
		);

	void Lock()
	{
		KeEnterCriticalRegion();
		ExfAcquirePushLockExclusive(&m_lock);
	}

	void Unlock()
	{
		ExfReleasePushLockExclusive(&m_lock);
		KeLeaveCriticalRegion();
	}

	void operator delete(PVOID pv)
	{
		ExFreePool(pv);
	}

	void* operator new(size_t s)
	{
#pragma warning (suppress : 4996)
		return ExAllocatePool(PagedPool, s);
	}
};

BOOL OpenContainer(_In_ PUNICODE_STRING VolumeName, _In_ ULONG hash, _Out_ SMARTCARD** ppSC);