#pragma once

#include "../asio/packet.h"

class UH_PACKET 
{
	enum PT { e_ecdh = 'HDCE', e_rsa = '*ASR', e_rsa_aes = '+ASR', e_aes = '*SEA', e_tpm = '2MPT' } magic;
	ULONG PacketSize;
	union {
		BYTE encrypted[];
		struct {
			USHORT s1, s2; // e_tpm
			UCHAR tpm_data[];
		};
		struct {
			ULONG DataSize; // in big endian in case e_rsa !!
			union {
				UCHAR rsa_data[];
				struct {
					UCHAR Nonce[12];
					UCHAR Tag[16];
					union {
						UCHAR buf[]; // ecdh+aes, aes
						struct {
							UCHAR aes[32];
							UCHAR rsa_aes_data[];
						};
					};
				};
			};
		};
	};

	HRESULT AES_Decode_I(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData);
	
	HRESULT AES_Encode_I(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData, _In_ PBYTE pb);

	HRESULT RSA_Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_In_ ULONG cbPacket, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Reserved_ BCRYPT_KEY_HANDLE* = 0);
	
	HRESULT RSA_AES_Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_In_ ULONG cbPacket, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);
	
	HRESULT DH_Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_In_ ULONG cbPacket, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);

	HRESULT RSA_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_In_ ULONG BlockLength,
		_Reserved_ BCRYPT_KEY_HANDLE* = 0);
	
	HRESULT RSA_AES_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_In_ ULONG BlockLength,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);

public:
	//++ Decode

	HRESULT AES_Decode(
		_In_ BCRYPT_KEY_HANDLE hKey, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData);

	HRESULT Decode(
		_In_ BCRYPT_KEY_HANDLE hPrivKey, 
		_Out_ PBYTE* ppbData, 
		_Out_ ULONG* pcbData,
		_Out_opt_ BCRYPT_KEY_HANDLE* phKey = 0);

	//-- Decode

	//++ Encode

	HRESULT AES_Encode(_In_ BCRYPT_KEY_HANDLE hKey, _In_ PBYTE pbData, _In_ ULONG cbData);

	static HRESULT AES_Encode(
		_In_ BCRYPT_KEY_HANDLE hKey, 
		_In_ PBYTE pbData, 
		_In_ ULONG cbData, 
		_Out_ CDataPacket** ppacket);

	static HRESULT RSA_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ BCRYPT_KEY_HANDLE *phKey = 0);

	static HRESULT DH_Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey,
		_In_ PCWSTR pszEccAlgId,
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ BCRYPT_KEY_HANDLE *phKey = 0);

	// internal call RSA_Encode or DH_Encode, based on hPubKey type
	static HRESULT Encode(
		_In_ BCRYPT_KEY_HANDLE hPubKey, 
		_In_opt_ PBYTE pbData, 
		_In_opt_ ULONG cbData, 
		_Out_ CDataPacket** ppacket,
		_Out_opt_ BCRYPT_KEY_HANDLE *phKey = 0);

	static UH_PACKET* AES_Allocate(_In_ ULONG cbData, _Out_ PBYTE *ppb, _Out_ CDataPacket** ppacket);
	
	static UH_PACKET* TPM_Allocate(_In_ ULONG cbData, _Out_ PBYTE *ppb, _Out_ CDataPacket** ppacket);

	//-- Encode

	static UH_PACKET* get(CDataPacket* packet)
	{
		return (UH_PACKET*)packet->getData();
	}

	ULONG getPacketSize()
	{
		return PacketSize;
	}

	void setPacketSize(ULONG cbPacket)
	{
		PacketSize = cbPacket;
	}

	static ULONG MinPacketSize()
	{
		return offsetof(UH_PACKET, buf);
	}

	ULONG setTpmSize(USHORT cb1, USHORT cb2)
	{
		s1 = cb1, s2 = cb2;
		return PacketSize = offsetof(UH_PACKET, tpm_data) + cb1 + cb2;
	}

	BOOL getTpmSize(_Out_ ULONG *ps1, _Out_ ULONG *ps2, _Out_ PBYTE* ppb1, _Out_ PBYTE* ppb2)
	{
		if (e_tpm == magic)
		{
			*ps1 = s1, *ps2 = s2, *ppb1 = tpm_data, *ppb2 = tpm_data + s1;
			return TRUE;
		}
		return FALSE;
	}
};

inline HRESULT CreateSessionKey(
								_In_ BCRYPT_KEY_HANDLE hPubKey,
								_Out_ CDataPacket** ppacket,
								_Out_ BCRYPT_KEY_HANDLE* phKey)
{
	return UH_PACKET::Encode(hPubKey, 0, 0, ppacket, phKey);
}