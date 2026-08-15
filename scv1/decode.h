#pragma once

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ const BYTE* pb, _In_ ULONG cb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return CryptDecodeObjectEx(X509_ASN_ENCODING, lpszStructType, pb, cb,
		CRYPT_DECODE_ALLOC_FLAG|
		CRYPT_DECODE_NOCOPY_FLAG|
		CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG|
		CRYPT_DECODE_SHARE_OID_STRING_FLAG, 
		0, ppv, pcb ? pcb : &cb) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_DATA_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}

inline HRESULT Decode(_In_ PCSTR lpszStructType, _In_ PCRYPT_BIT_BLOB pdb, _Out_ void* ppv, _Out_opt_ PULONG pcb = 0)
{
	return Decode(lpszStructType, pdb->pbData, pdb->cbData, ppv, pcb);
}