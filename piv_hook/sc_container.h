#pragma once

struct RBMM_CARD 
{
	enum { eMagic = 'MMBR' };
	ULONG dwMagic;
	UCHAR Nonce[12];
	UCHAR cardid[16];
	ULONG cbCert;
	ULONG cbKey;
	UCHAR buf[];//cert+key

	ULONG size()
	{
		return FIELD_OFFSET(RBMM_CARD, buf) + cbCert + cbKey;
	}

	ULONG public_size()
	{
		return FIELD_OFFSET(RBMM_CARD, buf) + cbCert;
	}

	PBYTE GeyKey()
	{
		return buf + cbCert;
	}

#ifndef _KERNEL_MODE
	void* operator new(size_t s, ULONG cb)
	{
		return LocalAlloc(LMEM_FIXED, s + cb);
	}

	void operator delete(PVOID pv)
	{
		LocalFree(pv);
	}
#endif
};