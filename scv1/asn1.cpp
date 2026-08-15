#include "stdafx.h"

_NT_BEGIN

#include "asn1.h"

BOOL StoreSingleTag(_In_ ULONG Tag, 
					_In_ const void* pv, 
					_In_ ULONG cb, 
					_Inout_ PBYTE pb, 
					_In_ ULONG OutputBufferLength, 
					_Out_ PULONG ReturnBufferLength)
{
	union {
		ULONG uTagLen;
		struct {
			SCHAR s_0;
			SCHAR s_1;
			SCHAR s_2;
			SCHAR s_3;
		};
		struct {
			BYTE tag : 5;
			BYTE composite : 1;
			BYTE cls : 2;
		};
	};

	if (!OutputBufferLength--)
	{
		return FALSE;
	}

	PBYTE _pb = pb;

	uTagLen = Tag;

	*pb++ = s_0;

	if (tag == 0x1F)
	{
		if (!OutputBufferLength--)
		{
			return FALSE;
		}

		*pb++ = s_1;

		if (0 > s_1)
		{
			if (!OutputBufferLength--)
			{
				return FALSE;
			}

			*pb++ = s_2;

			if (0 > s_2)
			{
				if (!OutputBufferLength--)
				{
					return FALSE;
				}

				*pb++ = s_3;
			}
		}
	}

	ULONG s;

	if (cb < 0x80)
	{
		s = 1;
	}
	else if (cb < 0x100)
	{
		s = 2;
	}
	else if (cb < 0x10000)
	{
		s = 3;
	}
	else
	{
		s = 5;
	}

	if (OutputBufferLength < s)
	{
		return FALSE;
	}

	OutputBufferLength -= s;

	uTagLen = cb;

	if (cb < 0x80)
	{
		goto __0;
	}

	if (cb < 0x100)
	{
		*pb++ = 0x81;
		goto __0;
	}

	if (cb < 0x10000)
	{
		*pb++ = 0x82;
		goto __1;
	}

	*pb++ = 0x84;
	*pb++ = s_3;
	*pb++ = s_2;
__1:
	*pb++ = s_1;
__0:
	*pb++ = s_0;

	if (OutputBufferLength < cb)
	{
		return FALSE;
	}

	memcpy(pb, pv, cb);

	*ReturnBufferLength = RtlPointerToOffset(_pb, pb + cb);

	return TRUE;
}

BOOL Asn1Alloc::Store(_In_ ULONG Tag, _In_ ULONG Len, _In_opt_ const void* pvData, _In_opt_ ULONG cbData)
{
	ULONG cb = _cb;
	PBYTE pb = _pb;

	if (cbData)
	{
		if (cb < cbData)
		{
			return FALSE;
		}

		cb -= cbData;
		memcpy(pb -= cbData, pvData, cbData);
	}

	union {
		ULONG uTagLen;
		struct {
			SCHAR s_0;
			SCHAR s_1;
			SCHAR s_2;
			SCHAR s_3;
		};
		struct {
			BYTE tag : 5;
			BYTE composite : 1;
			BYTE cls : 2;
		};
	};

	uTagLen = Len;

	ULONG s;

	if (Len < 0x80)
	{
		s = 1;
	}
	else if (Len < 0x100)
	{
		s = 2;
	}
	else if (Len < 0x10000)
	{
		s = 3;
	}
	else
	{
		s = 5;
	}

	if (cb < s)
	{
		return FALSE;
	}

	cb -= s, pb -= s;

	PBYTE lpb = pb;

	if (Len < 0x80)
	{
		goto __0;
	}

	if (Len < 0x100)
	{
		*lpb++ = 0x81;
		goto __0;
	}

	if (Len < 0x10000)
	{
		*lpb++ = 0x82;
		goto __1;
	}

	*lpb++ = 0x84;
	*lpb++ = s_3;
	*lpb++ = s_2;
__1:
	*lpb++ = s_1;
__0:
	*lpb++ = s_0;

	uTagLen = Tag;

	s = 1;

	if (tag == 0x1F)
	{
		s = 2;

		if (s_1 < 0)
		{
			s = 3;

			if (s_2 < 0)
			{
				s = 4;
			}
		}
	}

	if (cb < s)
	{
		return FALSE;
	}

	cb -= s, lpb = (pb -= s);

	*lpb++ = s_0;

	if (tag == 0x1F)
	{
		*lpb++ = s_1;

		if (0 > s_1)
		{
			*lpb++ = s_2;

			if (0 > s_2)
			{
				*lpb++ = s_3;
			}
		}
	}

	_pb = pb, _cb = cb;

	return TRUE;
}

_NT_END