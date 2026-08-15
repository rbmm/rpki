#include "stdafx.h"

_NT_BEGIN

#include "container.h"

NTSTATUS sha256(_Out_ PUCHAR pbOut, _In_ ULONG cbOut, _In_ LPCVOID pbData, _In_ ULONG cbData)
{
	NTSTATUS status;
	BCRYPT_HASH_HANDLE hHash;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, 0, 0)))
	{
		status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, 0, 0, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			0 <= (status = BCryptHashData(hHash, (PUCHAR)pbData, cbData, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbOut, cbOut, 0));

			BCryptDestroyHash(hHash);
		}
	}

	return status;
}

NTSTATUS GetSerialHash(_In_ PCUNICODE_STRING VolumeName, _Out_ PUCHAR pbOut, _In_ ULONG cbOut)
{
	DbgPrint("GetSerialHash(%wZ)\n", VolumeName);

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(VolumeName) };

	KPROCESSOR_MODE mode = ExGetPreviousMode();

	NTSTATUS status = SKUM(mode, OpenFile)(&hFile, SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);

	if (0 <= status)
	{
		STORAGE_DEVICE_NUMBER sdn{};

		static const STORAGE_PROPERTY_QUERY spq = { StorageDeviceProperty, PropertyStandardQuery }; 

		union {
			PVOID buf;
			PBYTE pb;
			ULONG_PTR ubuf;
			PSTORAGE_DEVICE_DESCRIPTOR psdd;
		};

		ULONG cb = sizeof(STORAGE_DEVICE_DESCRIPTOR) + 0x180;

		do 
		{
			status = STATUS_NO_MEMORY;

#pragma warning (suppress : 4996)
			if (buf = ExAllocatePool(PagedPool, cb))
			{
				switch (status = SKUM(mode, DeviceIoControlFile)
					(hFile, 0, 0, 0, &iosb, IOCTL_STORAGE_QUERY_PROPERTY, (void*)&spq, sizeof(spq), buf, cb))
				{
				case STATUS_SUCCESS:
				case STATUS_BUFFER_OVERFLOW:

					if (!psdd->RemovableMedia)
					{
						status = STATUS_OBJECT_TYPE_MISMATCH;
						break;
					}

					if (psdd->Size > cb)
					{
						cb = psdd->Size;
						status = STATUS_BUFFER_OVERFLOW;
						break;
					}

					union {
						ULONG_PTR SerialNumberOffset;
						PSTR SerialNumber;
					};

					if ((SerialNumberOffset = psdd->SerialNumberOffset) && (SerialNumberOffset < psdd->Size))
					{
						pb[psdd->Size - 1] = 0;
						SerialNumber += ubuf;

						DbgPrint("SerialNumber=\"%hs\"\n", SerialNumber);

						status = sha256(pbOut, cbOut, SerialNumber, (ULONG)strlen(SerialNumber));

						if (status == STATUS_BUFFER_OVERFLOW)
						{
							status = STATUS_INTERNAL_ERROR;
						}
					}
					else
					{
						status = STATUS_NOT_FOUND;
					}

					break;
				}

				ExFreePool(buf);
			}

		} while (status == STATUS_BUFFER_OVERFLOW);

		SKUM(mode, Close)(hFile);
	}

	return status;
}

NTSTATUS OpenContainer(_In_ HANDLE hFile, _In_ PUNICODE_STRING VolumeName, _In_ ULONG hash, _Out_ SMARTCARD** ppSC)
{
	NTSTATUS status;
	IO_STATUS_BLOCK iosb;
	FILE_STANDARD_INFORMATION fsi;
	KPROCESSOR_MODE mode = ExGetPreviousMode();
	if (0 > (status = SKUM(mode, QueryInformationFile)(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		return status;
	}

	if (sizeof(RBMM_CARD) >= fsi.EndOfFile.QuadPart || 0x4000 < fsi.EndOfFile.QuadPart)
	{
		return STATUS_FILE_INVALID;
	}

	if (SMARTCARD* pSC = new(fsi.EndOfFile.LowPart) SMARTCARD(hash))
	{
		if (0 <= (status = SKUM(mode, ReadFile)(hFile, 0, 0, 0, &iosb, &pSC->m_card, fsi.EndOfFile.LowPart, 0, 0)))
		{
			if (pSC->m_card.size() == iosb.Information && RBMM_CARD::eMagic == pSC->m_card.dwMagic)
			{
				if (0 <= (status = GetSerialHash(VolumeName, pSC->m_Salt, sizeof(pSC->m_Salt))))
				{
					*ppSC = pSC;

					return STATUS_SUCCESS;
				}
			}
			else
			{
				status = STATUS_FILE_INVALID;
			}
		}

		delete pSC;

		return status;
	}

	return STATUS_NO_MEMORY;
}

NTSTATUS OpenContainer(_In_ PUNICODE_STRING VolumeName, _In_ ULONG hash, _Out_ SMARTCARD** ppSC)
{
	UNICODE_STRING ObjectName = { };
	int len = 0;
	while (0 < (len = _snwprintf(ObjectName.Buffer, len, L"%wZ\\BCB2ECBBF8FD46f68E0448547D3CECE8", VolumeName)))
	{
		if (ObjectName.Buffer)
		{
			IO_STATUS_BLOCK iosb;
			ObjectName.MaximumLength = ObjectName.Length = (USHORT)(len * sizeof(WCHAR));
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE };
			HANDLE hFile;
			NTSTATUS status;
			KPROCESSOR_MODE mode = ExGetPreviousMode( );

			if (0 <= (status = SKUM(mode, OpenFile)(&hFile, FILE_GENERIC_READ, &oa, 
				&iosb,  FILE_SHARE_VALID_FLAGS, FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
			{
				status = OpenContainer(hFile, VolumeName, hash, ppSC);

				SKUM(mode, Close)(hFile);
			}

			DbgPrint("%u: OpenContainer=%x \"%wZ\"\r\n", __LINE__, status, &ObjectName);

			return status;
		}

		ObjectName.Buffer = (PWSTR)alloca(++len * sizeof(WCHAR));
	}
	return STATUS_INTERNAL_ERROR;
}

_NT_END