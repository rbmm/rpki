#include "stdafx.h"

_NT_BEGIN

#include "container.h"

SMARTCARD::~SMARTCARD()
{
	DbgPrint("%hs<%p>(%x)\n", __FUNCTION__, this, m_hash);

	Reset();
}

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

	IO_STATUS_BLOCK iosb;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(VolumeName) };

	bool km = ExGetPreviousMode() == KernelMode;

	NTSTATUS status = SKUM(km, OpenFile)(&oa.RootDirectory, SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);

	if (0 <= status)
	{
		STORAGE_DEVICE_NUMBER sdn{};

		static const STORAGE_PROPERTY_QUERY spq = { StorageDeviceProperty, PropertyStandardQuery }; 

		union {
			PVOID buf;
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
				switch (status = SKUM(km, DeviceIoControlFile)
					(oa.RootDirectory, 0, 0, 0, &iosb, IOCTL_STORAGE_QUERY_PROPERTY, (void*)&spq, sizeof(spq), buf, cb))
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

					if (SerialNumberOffset = psdd->SerialNumberOffset)
					{
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

		SKUM(km, Close)(oa.RootDirectory);
	}

	return status;
}

BOOL OpenContainer(_In_ HANDLE hFile, _In_ PUNICODE_STRING VolumeName, _In_ ULONG hash, _Out_ SMARTCARD** ppSC)
{
	if (SMARTCARD* pSC = new SMARTCARD(hash))
	{
		if (0 <= GetSerialHash(VolumeName, pSC->m_Salt, sizeof(pSC->m_Salt)))
		{
			if (pSC->InitFiles(hFile))
			{
				*ppSC = pSC;

				return TRUE;
			}
		}

		delete pSC;
	}
	return FALSE;
}

BOOL OpenContainer(_In_ PUNICODE_STRING VolumeName, _In_ ULONG hash, _Out_ SMARTCARD** ppSC)
{
	BOOL fOk = FALSE;
	UNICODE_STRING ObjectName = { };
	int len = 0;
	while (0 < (len = _snwprintf(ObjectName.Buffer, len, L"%wZ\\{4ED8B5D0-1CB8-4958-8CA7-80EDA0CE6EBF}", VolumeName)))
	{
		if (ObjectName.Buffer)
		{
			IO_STATUS_BLOCK iosb;
			ObjectName.MaximumLength = ObjectName.Length = (USHORT)(len * sizeof(WCHAR));
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE };
			HANDLE hFile;

			if (0 <= SKUM(ExGetPreviousMode() == KernelMode, OpenFile)(&hFile, FILE_GENERIC_READ, &oa, 
				&iosb,  FILE_SHARE_VALID_FLAGS, FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))
			{
				fOk = OpenContainer(hFile, VolumeName, hash, ppSC);

				NtClose(hFile);
			}
			break;
		}

		ObjectName.Buffer = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return fOk;
}

_NT_END