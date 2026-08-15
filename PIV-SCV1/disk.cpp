#include "stdafx.h"

_NT_BEGIN

#include <initguid.h>
#include <ntddstor.h>
#include "disk.h"
#include <initguid.h>
#include <devpkey.h>

extern const volatile UCHAR guz = 0;

NTSTATUS sha256(_Out_ PUCHAR pbOut, _In_ ULONG cbOut, _In_ LPCVOID pbData, _In_ ULONG cbData)
{
	return GetLastHresult(CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, 0, (PUCHAR)pbData, cbData, pbOut, &cbOut));
}

HRESULT CoStrDup(_In_ PCWSTR psz, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
	*ppwsz = 0;

	if (!psz) return E_INVALIDARG;

	SIZE_T cb = (wcslen(psz) + 1) * sizeof(WCHAR);

	if (PVOID pv = CoTaskMemAlloc(cb))
	{
		memcpy(pv, psz, cb);
		*ppwsz = (PWSTR)pv;

		return S_OK;
	}

	return E_OUTOFMEMORY;
}

struct __declspec(novtable) CInterfaceList 
{
	virtual BOOL OnInterface(_In_ PWSTR pszDeviceInterface) = 0;

	void Enum(_In_ LPCGUID Guid)
	{
		CONFIGRET cr;
		ULONG cb = 0, rcb;
		union {
			PVOID buf;
			PZZWSTR Buffer;
		};

		PVOID stack = alloca(guz);
		do 
		{
			cr = CM_Get_Device_Interface_List_SizeW(&rcb, const_cast<GUID*>(Guid), 0, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

			if (cr != CR_SUCCESS)
			{
				break;
			}

			if (cb < (rcb *= sizeof(WCHAR)))
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			cr = CM_Get_Device_Interface_ListW(const_cast<GUID*>(Guid), 
				0, Buffer, cb/sizeof(WCHAR), CM_GET_DEVICE_INTERFACE_LIST_PRESENT);

		} while (cr == CR_BUFFER_SMALL);

		if (cr == CR_SUCCESS)
		{
			while (*Buffer && OnInterface(Buffer))
			{
				Buffer += wcslen(Buffer) + 1;
			}
		}
	}
};

CONFIGRET GetFriendlyName(_Out_ PWSTR* ppszName, _In_ DEVINST dnDevInst)
{
	DEVPROPTYPE PropertyType;

	union {
		PVOID pv;
		PWSTR sz;
		PBYTE pb;
	};

	ULONG cb = 0x80;
	CONFIGRET cr;

	do 
	{
		cr = CR_OUT_OF_MEMORY;

		if (pv = LocalAlloc(0, cb))
		{
			if (CR_SUCCESS == (cr = CM_Get_DevNode_PropertyW(dnDevInst, &DEVPKEY_NAME, &PropertyType, pb, &cb, 0)))
			{
				*ppszName = sz;
				return CR_SUCCESS;
			}
			LocalFree(pv);
		}

	} while (cr == CR_BUFFER_SMALL);

	return cr;
}

CONFIGRET GetFriendlyName(_Out_ PWSTR* ppszName, _In_ PCWSTR pszDeviceInterface)
{
	DEVPROPTYPE PropertyType;

	union {
		PBYTE PropertyBuffer;
		PVOID buf;
		PWSTR pszName;
		DEVINSTID_W pDeviceID;
	};

	ULONG cb = 0, rcb = 0x80;
	CONFIGRET cr;
	PVOID stack = alloca(guz);

	do 
	{
		if (cb < rcb)
		{
			rcb = cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		cr = CM_Get_Device_Interface_PropertyW(pszDeviceInterface, 
			&DEVPKEY_Device_InstanceId, &PropertyType, PropertyBuffer, &rcb, 0);

	} while (cr == CR_BUFFER_SMALL);

	if (cr == CR_SUCCESS)
	{
		if (PropertyType != DEVPROP_TYPE_STRING)
		{
			return CR_FAILURE;
		}

		DEVINST dnDevInst;

		if (CR_SUCCESS == (cr = CM_Locate_DevNodeW(&dnDevInst, pDeviceID, CM_LOCATE_DEVNODE_NORMAL)))
		{
			return GetFriendlyName(ppszName, dnDevInst);
		}
	}

	return cr;
}

//////////////////////////////////////////////////////////////////////////

struct CVolumeList : CInterfaceList
{
	PWSTR szVolume;
	ULONG cchVolume;
	ULONG DeviceNumber;
	NTSTATUS opStatus = STATUS_UNRECOGNIZED_MEDIA;

	CVolumeList(ULONG DeviceNumber, PWSTR szVolume, ULONG cchVolume) : DeviceNumber(DeviceNumber), szVolume(szVolume), cchVolume(cchVolume)
	{
	}

	virtual BOOL OnInterface(_In_ PWSTR pszDeviceInterface);
};

extern const WCHAR Device[];
extern const WCHAR MyId[];

BOOL CVolumeList::OnInterface(_In_ PWSTR pszDeviceInterface)
{
	if (HANDLE hVolume = fixH(CreateFileW(pszDeviceInterface, 0, FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)))
	{
		IO_STATUS_BLOCK iosb;
		VOLUME_DISK_EXTENTS vde;

		NTSTATUS status = NtDeviceIoControlFile(hVolume, 0, 0, 0, &iosb,
			IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0, 0, &vde, sizeof(vde));

		NtClose(hVolume);

		if (0 <= status && 1 == vde.NumberOfDiskExtents && vde.Extents->DiskNumber == DeviceNumber)
		{
			pszDeviceInterface[1] = '?';
			opStatus = 0 > swprintf_s(szVolume, cchVolume, 
				L"%ws%ws%ws\\BCB2ECBBF8FD46f68E0448547D3CECE8", Device, MyId, pszDeviceInterface) ? STATUS_BUFFER_TOO_SMALL : 0;

			return FALSE;
		}
	}

	return TRUE;
}

NTSTATUS FormatContainerName(ULONG DeviceNumber, PWSTR szVolume, ULONG cchVolume)
{
	CVolumeList vl(DeviceNumber, szVolume, cchVolume);
	vl.Enum(&GUID_DEVINTERFACE_VOLUME);
	return vl.opStatus;
}

//////////////////////////////////////////////////////////////////////////

struct CDisk : public LIST_ENTRY 
{
	UCHAR _Serial[32];
	PWSTR _name = 0;
	ULONG _DeviceNumber;
	ULONG _hash = 0;

	~CDisk()
	{
		if (PVOID p = _name)
		{
			delete [] p;
		}
	}

	CDisk(ULONG DeviceNumber) : _DeviceNumber(DeviceNumber)
	{
	}

	CONFIGRET InitName(_In_ PCWSTR pszDeviceInterface)
	{
		UNICODE_STRING String;
		RtlInitUnicodeString(&String, pszDeviceInterface);
		RtlHashUnicodeString(&String, FALSE, HASH_STRING_ALGORITHM_DEFAULT, &_hash);

		return GetFriendlyName(&_name, pszDeviceInterface);
	}

	BOOL InitName(PCSTR ProductId)
	{
		PWSTR name = 0;
		ULONG cch = 0;
		while (cch = MultiByteToWideChar(CP_ACP, 0, ProductId, 0, name, cch))
		{
			if (name)
			{
				_name = name;
				return TRUE;
			}

			if (!(name = new WCHAR[cch]))
			{
				break;
			}
		}

		return FALSE;
	}

	BOOL InitName2(_In_ PCWSTR pszDeviceInterface)
	{
		if (pszDeviceInterface = wcschr(pszDeviceInterface, '#'))
		{
			if (PWSTR pc = wcschr(++pszDeviceInterface, '#'))
			{
				size_t cch = pc - pszDeviceInterface;
				if (PWSTR name = new WCHAR[cch + 1])
				{
					memcpy(name, pszDeviceInterface, cch * sizeof(WCHAR));
					name[cch] = 0;
					_name = name;

					return TRUE;
				}
			}
		}

		return FALSE;
	}
};

BOOL IsExistPartitions(_In_ HANDLE hDisk)
{
	ULONG cb = 0, rcb = FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry[4]), d = 4*sizeof(PARTITION_INFORMATION_EX);

	union {
		PVOID buf;
		PDRIVE_LAYOUT_INFORMATION_EX pdli;
	};

	PVOID stack = alloca(guz);

__loop:
	if (cb < rcb)
	{
		cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
	}

	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtDeviceIoControlFile(hDisk, 0, 0, 0, &iosb, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, 0, 0, pdli, cb);

	switch (status)
	{
	case STATUS_BUFFER_TOO_SMALL:
	case STATUS_INFO_LENGTH_MISMATCH:
	case STATUS_BUFFER_OVERFLOW:
		rcb += d, d <<= 1;
		goto __loop;

	case STATUS_SUCCESS:
		if (ULONG PartitionCount = pdli->PartitionCount)
		{
			PPARTITION_INFORMATION_EX PartitionEntry = pdli->PartitionEntry;
			do 
			{
				if (PartitionEntry->PartitionNumber)
				{
					switch (PartitionEntry->PartitionStyle)
					{							
					case PARTITION_STYLE_GPT:
						return TRUE;
					case PARTITION_STYLE_MBR:
						if (PartitionEntry->Mbr.RecognizedPartition)
						{
							return TRUE;
						}
					}
				}

			} while (PartitionEntry++, --PartitionCount);
		}
		break;
	}

	return status;
}

BOOL OnDiskArrival(_Out_ CDisk** ppDisk, _In_ PCWSTR pszDeviceInterface)
{
	DbgPrint("\r\n====================================\r\n%S\r\n", pszDeviceInterface);

	BOOL fOk = FALSE;

	if (HANDLE hDisk = fixH(CreateFileW(pszDeviceInterface, 0, 
		FILE_SHARE_VALID_FLAGS, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)))
	{
		ULONG cb = 0, rcb;

		PVOID stack = alloca(guz);
		STORAGE_DEVICE_NUMBER sdn{};
		IO_STATUS_BLOCK iosb;

		NTSTATUS status = NtDeviceIoControlFile(hDisk, 0, 0, 0, &iosb,
			IOCTL_STORAGE_GET_DEVICE_NUMBER, 0, 0, &sdn, sizeof(sdn));

		if (0 <= status && sdn.DeviceType == FILE_DEVICE_DISK && !sdn.PartitionNumber)
		{
			static const STORAGE_PROPERTY_QUERY spq = { StorageDeviceProperty, PropertyStandardQuery }; 

			union {
				PVOID buf;
				PSTR psz;
				ULONG_PTR ubuf;
				PBYTE pb;
				PSTORAGE_DEVICE_DESCRIPTOR psdd;
			};

			rcb = sizeof(STORAGE_DEVICE_DESCRIPTOR) + 0x200;

__loop:
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			switch (status = (NtDeviceIoControlFile(hDisk, 0, 0, 0, &iosb, 
				IOCTL_STORAGE_QUERY_PROPERTY, (void*)&spq, sizeof(spq), buf, cb)))
			{
			case STATUS_SUCCESS:
			case STATUS_BUFFER_OVERFLOW:

				if (psdd->Size > cb)
				{
					rcb = psdd->Size;
					goto __loop;
				}

				union {
					ULONG_PTR Offset;
					PSTR SerialNumber;
				};

				if (!psdd->RemovableMedia || !(Offset = psdd->SerialNumberOffset) || Offset >= psdd->Size || !IsExistPartitions(hDisk))
				{
					break;
				}

				if (CDisk* pDisk = new CDisk(sdn.DeviceNumber))
				{
					pb[psdd->Size - 1] = 0;
					Offset += ubuf;

					DbgPrint("Serial=\"%hs\"\r\n", SerialNumber);

					if (0 <= sha256(pDisk->_Serial, sizeof(pDisk->_Serial), SerialNumber, (ULONG)strlen(SerialNumber)))
					{
						if (CR_SUCCESS == pDisk->InitName(pszDeviceInterface))
						{
__ok:
							fOk = TRUE;
							*ppDisk = pDisk;
							break;
						}

						if (Offset = psdd->ProductIdOffset)
						{
							if (pDisk->InitName(psz + Offset))
							{
								goto __ok;
							}
						}

						if (pDisk->InitName2(pszDeviceInterface))
						{
							goto __ok;
						}
					}

					delete pDisk;
				}

				break;
			}
		}

		NtClose(hDisk);
	}

	return fOk;
}

void DiskList::EnumDisks(_In_ HWND hwndCB)
{
	struct CDiskList : public CInterfaceList
	{
		DiskList* List;
		HWND hwndCB;

		virtual BOOL OnInterface(_In_ PWSTR pszDeviceInterface)
		{
			List->Add(hwndCB, pszDeviceInterface);
			return TRUE;
		}

		CDiskList(DiskList* List, HWND hwndCB) : List(List), hwndCB(hwndCB)
		{
		}

	} e(this, hwndCB);

	e.Enum(&GUID_DEVINTERFACE_DISK);
}

HDEVNOTIFY DiskList::Init(_In_ HWND hwndCB, _In_ HWND hwndMy)
{
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter = { 
		sizeof(DEV_BROADCAST_DEVICEINTERFACE), DBT_DEVTYP_DEVICEINTERFACE, 0, GUID_DEVINTERFACE_DISK
	};

	HDEVNOTIFY HandleV = RegisterDeviceNotification(hwndMy, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);

	EnumDisks(hwndCB);

	return HandleV;
}

DiskList::~DiskList()
{
	PLIST_ENTRY head = this, entry = head->Blink;
	while (entry != head)
	{
		CDisk* pDisk = static_cast<CDisk*>(entry);
		entry = entry->Blink;
		delete pDisk;
	}
}

CDisk* DiskList::GetDisk(ULONG dwItem)
{
	if (dwItem < _cItems)
	{
		PLIST_ENTRY entry = this;

		do 
		{
			entry = entry->Flink;
		} while (dwItem--);

		return static_cast<CDisk*>(entry);
	}

	return 0;
}

PCWSTR DiskList::GetDiskName(ULONG dwItem)
{
	if (CDisk* pDisk = GetDisk(dwItem))
	{
		return pDisk->_name;
	}

	return 0;
}

int DiskList::GetDeviceNumber(_In_ ULONG dwItem, _Out_ UCHAR Serial[])
{
	if (CDisk* pDisk = GetDisk(dwItem))
	{
		memcpy(Serial, pDisk->_Serial, sizeof(pDisk->_Serial));
		return pDisk->_DeviceNumber;
	}

	return -1;
}

HRESULT DiskList::GetComboBoxValueAt(ULONG dwItem, PWSTR *ppszItem)
{
	if (CDisk* pDisk = GetDisk(dwItem))
	{
		return CoStrDup(pDisk->_name, ppszItem);
	}

	*ppszItem = 0;
	return E_INVALIDARG;
}

void DiskList::Remove(_In_ HWND hwndCB, _In_ PCWSTR pszDeviceInterface)
{
	DbgPrint("REMOVECOMPLETE: %S\r\n", pszDeviceInterface);

	ULONG hash;
	UNICODE_STRING String;
	RtlInitUnicodeString(&String, pszDeviceInterface);
	RtlHashUnicodeString(&String, FALSE, HASH_STRING_ALGORITHM_DEFAULT, &hash);

	ULONG dwItem = 0;
	PLIST_ENTRY head = this, entry = head;

	while ((entry = entry->Flink) != head)
	{
		if (static_cast<CDisk*>(entry)->_hash == hash)
		{
			_cItems--;
			if (dwItem < _dwSelectedItem || _dwSelectedItem == _cItems)
			{
				_dwSelectedItem--;
			}
			RemoveEntryList(entry);
			delete static_cast<CDisk*>(entry);

			ComboBox_DeleteString(hwndCB, dwItem);
			ComboBox_SetCurSel(hwndCB, _dwSelectedItem);

			return ;
		}

		dwItem++;
	}
}

void DiskList::Add(_In_ HWND hwndCB, _In_ PCWSTR pszDeviceInterface)
{
	CDisk* pDisk;
	if (OnDiskArrival(&pDisk, pszDeviceInterface))
	{
		InsertTailList(this, pDisk);
		_dwSelectedItem = _cItems++;

		ComboBox_AddString(hwndCB, pDisk->_name);
		ComboBox_SetCurSel(hwndCB, _dwSelectedItem);
	}
}

void DiskList::OnInterfaceChange(_In_ HWND hwndCB, _In_ WPARAM wParam, _In_ PDEV_BROADCAST_DEVICEINTERFACE p)
{
	switch (wParam)
	{
	case DBT_DEVICEREMOVECOMPLETE:
	case DBT_DEVICEARRIVAL:
		break;
	default: return;
	}

	if (p->dbcc_devicetype == DBT_DEVTYP_DEVICEINTERFACE && p->dbcc_classguid == GUID_DEVINTERFACE_DISK)
	{
		switch (wParam)
		{
		case DBT_DEVICEREMOVECOMPLETE:
			Remove(hwndCB, p->dbcc_name);
			break;
		case DBT_DEVICEARRIVAL:
			Add(hwndCB, p->dbcc_name);
			break;
		}
	}
}

_NT_END