//////////////////////////////////////////////////////////////////////////

class IRP_LIST : LIST_ENTRY 
{
	KSPIN_LOCK Lock;
	ULONG n;

	struct IRP_BLOCK : LIST_ENTRY 
	{
		PIRP Irp;
	};
public:
	IRP_LIST() : n(0)
	{
		KeInitializeSpinLock(&Lock);
		InitializeListHead(this);
	}

	~IRP_LIST()
	{
		if (!n)__debugbreak();
	}

	void InsertIrp(PIRP Irp)
	{
		if (IRP_BLOCK* p = (IRP_BLOCK*)ExAllocatePool(NonPagedPool, sizeof(IRP_BLOCK)))
		{
			p->Irp = Irp;
			KIRQL irql;
			KeAcquireSpinLock(&Lock, &irql);
			InsertHeadList(this, p);
			n++;
			KeReleaseSpinLock(&Lock, irql);
		}
	}

	void RemoveIrp(PIRP Irp)
	{
		PLIST_ENTRY head = this, entry = head;
		KIRQL irql;
		KeAcquireSpinLock(&Lock, &irql);
		while ((entry = entry->Flink) != head)
		{
			if (static_cast<IRP_BLOCK*>(entry)->Irp == Irp)
			{
				RemoveEntryList(entry);
				n--;
				break;
			}
		}
		KeReleaseSpinLock(&Lock, irql);

		if (entry == head)
		{
			__debugbreak();
		}

		ExFreePool(static_cast<IRP_BLOCK*>(entry));
	}

	ULONG getCount()
	{
		return n;
	}
};

//////////////////////////////////////////////////////////////////////////

