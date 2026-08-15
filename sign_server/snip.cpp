void ecty()
{
  BCRYPT_KEY_HANDLE hKey;
  if (0 <= BCryptGenerateKeyPair(BCRYPT_ECDSA_P521_ALG_HANDLE, &hKey, 0, 0))
  {
    if (0 <= BCryptFinalizeKeyPair(hKey, 0))
    {
      UCHAR buf[0x100];
      ULONG cb, len;
      BCryptGetProperty(hKey, BCRYPT_KEY_LENGTH, (PBYTE)&len, sizeof(len), &cb, 0);
      BCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, buf, sizeof(buf), &cb, 0);
      PCERT_PUBLIC_KEY_INFO pInfo = 0;
      ULONG cbInfo = 0;

      while (CryptExportPublicKeyInfoFromBCryptKeyHandle(hKey, X509_ASN_ENCODING, 0, 0, 0, pInfo, &cbInfo))
      {
        if (pInfo)
        {
          if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, 
            pInfo->Algorithm.pszObjId, CRYPT_OID_PREFER_CNG_ALGID_FLAG))
          {

            __nop();
          }
          if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, 
            (void*)szOID_ECDSA_SPECIFIED, CRYPT_OID_PREFER_CNG_ALGID_FLAG))
          {

            __nop();
          }
          TestDecode(pInfo->PublicKey.pbData, pInfo->PublicKey.cbData);
          break;
        }

        pInfo = (PCERT_PUBLIC_KEY_INFO)alloca(cbInfo);
      }
    }
    BCryptDestroyKey(hKey);
  }
}

void tty(PCERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo, BOOL f)
{
  if (!strcmp(szOID_ECC_PUBLIC_KEY, SubjectPublicKeyInfo->Algorithm.pszObjId))
  {
    PSTR* pcstr;
    if (0 <= Decode(X509_OBJECT_IDENTIFIER, &SubjectPublicKeyInfo->Algorithm.Parameters, &pcstr))
    {
      if (PCCRYPT_OID_INFO pcoi = CryptFindOIDInfo(CRYPT_OID_INFO_OID_KEY, *pcstr, 0))
      {
        DbgPrint("%ws(%hs) [%ws, %ws]\r\n", pcoi->pwszName, pcoi->pszOID, pcoi->pwszCNGAlgid, pcoi->pwszCNGExtraAlgid);
      }
      LocalFree(pcstr);
    }

    BCRYPT_KEY_HANDLE hDsaKey, hDhKey;

    if (CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, 
      SubjectPublicKeyInfo, CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG, 0, &hDsaKey))
    {
      PBYTE pb = 0;
      ULONG cb = 0;
      while (0 <= BCryptExportKey(hDsaKey, 0, BCRYPT_PUBLIC_KEY_BLOB, pb, cb, &cb, 0))
      {
        if (pb)
        {
          if (f)
          {
            reinterpret_cast<PBCRYPT_ECCKEY_BLOB>(pb)->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
            if (0 <= BCryptImportKeyPair(BCRYPT_ECDH_P256_ALG_HANDLE, 0, BCRYPT_PUBLIC_KEY_BLOB, &hDhKey, pb, cb, 0))
            {
              SubjectPublicKeyInfo = 0, cb = 0;

              NTSTATUS status;
              while (HR(status, CryptExportPublicKeyInfoFromBCryptKeyHandle(hDhKey, X509_ASN_ENCODING, 
                0, 0, 0, SubjectPublicKeyInfo, &cb)))
              {
                if (SubjectPublicKeyInfo)
                {
                  break;
                }

                SubjectPublicKeyInfo = (PCERT_PUBLIC_KEY_INFO)alloca(cb);
              }

              BCryptDestroyKey(hDhKey);

              if (0 <= status)
              {
                tty(SubjectPublicKeyInfo, FALSE);
              }
            }
          }
          break;
        }

        pb = (PBYTE)alloca(cb);
      }
      BCryptDestroyKey(hDsaKey);
    }
  }
}

void tesr(PCWSTR pszFileName)
{
  PBYTE pb;
  ULONG cb;
  if (!ReadFromFile(pszFileName, &pb, &cb))
  {
    PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pb, cb);
    LocalFree(pb);
    if (pCertContext)
    {
      tty(&pCertContext->pCertInfo->SubjectPublicKeyInfo, TRUE);
      CertFreeCertificateContext(pCertContext);
    }
  }
}

void st()
{
	HRESULT hr;
	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
		CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG|CERT_SYSTEM_STORE_CURRENT_USER, L"My")))
	{
		ULONG cb;
		PCRYPT_KEY_PROV_INFO pkpi = (PCRYPT_KEY_PROV_INFO)alloca(0x400);
		PCCERT_CONTEXT pCertContext = 0;
		while (pCertContext = HR(hr, CertEnumCertificatesInStore(hCertStore, pCertContext)))
		{
			DumpName(&pCertContext->pCertInfo->Subject, L"SN:\r\n");
			if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pkpi, &(cb = 0x400)))
			{
				DbgPrint("%x-%x-%x %ws\\%ws\r\n", pkpi->dwProvType, pkpi->dwKeySpec, pkpi->dwFlags,
					pkpi->pwszProvName, pkpi->pwszContainerName);
			}
			else
			{
				__debugbreak();
			}
		}

		CertCloseStore(hCertStore, 0);
	}

}
  //tesr(L"c:/dbg/ha.cer");
  //tesr(L"c:/users/harry/downloads/learn.microsoft.der");
  //tesr(L"c:/users/harry/downloads/wr2.der");
  //ecty();
  //PBYTE pbPKCS;
  //ULONG cbPKCS;
  //if (!ReadFromFile(L"O:\\vc\\x64\\user.cr", &pbPKCS, &cbPKCS))
  //{
  //  Verify_PKCS_10(pbPKCS, cbPKCS);
  //  LocalFree(pbPKCS);
  //}
struct XT2
{
	ULONG64 ticks;
	ULONG64 time;
	ULONG n;
};
VOID WINAPI TimerCB( _In_opt_ XT2* p,
					_In_     DWORD dwTimerLowValue,
					_In_     DWORD dwTimerHighValue)
{
	ULONG64 ticks = GetTickCount64();
	LARGE_INTEGER time = { dwTimerLowValue, dwTimerHighValue };
	DbgPrint("%02u: %I64u %I64u\r\n", p->n--, time.QuadPart - p->time, ticks - p->ticks);
	p->ticks = ticks;
	p->time = time.QuadPart;
}

void tp(_In_ LONG lPeriod = 128)
{
	//, TIMER_ALL_ACCESS
	if (HANDLE hTimer = CreateWaitableTimerExW(0, 0, 0, TIMER_ALL_ACCESS))
	{
		::LARGE_INTEGER dueTime;
		dueTime.QuadPart = -10000000; // 1 secondEx

		XT2 x = { GetTickCount64(), 0, 64 };
		GetSystemTimeAsFileTime((LPFILETIME)&x.time);
		if (SetWaitableTimer(hTimer, &dueTime, lPeriod, (PTIMERAPCROUTINE)TimerCB, &x, 0))
		{
			while (WAIT_IO_COMPLETION == SleepEx(INFINITE, TRUE) && x.n)
			{
			}

		}
		GetLastHresult();
		NtClose(hTimer);
	}
}

void test_sa_h(_In_ BOOL bSign)
{
	DbgPrint("\f----- %ws -----\r\n", bSign ? L"SIGN" : L"ENCRYPT");
	static const PCWSTR sh[] = { L"SA", L"H" };
	static const ULONG m2[] = { 'S' << 16, 'K' << 16 };
	static const UINT Pn[] = { 256, 384, 521 };
	BCRYPT_KEY_BLOB bkb;
	int s = _countof(sh);
	do 
	{
		PCWSTR pcsz = sh[--s];
		ULONG x2 = m2[s];
		int i = _countof(Pn);
		do 
		{
			WCHAR szAlgId[16];

			bkb.Magic = 'CE' | x2 | (('0' + 2*i) << 24);
			swprintf_s(szAlgId, _countof(szAlgId), L"ECD%ws_P%u", pcsz, Pn[--i]);

			int k = 2;
			do 
			{
				DbgPrint("\f%.4hs %ws -> ", &bkb.Magic, szAlgId);
				DbgPrint("\f%.4hs %ws\r\n", &bkb.Magic, FixAlgName(szAlgId, &bkb, bSign));
				bkb.Magic -= 0x01000000;
			} while (--k);
		} while (i);
	} while (s);
}

void SetPrivKey(PCWSTR szHash)
{
	HRESULT hr;

	UCHAR hash[SHA1_DIGEST_SIZE];
	DATA_BLOB db = { sizeof(hash), hash };

	if (HR(hr, CryptStringToBinaryW(szHash, 0, CRYPT_STRING_HEXRAW, hash, &db.cbData, 0, 0)))
	{
		if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
			CERT_STORE_OPEN_EXISTING_FLAG|CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT")))
		{
			if (PCCERT_CONTEXT pCertContext = HR(hr, CertFindCertificateInStore(
				hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_HASH, &db, 0)))
			{
				CRYPT_KEY_PROV_INFO ckpi = { 
					(PWSTR)L"RBMM-CA", (PWSTR)MS_KEY_STORAGE_PROVIDER, 0, NCRYPT_MACHINE_KEY_FLAG
				};

				CertSetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, 0, &ckpi);
				CertFreeCertificateContext(pCertContext);
			}

			CertCloseStore(hCertStore, 0);
		}
	}

}
struct PCTX : IO_STATUS_BLOCK 
{
	HANDLE hFile;
	PCSTR name;
	enum OP { op_read='rrrr', op_write='wwww' } op;
	char buf[0x100];

	PCTX(HANDLE hFile, OP op, PCSTR name) : hFile(hFile), op(op), name(name) {
		Status = STATUS_PENDING, Information = 0;
	}
};

void ReadFromPipe(HANDLE hPipe, PCTX* ctx);

VOID NTAPI OnApc (
				  _In_ PCTX* ApcContext,
				  _In_ PIO_STATUS_BLOCK IoStatusBlock,
				  _In_ ULONG /*Reserved*/
				  )
{
	DbgPrint("OnApc<%hs>(%.4hs %x %x \"%hs\")\r\n", 
		ApcContext->name, &ApcContext->op, IoStatusBlock->Status, IoStatusBlock->Information, ApcContext->buf);

	switch (ApcContext->op)
	{
	case PCTX::op_read:
		if (0 <= IoStatusBlock->Status)
		{
			ReadFromPipe(ApcContext->hFile, ApcContext);
			return ;
		}
		break;
	}
	delete ApcContext;
}

void WriteToPipe(PCSTR name, HANDLE hPipe, PCSTR fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (PCTX* ctx = new PCTX(hPipe, PCTX::op_write, name))
	{
		NTSTATUS status = STATUS_BUFFER_OVERFLOW;
		if (int len = _vsnprintf_s(ctx->buf, _countof(ctx->buf), _TRUNCATE, fmt, ap))
		{
			if (0 <= (status = NtWriteFile(hPipe, 0, (PIO_APC_ROUTINE)OnApc, ctx, ctx, ctx->buf, 1 + len, 0, 0)))
			{
				return ;
			}
		}
		ctx->Status = status;
		OnApc(ctx, ctx, 0);
	}
}

void ReadFromPipe(HANDLE hPipe, PCTX* ctx)
{
	NTSTATUS status;
	if (0 <= (status = NtReadFile(hPipe, 0, (PIO_APC_ROUTINE)OnApc, ctx, ctx, ctx->buf, sizeof(ctx->buf), 0, 0)))
	{
		return ;
	}
	ctx->Status = status;
	OnApc(ctx, ctx, 0);
}

void ReadFromPipe(PCSTR name, HANDLE hPipe)
{
	if (PCTX* ctx = new PCTX(hPipe, PCTX::op_read, name))
	{
		ReadFromPipe(hPipe, ctx);
	}
}

void TestP1()
{
	HANDLE hServerPipe, hClientPipe;

	if (0 <= CreatePipeAnonymousPair(&hServerPipe, &hClientPipe, FLAG_PIPE_SERVER_MESSAGE_MODE|FLAG_PIPE_CLIENT_MESSAGE_MODE))
	{
		WriteToPipe("server", hServerPipe, "%u %hs", 2, "sss");
		WriteToPipe("server", hServerPipe, "%u %hs", 1, "sss");
		WriteToPipe("client", hClientPipe, "%u %hs", 2, "ccc");
		WriteToPipe("client", hClientPipe, "%u %hs", 1, "ccc");

		ReadFromPipe("client", hClientPipe);
		ReadFromPipe("server", hServerPipe);
		LARGE_INTEGER li = {0, MINLONG};
		do 
		{
		} while (STATUS_USER_APC == ZwDelayExecution(TRUE, &li));
		NtClose(hClientPipe);
		NtClose(hServerPipe);
	}
}

#include "../asio/pipe.h"

class CTS : public CPipeEnd
{
	PCSTR m_name;
	ULONG m_nMsg = 2;
	BOOL m_bSrv;

	void SendMsg()
	{
		if (!m_nMsg)
		{
			return ;
		}

		--m_nMsg;

		if (CDataPacket* packet = new(0x100) CDataPacket)
		{
			PSTR buf = packet->getData();
			if (int len = sprintf_s(buf, 0x100, "%u %hs", m_nMsg, m_name))
			{
				packet->setDataSize(len + 1);
				Write(packet);
			}
			packet->Release();
		}
	}

	virtual BOOL UseApcCompletion()
	{
		return FALSE;
	}

	virtual BOOL IsServer()
	{
		return m_bSrv;
	}

	virtual BOOL OnRead(PVOID Buffer, ULONG cbTransferred)
	{
		DbgPrint("%hs<%hs>(%x \"%hs\")\r\n", __FUNCTION__, m_name, cbTransferred, Buffer);
		SendMsg();
		return true;
	}

	virtual BOOL OnConnect(NTSTATUS status)
	{
		DbgPrint("%hs<%hs>(%x)\r\n", __FUNCTION__, m_name, status);
		if (0 <= status)
		{
			SendMsg();
			return TRUE;
		}
		return FALSE;
	}

	virtual void OnDisconnect()
	{
		DbgPrint("%hs<%hs>\r\n", __FUNCTION__, m_name);
	}
	~CTS()
	{
		DbgPrint("%hs<%hs>\r\n", __FUNCTION__, m_name);
	}
public:
	CTS(PCSTR name, BOOL bSrv) : m_name(name), m_bSrv(bSrv)
	{
		DbgPrint("%hs<%hs>\r\n", __FUNCTION__, m_name);
	}
};

void TestP1()
{
	initterm();
	STATIC_OBJECT_ATTRIBUTES(oa, "\\device\\namedpipe\\mp");
	if (CTS* s = new CTS("server", TRUE))
	{
		if (0 <= s->SetBuffer(0x100) && 
			0 <= s->Create(&oa, 0, PIPE_UNLIMITED_INSTANCES, FILE_PIPE_MESSAGE_TYPE))
		{
			if (CTS* c = new CTS("client", FALSE))
			{
				if (0 <= c->SetBuffer(0x100) && 
					0 <= c->Create(&oa, 0, PIPE_UNLIMITED_INSTANCES, FILE_PIPE_MESSAGE_TYPE))
				{
					Sleep(4000);
					//LARGE_INTEGER li = {0, MINLONG};
					//do 
					//{
					//} while (STATUS_USER_APC == ZwDelayExecution(TRUE, &li));
				}
				c->Close();
				c->Release();
			}
		}
		s->Close();
		s->Release();
	}
	ZwTestAlert();
	destroyterm();
	Sleep(1000);
}