#include "stdafx.h"
#include "jni.h"

_NT_BEGIN

/*
 * Class:     Server
 * Method:    StopUdpServer
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_Server_StopUdpServer(JNIEnv *, jobject)
{
	if (IsDebuggerPresent()) __debugbreak();
}

jboolean DoCB(JNIEnv * env, jobject obj, jmethodID get_balance, jmethodID Allow)
{
	jboolean fOk = TRUE;

	env->CallIntMethod(obj, get_balance, 2000);

	if (jstring domain = env->NewStringUTF("rbmm.local"))
	{
		if (jstring user = env->NewStringUTF("admin"))
		{
			if (jstring workstation = env->NewStringUTF("tpm11"))
			{
				char sz[32];
				sprintf_s(sz, _countof(sz), "+%I64u", 380941234567);

				if (jstring phone = env->NewStringUTF(sz))
				{
					fOk = env->CallBooleanMethod(obj, Allow, domain, user, workstation, phone);

					env->DeleteLocalRef(phone);
				}
				env->DeleteLocalRef(workstation);
			}
			env->DeleteLocalRef(user);
		}

		env->DeleteLocalRef(domain);
	}

	return fOk;
}

struct JD 
{
	JavaVM *vm;
	jobject _M_obj = 0;
	jmethodID _M_get_balance;
	jmethodID _M_Allow;
	jshort port;
};

ULONG WINAPI SrvThread(JD* pj)
{
	MessageBoxW(0,0,0,0);
	if (IsDebuggerPresent()) __debugbreak();
	JNIEnv* env;
	JavaVM *vm = pj->vm;
	jobject obj = pj->_M_obj;

	if (!vm->AttachCurrentThread((void**)&env, 0))
	{
		DoCB(env, obj, pj->_M_get_balance, pj->_M_Allow);
		env->DeleteGlobalRef(obj);
		vm->DetachCurrentThread();
	}

	delete pj;

	return 0;
}

/*
* Class:     Server
* Method:    StartUdpServer
* Signature: (S)Z
 */
jboolean JNICALL Java_Server_StartUdpServer(JNIEnv * env, jobject obj, jshort port)
{
	if (IsDebuggerPresent()) __debugbreak();
	
	if (jclass cls = env->GetObjectClass(obj))
	{
		jmethodID m2 = env->GetMethodID(cls, "get_balance", "(I)I");
		jmethodID m1 = env->GetMethodID(cls, "Allow", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z");

		env->DeleteLocalRef(cls);

		if (m1 && m2)
		{
			if (JD* pj = new JD)
			{
				if (!env->GetJavaVM(&pj->vm))
				{
					pj->port = port;
					pj->_M_Allow = m1;
					pj->_M_get_balance = m2;

					if (pj->_M_obj = env->NewGlobalRef(obj))
					{
						if (HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SrvThread, pj, 0, 0))
						{
							NtClose(hThread);
							return true;
						}

						env->DeleteGlobalRef(pj->_M_obj);
					}
				}

				delete pj;
			}
		}
	}

	return false;
}

NTSTATUS ReadFromKey(_In_ HANDLE hKey, 
					 _In_ PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi,
					 _In_ ULONG cb,
					 _In_ PCWSTR fmt,
					 ...)
{
	va_list ap;
	va_start(ap, fmt);
	if (0 < _vsnwprintf_s((PWSTR)pkvpi, cb/sizeof(WCHAR), _TRUNCATE, fmt, ap))
	{
		UNICODE_STRING ValueName;
		RtlInitUnicodeString(&ValueName, (PWSTR)pkvpi);
		return ZwQueryValueKey(hKey, &ValueName, KeyValuePartialInformationAlign64, pkvpi, cb, &cb);
	}

	return STATUS_BUFFER_TOO_SMALL;
}

bool IsValid(_In_ BCRYPT_RSAKEY_BLOB* pbrb, _In_ ULONG cb)
{
	if (sizeof(BCRYPT_RSAKEY_BLOB) < cb)
	{
		switch (pbrb->Magic)
		{
		case BCRYPT_RSAPRIVATE_MAGIC:
			ULONG cbModulus = pbrb->cbModulus;
			return (cbModulus << 3) == pbrb->BitLength && 
				(ULONG64)cbModulus + pbrb->cbPublicExp + pbrb->cbPrime1 + pbrb->cbPrime2 + sizeof(BCRYPT_RSAKEY_BLOB) == cb;
		}
	}

	return false;
}

ULONG64 Crc64(_In_ BCRYPT_RSAKEY_BLOB* pbrb)
{
	return RtlCrc64(pbrb + 1, pbrb->cbModulus + pbrb->cbPublicExp, 0);
}

/*
 * Class:     Main
 * Method:    getKey
 * Signature: (I)Ljava/lang/String;
 */
jstring JNICALL Java_Main_getKey(JNIEnv *env, jclass, jint id)
{
	if (IsDebuggerPresent()) __debugbreak();

	STATIC_OBJECT_ATTRIBUTES(oa, "\\registry\\MACHINE\\SOFTWARE\\rbmm");

	HANDLE hKey;
	NTSTATUS status;

	if (0 <= (status = ZwCreateKey(&hKey, KEY_WRITE|KEY_READ, &oa, 0, 0, 0, 0)))
	{
		// id -> crc64 (REG_QWORD)
		// crc64 -> rsa2 (REG_BINARY)

		union {
			ULONG64 a;
			KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 kvpi;
			UCHAR bb[0x230];
		};

		BCRYPT_RSAKEY_BLOB* pbrb = 0;

		if (0 <= ReadFromKey(hKey, &kvpi, sizeof(bb), L"%08x", id))
		{
			if (REG_QWORD == kvpi.Type && sizeof(ULONG64) == kvpi.DataLength)
			{
				if (0 <= ReadFromKey(hKey, &kvpi, sizeof(bb), L"%016I64x", *(ULONG64*)kvpi.Data))
				{
					if ((ULONG)id == kvpi.Type && IsValid((BCRYPT_RSAKEY_BLOB*)kvpi.Data, kvpi.DataLength))
					{
						pbrb = (BCRYPT_RSAKEY_BLOB*)kvpi.Data;
					}
				}
			}
		}

		ULONG64 crc;

		if (!pbrb)
		{
			BCRYPT_ALG_HANDLE hAlgorithm;
			if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_RSA_ALGORITHM, 0, 0)))
			{
				BCRYPT_KEY_HANDLE hBKey;
				status = BCryptGenerateKeyPair(hAlgorithm, &hBKey, 2048, 0);
				BCryptCloseAlgorithmProvider(hAlgorithm, 0);

				if (0 <= status)
				{
					if (0 <= (status = BCryptFinalizeKeyPair(hBKey, 0)))
					{
						union {
							PVOID pv;
							PBYTE pb = 0;
						};
						ULONG cb = 0;
						if (0 <= (status = BCryptExportKey(hBKey, 0, BCRYPT_RSAPRIVATE_BLOB, bb, sizeof(bb), &cb, 0)))
						{
							WCHAR sz[32];
							UNICODE_STRING ValueName;
							swprintf_s(sz, _countof(sz), L"%016I64x", crc = Crc64((BCRYPT_RSAKEY_BLOB*)bb));
							RtlInitUnicodeString(&ValueName, sz);

							if (0 <= (status = ZwSetValueKey(hKey, &ValueName, 0, id, bb, cb)))
							{
								swprintf_s(sz, _countof(sz), L"%08x", id);
								RtlInitUnicodeString(&ValueName, sz);

								if (0 <= (status = ZwSetValueKey(hKey, &ValueName, 0, REG_QWORD, &crc, sizeof(crc))))
								{
									pbrb = (BCRYPT_RSAKEY_BLOB*)bb;
								}
							}
						}
					}
					BCryptDestroyKey(hBKey);
				}
			}
		}

		NtClose(hKey);

		if (pbrb)
		{
			ULONG cb = sizeof(BCRYPT_RSAKEY_BLOB) + pbrb->cbModulus + pbrb->cbPublicExp;
			*(ULONG64*)&pbrb->cbPrime1 = crc = Crc64(pbrb);
			pbrb->Magic = BCRYPT_RSAPUBLIC_MAGIC;

			PSTR psz = 0;
			ULONG cch = 0;
			while(CryptBinaryToStringA((PBYTE)pbrb, cb, CRYPT_STRING_BASE64, psz, &cch))
			{
				if (psz)
				{
					return env->NewStringUTF(psz);
				}

				psz = (PSTR)alloca(cch);
			}
		}
	}

	return env->NewStringUTF("");
}

_NT_END