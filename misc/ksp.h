#pragma once

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptOpenStorageProviderFn)(
									   __out   NCRYPT_PROV_HANDLE *phProvider,
									   __in_opt LPCWSTR pszProviderName,
									   __in    DWORD   dwFlags);

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumAlgorithmsFn)(
								  __in    NCRYPT_PROV_HANDLE hProvider,
								  __in    DWORD   dwAlgClass,
								  __out   DWORD * pdwAlgCount,
								  __deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
								  __in    DWORD   dwFlags);

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptIsAlgSupportedFn)(
								  __in    NCRYPT_PROV_HANDLE hProvider,
								  __in    LPCWSTR pszAlgId,
								  __in    DWORD   dwFlags);

// @@END_DDKSPLIT



// NCryptEnumKeys flags
#define NCRYPT_MACHINE_KEY_FLAG         0x00000020

typedef struct NCryptKeyName
{
	LPWSTR  pszName;
	LPWSTR  pszAlgid;
	DWORD   dwLegacyKeySpec;
	DWORD   dwFlags;
} NCryptKeyName;


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumKeysFn)(
							__in    NCRYPT_PROV_HANDLE hProvider,
							__in_opt LPCWSTR pszScope,
							__deref_out NCryptKeyName **ppKeyName,
							__inout PVOID * ppEnumState,
							__in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEnumStorageProvidersFn)(
										__out   DWORD * pdwProviderCount,
										__deref_out_ecount(*pdwProviderCount) NCryptProviderName **ppProviderList,
										__in    DWORD   dwFlags);


typedef SECURITY_STATUS
(WINAPI * NCryptFreeBufferFn)(
							  __deref PVOID   pvInput);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptOpenKeyFn)(
						   __in    NCRYPT_PROV_HANDLE hProvider,
						   __out   NCRYPT_KEY_HANDLE *phKey,
						   __in    LPCWSTR pszKeyName,
						   __in_opt DWORD  dwLegacyKeySpec,
						   __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptCreatePersistedKeyFn)(
									  __in    NCRYPT_PROV_HANDLE hProvider,
									  __out   NCRYPT_KEY_HANDLE *phKey,
									  __in    LPCWSTR pszAlgId,
									  __in_opt LPCWSTR pszKeyName,
									  __in    DWORD   dwLegacyKeySpec,
									  __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptGetProviderPropertyFn)(
									   __in    NCRYPT_PROV_HANDLE hProvider,
									   __in    LPCWSTR pszProperty,
									   __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
									   __in    DWORD   cbOutput,
									   __out   DWORD * pcbResult,
									   __in    DWORD   dwFlags);

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptGetKeyPropertyFn)(
								  __in    NCRYPT_PROV_HANDLE hProvider,
								  __in    NCRYPT_KEY_HANDLE hKey,
								  __in    LPCWSTR pszProperty,
								  __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
								  __in    DWORD   cbOutput,
								  __out   DWORD * pcbResult,
								  __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSetProviderPropertyFn)(
									   __in    NCRYPT_PROV_HANDLE hProvider,
									   __in    LPCWSTR pszProperty,
									   __in_bcount(cbInput) PBYTE pbInput,
									   __in    DWORD   cbInput,
									   __in    DWORD   dwFlags);

typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSetKeyPropertyFn)(
								  __in    NCRYPT_PROV_HANDLE hProvider,
								  __in    NCRYPT_KEY_HANDLE hKey,
								  __in    LPCWSTR pszProperty,
								  __in_bcount(cbInput) PBYTE pbInput,
								  __in    DWORD   cbInput,
								  __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptFinalizeKeyFn)(
							   __in    NCRYPT_PROV_HANDLE hProvider,
							   __in    NCRYPT_KEY_HANDLE hKey,
							   __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptEncryptFn)(
						   __in    NCRYPT_PROV_HANDLE hProvider,
						   __in    NCRYPT_KEY_HANDLE hKey,
						   __in_bcount_opt(cbInput) PBYTE pbInput,
						   __in    DWORD   cbInput,
						   __in_opt    VOID *pPaddingInfo,
						   __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
						   __in    DWORD   cbOutput,
						   __out   DWORD * pcbResult,
						   __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptDecryptFn)(
						   __in    NCRYPT_PROV_HANDLE hProvider,
						   __in    NCRYPT_KEY_HANDLE hKey,
						   __in_bcount_opt(cbInput) PBYTE pbInput,
						   __in    DWORD   cbInput,
						   __in_opt    VOID *pPaddingInfo,
						   __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
						   __in    DWORD   cbOutput,
						   __out   DWORD * pcbResult,
						   __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptImportKeyFn)(
							 __in    NCRYPT_PROV_HANDLE hProvider,
							 __in_opt NCRYPT_KEY_HANDLE hImportKey,
							 __in    LPCWSTR pszBlobType,
							 __in_opt NCryptBufferDesc *pParameterList,
							 __out   NCRYPT_KEY_HANDLE *phKey,
							 __in_bcount(cbData) PBYTE pbData,
							 __in    DWORD   cbData,
							 __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptExportKeyFn)(
							 __in    NCRYPT_PROV_HANDLE hProvider,
							 __in    NCRYPT_KEY_HANDLE hKey,
							 __in_opt NCRYPT_KEY_HANDLE hExportKey,
							 __in    LPCWSTR pszBlobType,
							 __in_opt NCryptBufferDesc *pParameterList,
							 __out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
							 __in    DWORD   cbOutput,
							 __out   DWORD * pcbResult,
							 __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptSignHashFn)(
							__in    NCRYPT_PROV_HANDLE hProvider,
							__in    NCRYPT_KEY_HANDLE hKey,
							__in_opt    VOID *pPaddingInfo,
							__in_bcount(cbHashValue) PBYTE pbHashValue,
							__in    DWORD   cbHashValue,
							__out_bcount_part_opt(cbSignature, *pcbResult) PBYTE pbSignature,
							__in    DWORD   cbSignature,
							__out   DWORD * pcbResult,
							__in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptVerifySignatureFn)(
								   __in    NCRYPT_PROV_HANDLE hProvider,
								   __in    NCRYPT_KEY_HANDLE hKey,
								   __in_opt    VOID *pPaddingInfo,
								   __in_bcount(cbHashValue) PBYTE pbHashValue,
								   __in    DWORD   cbHashValue,
								   __in_bcount(cbSignature) PBYTE pbSignature,
								   __in    DWORD   cbSignature,
								   __in    DWORD   dwFlags);


typedef SECURITY_STATUS
(WINAPI * NCryptDeleteKeyFn)(
							 __in    NCRYPT_PROV_HANDLE hProvider,
							 __in    NCRYPT_KEY_HANDLE hKey,
							 __in    DWORD   dwFlags);


typedef SECURITY_STATUS
(WINAPI * NCryptFreeProviderFn)(
								__in    NCRYPT_PROV_HANDLE hProvider);

typedef SECURITY_STATUS
(WINAPI * NCryptFreeKeyFn)(
						   __in    NCRYPT_PROV_HANDLE hProvider,
						   __in    NCRYPT_KEY_HANDLE hKey);

typedef SECURITY_STATUS
(WINAPI * NCryptFreeSecretFn)(
							  __in    NCRYPT_PROV_HANDLE hProvider,
							  __in    NCRYPT_SECRET_HANDLE hSharedSecret);


typedef SECURITY_STATUS
(WINAPI * NCryptPromptUserFn)(
							  __in    NCRYPT_PROV_HANDLE hProvider,
							  __in_opt NCRYPT_KEY_HANDLE hKey,
							  __in    LPCWSTR pszOperation,
							  __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptNotifyChangeKeyFn)(
								   __in    NCRYPT_PROV_HANDLE hProvider,
								   __inout HANDLE *phEvent,
								   __in    DWORD   dwFlags);

__checkReturn
typedef SECURITY_STATUS
(WINAPI * NCryptSecretAgreementFn)(
								   __in    NCRYPT_PROV_HANDLE hProvider,
								   __in    NCRYPT_KEY_HANDLE hPrivKey,
								   __in    NCRYPT_KEY_HANDLE hPubKey,
								   __out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
								   __in    DWORD   dwFlags);


typedef __checkReturn SECURITY_STATUS
(WINAPI * NCryptDeriveKeyFn)(
							 __in        NCRYPT_PROV_HANDLE   hProvider,
							 __in        NCRYPT_SECRET_HANDLE hSharedSecret,
							 __in        LPCWSTR              pwszKDF,
							 __in_opt    NCryptBufferDesc     *pParameterList,
							 __out_bcount_part_opt(cbDerivedKey, *pcbResult) PBYTE pbDerivedKey,
							 __in        DWORD                cbDerivedKey,
							 __out       DWORD                *pcbResult,
							 __in        ULONG                dwFlags);


typedef struct _NCRYPT_KEY_STORAGE_FUNCTION_TABLE
{
	BCRYPT_INTERFACE_VERSION        Version;
	NCryptOpenStorageProviderFn     OpenProvider;
	NCryptOpenKeyFn                 OpenKey;
	NCryptCreatePersistedKeyFn      CreatePersistedKey;
	NCryptGetProviderPropertyFn     GetProviderProperty;
	NCryptGetKeyPropertyFn          GetKeyProperty;
	NCryptSetProviderPropertyFn     SetProviderProperty;
	NCryptSetKeyPropertyFn          SetKeyProperty;
	NCryptFinalizeKeyFn             FinalizeKey;
	NCryptDeleteKeyFn               DeleteKey;
	NCryptFreeProviderFn            FreeProvider;
	NCryptFreeKeyFn                 FreeKey;
	NCryptFreeBufferFn              FreeBuffer;
	NCryptEncryptFn                 Encrypt;
	NCryptDecryptFn                 Decrypt;
	NCryptIsAlgSupportedFn          IsAlgSupported;
	NCryptEnumAlgorithmsFn          EnumAlgorithms;
	NCryptEnumKeysFn                EnumKeys;
	NCryptImportKeyFn               ImportKey;
	NCryptExportKeyFn               ExportKey;
	NCryptSignHashFn                SignHash;
	NCryptVerifySignatureFn         VerifySignature;
	NCryptPromptUserFn              PromptUser;
	NCryptNotifyChangeKeyFn         NotifyChangeKey;
	NCryptSecretAgreementFn         SecretAgreement;
	NCryptDeriveKeyFn               DeriveKey;
	NCryptFreeSecretFn              FreeSecret;
} NCRYPT_KEY_STORAGE_FUNCTION_TABLE;


