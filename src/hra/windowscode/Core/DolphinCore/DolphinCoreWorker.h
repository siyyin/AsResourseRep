#pragma once
#include <windows.h>
#include <ntstatus.h>
#include <sddl.h>
#include <userenv.h>
#include <NTSecAPI.h>
#include <Shlwapi.h>
#include "DolphinCoreDef.h"
#include "DolphinCoreWorkerWinApi.h"
#include "ap_md5.h"

#define	SYSKEY_LENGTH               16
#define	SAM_KEY_DATA_SALT_LENGTH    16
#define	SAM_KEY_DATA_KEY_LENGTH     16

#define LAZY_IV_SIZE                16

#define AES_BLOCK_SIZE              16

#define AI_S_WPREG_HIVE_KEY_NAMED_FLAG_VOLATILE     0x0001
#define AI_S_WPREG_HIVE_KEY_NAMED_FLAG_MOUNT_POINT  0x0002
#define AI_S_WPREG_HIVE_KEY_NAMED_FLAG_ROOT         0x0004
#define AI_S_WPREG_HIVE_KEY_NAMED_FLAG_LOCKED       0x0008
#define AI_S_WPREG_HIVE_KEY_NAMED_FLAG_SYMLINK      0x0010
#define AI_S_WPREG_HIVE_KEY_NAMED_FLAG_ASCII_NAME   0x0020

#define AI_S_WPREG_HIVE_VALUE_KEY_FLAG_ASCII_NAME   0x0001

#if !defined(NT_SUCCESS)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef struct _AI_S_WPREG_HIVE_HEADER
{
    DWORD tag;
    DWORD seqPri;
    DWORD seqSec;
    FILETIME lastModification;
    DWORD versionMajor;
    DWORD versionMinor;
    DWORD fileType;
    DWORD unk0;
    LONG offsetRootKey;
    DWORD szData;
    DWORD unk1;
    BYTE unk2[64];
    BYTE unk3[396];
    DWORD checksum;
    BYTE padding[3584];
} AI_S_WPREG_HIVE_HEADER, * PAI_S_WPREG_HIVE_HEADER;

typedef struct _AI_S_WPREG_HIVE_BIN_HEADER
{
    DWORD tag;
    LONG offsetHiveBin;
    DWORD szHiveBin;
    DWORD unk0;
    DWORD unk1;
    FILETIME timestamp;
    DWORD unk2;
} AI_S_WPREG_HIVE_BIN_HEADER, * PAI_S_WPREG_HIVE_BIN_HEADER;


typedef struct _AI_S_WPREG_HIVE_BIN_CELL
{
    LONG szCell;
    union
    {
        WORD tag;
        BYTE data[ANYSIZE_ARRAY];
    };
} AI_S_WPREG_HIVE_BIN_CELL, * PAI_S_WPREG_HIVE_BIN_CELL;

typedef struct _AI_S_WPREG_HIVE_KEY_NAMED
{
    LONG szCell;
    WORD tag;
    WORD flags;
    FILETIME lastModification;
    DWORD unk0;
    LONG offsetParentKey;
    DWORD nbSubKeys;
    DWORD nbVolatileSubKeys;
    LONG offsetSubKeys;
    LONG offsetVolatileSubkeys;
    DWORD nbValues;
    LONG offsetValues;
    LONG offsetSecurityKey;
    LONG offsetClassName;
    DWORD szMaxSubKeyName;
    DWORD szMaxSubKeyClassName;
    DWORD szMaxValueName;
    DWORD szMaxValueData;
    DWORD unk1;
    WORD szKeyName;
    WORD szClassName;
    BYTE keyName[ANYSIZE_ARRAY];
} AI_S_WPREG_HIVE_KEY_NAMED, * PAI_S_WPREG_HIVE_KEY_NAMED;

typedef enum _AI_S_WPREG_TYPE
{
    AI_S_WPREG_TYPE_OWN,
    AI_S_WPREG_TYPE_HIVE,
} AI_S_WPREG_TYPE;


typedef struct _AI_S_WPREG_HIVE_HANDLE
{
    HANDLE hFileMapping;
    LPVOID pMapViewOfFile;
    PBYTE pStartOf;
    PAI_S_WPREG_HIVE_KEY_NAMED pRootNamedKey;
} AI_S_WPREG_HIVE_HANDLE, * PAI_S_WPREG_HIVE_HANDLE;

typedef struct _AI_S_WPREG_HANDLE
{
    AI_S_WPREG_TYPE type;
    union
    {
        PAI_S_WPREG_HIVE_HANDLE pHandleHive;
    };
} AI_S_WPREG_HANDLE, * PAI_S_WPREG_HANDLE;

typedef struct _SAM_ENTRY
{
    DWORD offset;
    DWORD lenght;
    DWORD unk;
} SAM_ENTRY, * PSAM_SENTRY;

typedef struct _USER_ACCOUNT_V
{
    SAM_ENTRY unk0_header;
    SAM_ENTRY Username;
    SAM_ENTRY Fullname;
    SAM_ENTRY Comment;
    SAM_ENTRY UserComment;
    SAM_ENTRY unk1;
    SAM_ENTRY Homedir;
    SAM_ENTRY HomedirConnect;
    SAM_ENTRY ScriptPath;
    SAM_ENTRY ProfilePath;
    SAM_ENTRY Workstations;
    SAM_ENTRY HoursAllowed;
    SAM_ENTRY unk2;
    SAM_ENTRY LMHash;
    SAM_ENTRY NTLMHash;
    SAM_ENTRY NTLMHistory;
    SAM_ENTRY LMHistory;
    BYTE datas[ANYSIZE_ARRAY];
} USER_ACCOUNT_V, * PUSER_ACCOUNT_V;

typedef struct _AI_S_WPREG_HIVE_LF_LH_ELEMENT
{
    LONG offsetNamedKey;
    DWORD hash;
} AI_S_WPREG_HIVE_LF_LH_ELEMENT, * PAI_S_WPREG_HIVE_LF_LH_ELEMENT;

typedef struct _AI_S_WPREG_HIVE_LF_LH
{
    LONG szCell;
    WORD tag;
    WORD nbElements;
    AI_S_WPREG_HIVE_LF_LH_ELEMENT elements[ANYSIZE_ARRAY];
} AI_S_WPREG_HIVE_LF_LH, * PAI_S_WPREG_HIVE_LF_LH;

typedef struct _AI_S_WPREG_HIVE_VALUE_KEY
{
    LONG szCell;
    WORD tag;
    WORD szValueName;
    DWORD szData;
    LONG offsetData;
    DWORD typeData;
    WORD flags;
    WORD __align;
    BYTE valueName[ANYSIZE_ARRAY];
} AI_S_WPREG_HIVE_VALUE_KEY, * PAI_S_WPREG_HIVE_VALUE_KEY;

typedef struct _OLD_LARGE_INTEGER
{
    ULONG LowPart;
    LONG HighPart;
} OLD_LARGE_INTEGER, * POLD_LARGE_INTEGER;

typedef  enum _DOMAIN_SERVER_ROLE
{
    DomainServerRoleBackup = 2,
    DomainServerRolePrimary = 3
} DOMAIN_SERVER_ROLE, * PDOMAIN_SERVER_ROLE;

typedef  enum _DOMAIN_SERVER_ENABLE_STATE
{
    DomainServerEnabled = 1,
    DomainServerDisabled
} DOMAIN_SERVER_ENABLE_STATE, * PDOMAIN_SERVER_ENABLE_STATE;

typedef struct _SAM_KEY_DATA
{
    DWORD Revision;
    DWORD Length;
    BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
    BYTE Key[SAM_KEY_DATA_KEY_LENGTH];
    BYTE CheckSum[MD5_DIGEST_LENGTH];
    DWORD unk0;
    DWORD unk1;
} SAM_KEY_DATA, * PSAM_KEY_DATA;

typedef struct _DOMAIN_ACCOUNT_F
{
    WORD Revision;
    WORD unk0;
    DWORD unk1;
    OLD_LARGE_INTEGER CreationTime;
    OLD_LARGE_INTEGER DomainModifiedCount;
    OLD_LARGE_INTEGER MaxPasswordAge;
    OLD_LARGE_INTEGER MinPasswordAge;
    OLD_LARGE_INTEGER ForceLogoff;
    OLD_LARGE_INTEGER LockoutDuration;
    OLD_LARGE_INTEGER LockoutObservationWindow;
    OLD_LARGE_INTEGER ModifiedCountAtLastPromotion;
    DWORD NextRid;
    DWORD PasswordProperties;
    WORD MinPasswordLength;
    WORD PasswordHistoryLength;
    WORD LockoutThreshold;
    DOMAIN_SERVER_ENABLE_STATE ServerState;
    DOMAIN_SERVER_ROLE ServerRole;
    BOOL UasCompatibilityRequired;
    DWORD unk2;
    SAM_KEY_DATA keys1;
    SAM_KEY_DATA keys2;
    DWORD unk3;
    DWORD unk4;
} DOMAIN_ACCOUNT_F, * PDOMAIN_ACCOUNT_F;

typedef struct _SAM_KEY_DATA_AES
{
    DWORD Revision; // 2
    DWORD Length;
    DWORD CheckLen;
    DWORD DataLen;
    BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
    BYTE data[ANYSIZE_ARRAY]; // Data, then Check
} SAM_KEY_DATA_AES, * PSAM_KEY_DATA_AES;

typedef struct _SAM_HASH
{
    WORD PEKID;
    WORD Revision;
    BYTE data[ANYSIZE_ARRAY];
} SAM_HASH, * PSAM_HASH;

typedef struct _SAM_HASH_AES
{
    WORD PEKID;
    WORD Revision;
    DWORD dataOffset;
    BYTE Salt[SAM_KEY_DATA_SALT_LENGTH];
    BYTE data[ANYSIZE_ARRAY]; // Data
} SAM_HASH_AES, * PSAM_HASH_AES;

typedef struct _KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS
{
    DWORD unk0;
    DWORD unkSize;
    DWORD unk1; // flags ?
    DWORD originalSize;
    BYTE iv[LAZY_IV_SIZE];
    BYTE encrypted[ANYSIZE_ARRAY];
} KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS, * PKIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS;


typedef struct _AI_S_WPREG_HIVE_VALUE_LIST
{
    LONG szCell;
    LONG offsetValue[ANYSIZE_ARRAY];
} AI_S_WPREG_HIVE_VALUE_LIST, * PAI_S_WPREG_HIVE_VALUE_LIST;

typedef struct _WDIGEST_CREDENTIALS
{
    BYTE	Reserverd1;
    BYTE	Reserverd2;
    BYTE	Version;
    BYTE	NumberOfHashes;
    BYTE	Reserverd3[12];
    BYTE	Hash[ANYSIZE_ARRAY][MD5_DIGEST_LENGTH];
} WDIGEST_CREDENTIALS, * PWDIGEST_CREDENTIALS;

typedef struct _KERB_STORED_CREDENTIAL
{
    USHORT	Revision;
    USHORT	Flags;
    USHORT	CredentialCount;
    USHORT	OldCredentialCount;
    USHORT	DefaultSaltLength;
    USHORT	DefaultSaltMaximumLength;
    ULONG	DefaultSaltOffset;
    //KERB_KEY_DATA	Credentials[ANYSIZE_ARRAY];
    //KERB_KEY_DATA	OldCredentials[ANYSIZE_ARRAY];
    //BYTE	DefaultSalt[ANYSIZE_ARRAY];
    //BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL, * PKERB_STORED_CREDENTIAL;

typedef struct _KERB_KEY_DATA
{
    USHORT	Reserverd1;
    USHORT	Reserverd2;
    ULONG	Reserverd3;
    LONG	KeyType;
    ULONG	KeyLength;
    ULONG	KeyOffset;
} KERB_KEY_DATA, * PKERB_KEY_DATA;

typedef struct _KERB_STORED_CREDENTIAL_NEW
{
    USHORT	Revision;
    USHORT	Flags;
    USHORT	CredentialCount;
    USHORT	ServiceCredentialCount;
    USHORT	OldCredentialCount;
    USHORT	OlderCredentialCount;
    USHORT	DefaultSaltLength;
    USHORT	DefaultSaltMaximumLength;
    ULONG	DefaultSaltOffset;
    ULONG	DefaultIterationCount;
    //KERB_KEY_DATA_NEW	Credentials[ANYSIZE_ARRAY];
    //KERB_KEY_DATA_NEW	ServiceCredentials[ANYSIZE_ARRAY];
    //KERB_KEY_DATA_NEW	OldCredentials[ANYSIZE_ARRAY];
    //KERB_KEY_DATA_NEW	OlderCredentials[ANYSIZE_ARRAY];
    //BYTE	DefaultSalt[ANYSIZE_ARRAY];
    //BYTE	KeyValues[ANYSIZE_ARRAY];
} KERB_STORED_CREDENTIAL_NEW, * PKERB_STORED_CREDENTIAL_NEW;

typedef struct _KERB_KEY_DATA_NEW
{
    USHORT	Reserverd1;
    USHORT	Reserverd2;
    ULONG	Reserverd3;
    ULONG	IterationCount;
    LONG	KeyType;
    ULONG	KeyLength;
    ULONG	KeyOffset;
} KERB_KEY_DATA_NEW, * PKERB_KEY_DATA_NEW;

typedef struct _GENERICKEY_BLOB
{
    BLOBHEADER Header;
    DWORD dwKeyLen;
} GENERICKEY_BLOB, * PGENERICKEY_BLOB;

#pragma pack(push, 1) 
typedef struct _USER_PROPERTY
{
    USHORT NameLength;
    USHORT ValueLength;
    USHORT Reserved;
    wchar_t PropertyName[ANYSIZE_ARRAY];
    // PropertyValue in HEX !
} USER_PROPERTY, * PUSER_PROPERTY;

typedef struct _USER_PROPERTIES
{
    DWORD Reserved1;
    DWORD Length;
    USHORT Reserved2;
    USHORT Reserved3;
    BYTE Reserved4[96];
    wchar_t PropertySignature;
    USHORT PropertyCount;
    USER_PROPERTY UserProperties[ANYSIZE_ARRAY];
} USER_PROPERTIES, * PUSER_PROPERTIES;
#pragma pack(pop)

//int ai_s_wpdump_init();
//void ai_s_wpdump_uninit();
int ai_s_wpdump_sam(LPCWSTR szSystemFile, LPCWSTR szSamFile);
BOOL ai_s_wpreg_open(IN AI_S_WPREG_TYPE Type, IN HANDLE hAny, BOOL isWrite, OUT PAI_S_WPREG_HANDLE* hRegistry);
PAI_S_WPREG_HANDLE ai_s_wpreg_close(IN PAI_S_WPREG_HANDLE hRegistry);
BOOL ai_s_wpreg_RegOpenKeyEx(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN DWORD ulOptions, IN REGSAM samDesired, OUT PHKEY phkResult);
BOOL ai_s_wpreg_RegCloseKey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey);

BOOL ai_s_wpdump_getComputerAndSyskey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey);
BOOL ai_s_wpdump_getUsersAndSamKey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hSAMBase, IN LPCBYTE sysKey);
PAI_S_WPREG_HIVE_KEY_NAMED ai_s_wpreg_searchKeyNamedInList(IN PAI_S_WPREG_HANDLE hRegistry, IN PAI_S_WPREG_HIVE_BIN_CELL pHbC, IN LPCWSTR lpSubKey);
BOOL ai_s_wpdump_getCurrentControlSet(PAI_S_WPREG_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet);
BOOL ai_s_wpreg_OpenAndQueryWithAlloc(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN OPTIONAL LPCWSTR lpValueName, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPVOID* lpData, IN OUT OPTIONAL LPDWORD lpcbData);
BOOL ai_s_wpdump_getSyskey(PAI_S_WPREG_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey);
BOOL ai_s_wpdump_getSamKey(PAI_S_WPREG_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey);
BOOL ai_s_wpreg_RegQueryInfoKey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, IN OPTIONAL LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpcSubKeys, OUT OPTIONAL LPDWORD lpcMaxSubKeyLen, OUT OPTIONAL LPDWORD lpcMaxClassLen, OUT OPTIONAL LPDWORD lpcValues, OUT OPTIONAL LPDWORD lpcMaxValueNameLen, OUT OPTIONAL LPDWORD lpcMaxValueLen, OUT OPTIONAL LPDWORD lpcbSecurityDescriptor, OUT OPTIONAL PFILETIME lpftLastWriteTime);
BOOL ai_s_wpreg_RegEnumKeyEx(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN DWORD dwIndex, OUT LPWSTR lpName, IN OUT LPDWORD lpcName, IN LPDWORD lpReserved, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, OUT OPTIONAL PFILETIME lpftLastWriteTime);
BOOL ai_s_wpreg_QueryWithAlloc(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPVOID* lpData, IN OUT OPTIONAL LPDWORD lpcbData);
BOOL ai_s_wpdump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm, BOOL isHistory);
BOOL ai_s_wpdump_getSupplementalCreds(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hUser, IN const BYTE samKey[SAM_KEY_DATA_KEY_LENGTH]);
wchar_t* ai_s_string_qad_ansi_c_to_unicode(const char* ansi, SIZE_T szStr);
BOOL ai_s_wpreg_RegQueryValueEx(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, IN LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPBYTE lpData, IN OUT OPTIONAL LPDWORD lpcbData);
PAI_S_WPREG_HIVE_VALUE_KEY ai_s_wpreg_searchValueNameInList(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName);
BOOL ai_s_crypto_genericAES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID* pOut, DWORD* dwOutLen);
BOOL ai_s_wpdump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory);
void ai_s_wpdump_dcsync_descrUserProperties(PUSER_PROPERTIES properties);
BOOL ai_s_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hKey, HCRYPTPROV* hSessionProv);
PKERB_KEY_DATA ai_s_wpdump_lsa_keyDataInfo(PVOID base, PKERB_KEY_DATA keys, USHORT Count, PCWSTR title);
PKERB_KEY_DATA_NEW ai_s_wpdump_lsa_keyDataNewInfo(PVOID base, PKERB_KEY_DATA_NEW keys, USHORT Count, PCWSTR title);
BOOL ai_s_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hSessionKey, HCRYPTPROV* hSessionProv);
PWSTR ai_s_string_getRandomGUID();
BOOL ai_s_crypto_close_hprov_delete_container(HCRYPTPROV hProv);
BOOL ai_s_crypto_CryptGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BOOL withError, PBYTE* data, OPTIONAL DWORD* cbData, OPTIONAL DWORD* simpleDWORD);

//######################弱口令添加######################
BOOL DolphinCoreWorker_AddUser(const wchar_t* szUserName);
BOOL DolphinCoreWorker_AddHash(const BYTE byte_hash[LM_NTLM_HASH_LENGTH]);
const USER_PWD_RESULT* DolphinCoreWorker_GetResult();
void DolphinCoreWorker_FreeResult();

// ######################提权添加######################
// kull process
typedef LONG KPRIORITY;
typedef struct _VM_COUNTERS
{
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _KWAIT_REASON
{
    Executive,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrEventPair,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD
{
#if !defined(_M_X64) || !defined(_M_ARM64) // TODO:ARM64
    LARGE_INTEGER KernelTime;
#endif
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG State;
    KWAIT_REASON WaitReason;
#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
    LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    LPCWSTR Reserved2[2];
    ULONG PrivatePageCount;
    VM_COUNTERS VirtualMemoryCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

NTSTATUS ai_s_process_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass, PVOID buffer,
                                                 ULONG informationLength);

typedef BOOL(CALLBACK* PAI_S_PROCESS_ENUM_CALLBACK)(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation,
                                                      PVOID pvArg);
NTSTATUS ai_s_process_getProcessInformation(PAI_S_PROCESS_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL ai_s_process_run_data(LPCWSTR commandLine, HANDLE hToken);


// kull handle
typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING TypeName;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    // ...
    ULONG PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_HANDLE
{
    DWORD ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    DWORD HandleCount;
    SYSTEM_HANDLE Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef BOOL(CALLBACK* PAI_S_SYSTEM_HANDLE_ENUM_CALLBACK)(PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);
typedef BOOL(CALLBACK* PAI_S_HANDLE_ENUM_CALLBACK)(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);

typedef struct _HANDLE_ENUM_DATA
{
    PCUNICODE_STRING type;
    DWORD dwDesiredAccess;
    DWORD dwOptions;
    PAI_S_HANDLE_ENUM_CALLBACK callBack;
    PVOID pvArg;
} HANDLE_ENUM_DATA, *PHANDLE_ENUM_DATA;

NTSTATUS ai_s_handle_getHandles(PAI_S_SYSTEM_HANDLE_ENUM_CALLBACK callBack, PVOID pvArg);
NTSTATUS ai_s_handle_getHandlesOfType(PAI_S_HANDLE_ENUM_CALLBACK callBack, LPCTSTR type, DWORD dwDesiredAccess,
                                        DWORD dwOptions, PVOID pvArg);
BOOL CALLBACK ai_s_handle_getHandlesOfType_callback(PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);


//privilege
NTSTATUS ai_s_privilege_debug();
NTSTATUS ai_s_privilege_simple(ULONG privId);

//kull token
typedef BOOL(CALLBACK* PAI_S_TOKEN_ENUM_CALLBACK)(HANDLE hToken, DWORD ptid, PVOID pvArg);
typedef struct _AI_S_TOKEN_ENUM_DATA
{
    PAI_S_TOKEN_ENUM_CALLBACK callback;
    PVOID pvArg;
    BOOL mustContinue;
} AI_S_TOKEN_ENUM_DATA, *PAI_S_TOKEN_ENUM_DATA;

typedef struct _AI_S_TOKEN_LIST
{
    HANDLE hToken;
    DWORD ptid;
    struct _AI_S_TOKEN_LIST* next;
} AI_S_TOKEN_LIST, *PAI_S_TOKEN_LIST;

BOOL ai_s_token_getNameDomainFromSID(PSID pSid, PWSTR* pName, PWSTR* pDomain, PSID_NAME_USE pSidNameUse,
                                       LPCWSTR system);
BOOL ai_s_token_getTokens(PAI_S_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL ai_s_token_getTokensUnique(PAI_S_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg);
BOOL ai_s_token_getNameDomainFromToken(HANDLE hToken, PWSTR* pName, PWSTR* pDomain, PWSTR* pSid,
                                         PSID_NAME_USE pSidNameUse);
BOOL CALLBACK ai_s_token_getTokensUnique_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);
BOOL CALLBACK ai_s_token_getTokens_process_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation,
                                                      PVOID pvArg);
BOOL CALLBACK ai_s_token_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg);
BOOL ai_s_token_equal(IN HANDLE First, IN HANDLE Second);
PTOKEN_USER ai_s_token_getUserFromToken(HANDLE hToken);
BOOL ai_s_token_CheckTokenMembership(__in_opt HANDLE TokenHandle, __in PSID SidToCheck, __out PBOOL IsMember);

// kuhl token
typedef struct _AI_S_TOKEN_ELEVATE_DATA
{
    PSID pSid;
    PCWSTR pUsername;
    DWORD tokenId;
    BOOL elevateIt;
    BOOL runIt;
    PCWSTR pCommandLine;
    BOOL isSidDirectUser;
} AI_S_TOKEN_ELEVATE_DATA, *PAI_S_TOKEN_ELEVATE_DATA;

NTSTATUS ai_s_token_elevate_system();
BOOL CALLBACK ai_s_token_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg);
NTSTATUS ai_s_token_whoami(int argc, wchar_t* argv[]);
NTSTATUS ai_s_token_list_or_elevate(int argc, const wchar_t* argv[], BOOL elevate, BOOL runIt);

//string
BOOL ai_s_string_args_byName(const int argc, const wchar_t* argv[], const wchar_t* name, const wchar_t** theArgs,
                               const wchar_t* defaultValue);

//net
BOOL ai_s_net_getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO* pDomainInfo);
BOOL ai_s_net_CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID* pSid);
