#pragma once

#include <windows.h>

//#define	MD4_DIGEST_LENGTH	16
#define	MD5_DIGEST_LENGTH	16
//#define SHA_DIGEST_LENGTH	20

#define DECLARE_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
const WCHAR _var ## _buffer[] = _string; \
const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }

typedef CONST UNICODE_STRING* PCUNICODE_STRING;

//typedef struct _MD4_CTX
//{
//    DWORD state[4];
//    DWORD count[2];
//    BYTE buffer[64];
//    BYTE digest[MD4_DIGEST_LENGTH];
//} MD4_CTX, * PMD4_CTX;

//typedef struct _MD5_CTX
//{
//    DWORD count[2];
//    DWORD state[4];
//    BYTE buffer[64];
//    BYTE digest[MD5_DIGEST_LENGTH];
//} MD5_CTX, * PMD5_CTX;

//typedef struct _SHA_CTX
//{
//    BYTE buffer[64];
//    DWORD state[5];
//    DWORD count[2];
//    DWORD unk[6]; // to avoid error on XP
//} SHA_CTX, * PSHA_CTX;

//typedef struct _SHA_DIGEST
//{
//    BYTE digest[SHA_DIGEST_LENGTH];
//} SHA_DIGEST, * PSHA_DIGEST;

typedef struct _CRYPT_BUFFER
{
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

extern "C"
{
    //VOID WINAPI MD4Init(PMD4_CTX pCtx);
    //VOID WINAPI MD4Update(PMD4_CTX pCtx, LPCVOID data, DWORD cbData);
    //VOID WINAPI MD4Final(PMD4_CTX pCtx);

    //VOID WINAPI MD5Init(PMD5_CTX pCtx);
    //VOID WINAPI MD5Update(PMD5_CTX pCtx, LPCVOID data, DWORD cbData);
    //VOID WINAPI MD5Final(PMD5_CTX pCtx);

    //VOID WINAPI A_SHAInit(PSHA_CTX pCtx);
    //VOID WINAPI A_SHAUpdate(PSHA_CTX pCtx, LPCVOID data, DWORD cbData);
    //VOID WINAPI A_SHAFinal(PSHA_CTX pCtx, PSHA_DIGEST pDigest);

    //#define RtlEncryptBlock						SystemFunction001 // DES
    //#define RtlDecryptBlock						SystemFunction002 // DES
    //#define RtlEncryptStdBlock					SystemFunction003 // DES with key "KGS!@#$%" for LM hash
    //#define RtlEncryptData						SystemFunction004 // DES/ECB
    //#define RtlDecryptData						SystemFunction005 // DES/ECB
    //#define RtlCalculateLmOwfPassword			SystemFunction006
    //#define RtlCalculateNtOwfPassword			SystemFunction007
    //#define RtlCalculateLmResponse				SystemFunction008
    //#define RtlCalculateNtResponse				SystemFunction009
    //#define RtlCalculateUserSessionKeyLm		SystemFunction010
    //#define RtlCalculateUserSessionKeyNt		SystemFunction011
    //#define RtlEncryptLmOwfPwdWithLmOwfPwd		SystemFunction012
    //#define RtlDecryptLmOwfPwdWithLmOwfPwd		SystemFunction013
    //#define RtlEncryptNtOwfPwdWithNtOwfPwd		SystemFunction014
    //#define RtlDecryptNtOwfPwdWithNtOwfPwd		SystemFunction015
    //#define RtlEncryptLmOwfPwdWithLmSesKey		SystemFunction016
    //#define RtlDecryptLmOwfPwdWithLmSesKey		SystemFunction017
    //#define RtlEncryptNtOwfPwdWithNtSesKey		SystemFunction018
    //#define RtlDecryptNtOwfPwdWithNtSesKey		SystemFunction019
    //#define RtlEncryptLmOwfPwdWithUserKey		SystemFunction020
    //#define RtlDecryptLmOwfPwdWithUserKey		SystemFunction021
    //#define RtlEncryptNtOwfPwdWithUserKey		SystemFunction022
    //#define RtlDecryptNtOwfPwdWithUserKey		SystemFunction023
    //#define RtlEncryptLmOwfPwdWithIndex			SystemFunction024
    //#define RtlDecryptLmOwfPwdWithIndex			SystemFunction025
    //#define RtlEncryptNtOwfPwdWithIndex			SystemFunction026
#define RtlDecryptNtOwfPwdWithIndex			SystemFunction027
//#define RtlGetUserSessionKeyClient			SystemFunction028
//#define RtlGetUserSessionKeyServer			SystemFunction029
//#define RtlEqualLmOwfPassword				SystemFunction030
//#define RtlEqualNtOwfPassword				SystemFunction031
#define RtlEncryptData2						SystemFunction032 // RC4
#define RtlDecryptData2						SystemFunction033 // RC4
//#define RtlGetUserSessionKeyClientBinding	SystemFunction034
//#define RtlCheckSignatureInFile				SystemFunction035
//
//    NTSTATUS WINAPI RtlEncryptBlock(IN LPCBYTE ClearBlock, IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
//    NTSTATUS WINAPI RtlDecryptBlock(IN LPCBYTE CypherBlock, IN LPCBYTE BlockKey, OUT LPBYTE ClearBlock);
//    NTSTATUS WINAPI RtlEncryptStdBlock(IN LPCBYTE BlockKey, OUT LPBYTE CypherBlock);
//    NTSTATUS WINAPI RtlEncryptData(IN PCLEAR_DATA ClearData, IN PDATA_KEY DataKey, OUT PCYPHER_DATA CypherData);
//    NTSTATUS WINAPI RtlDecryptData(IN PCYPHER_DATA CypherData, IN PDATA_KEY DataKey, OUT PCLEAR_DATA ClearData);
//    NTSTATUS WINAPI RtlCalculateLmOwfPassword(IN LPCSTR data, OUT LPBYTE output);
//    NTSTATUS WINAPI RtlCalculateNtOwfPassword(IN PCUNICODE_STRING data, OUT LPBYTE output);
//    NTSTATUS WINAPI RtlCalculateLmResponse(IN LPCBYTE LmChallenge, IN LPCBYTE LmOwfPassword, OUT LPBYTE LmResponse);
//    NTSTATUS WINAPI RtlCalculateNtResponse(IN LPCBYTE NtChallenge, IN LPCBYTE NtOwfPassword, OUT LPBYTE NtResponse);
//    NTSTATUS WINAPI RtlCalculateUserSessionKeyLm(IN LPCBYTE LmResponse, IN LPCBYTE LmOwfPassword, OUT LPBYTE UserSessionKey);
//    NTSTATUS WINAPI RtlCalculateUserSessionKeyNt(IN LPCBYTE NtResponse, IN LPCBYTE NtOwfPassword, OUT LPBYTE UserSessionKey);
//    NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE DataLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE EncryptedLmOwfPassword);
//    NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmOwfPwd(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE KeyLmOwfPassword, OUT LPBYTE DataLmOwfPassword);
//    NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE DataNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE EncryptedNtOwfPassword);
//    NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtOwfPwd(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE KeyNtOwfPassword, OUT LPBYTE DataNtOwfPassword);
//    NTSTATUS WINAPI RtlEncryptLmOwfPwdWithLmSesKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
//    NTSTATUS WINAPI RtlDecryptLmOwfPwdWithLmSesKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE LmSessionKey, OUT LPBYTE LmOwfPassword);
//    NTSTATUS WINAPI RtlEncryptNtOwfPwdWithNtSesKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
//    NTSTATUS WINAPI RtlDecryptNtOwfPwdWithNtSesKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE NtSessionKey, OUT LPBYTE NtOwfPassword);
//    NTSTATUS WINAPI RtlEncryptLmOwfPwdWithUserKey(IN LPCBYTE LmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedLmOwfPassword);
//    NTSTATUS WINAPI RtlDecryptLmOwfPwdWithUserKey(IN LPCBYTE EncryptedLmOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE LmOwfPassword);
//    NTSTATUS WINAPI RtlEncryptNtOwfPwdWithUserKey(IN LPCBYTE NtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE EncryptedNtOwfPassword);
//    NTSTATUS WINAPI RtlDecryptNtOwfPwdWithUserKey(IN LPCBYTE EncryptedNtOwfPassword, IN LPCBYTE UserSessionKey, OUT LPBYTE NtOwfPassword);
//    NTSTATUS WINAPI RtlEncryptLmOwfPwdWithIndex(IN LPCBYTE LmOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedLmOwfPassword);
//    NTSTATUS WINAPI RtlDecryptLmOwfPwdWithIndex(IN LPCBYTE EncryptedLmOwfPassword, IN LPDWORD Index, OUT LPBYTE LmOwfPassword);
//    NTSTATUS WINAPI RtlEncryptNtOwfPwdWithIndex(IN LPCBYTE NtOwfPassword, IN LPDWORD Index, OUT LPBYTE EncryptedNtOwfPassword);
    NTSTATUS WINAPI RtlDecryptNtOwfPwdWithIndex(IN LPCBYTE EncryptedNtOwfPassword, IN LPDWORD Index, OUT LPBYTE NtOwfPassword);
    //    NTSTATUS WINAPI RtlGetUserSessionKeyClient(IN PVOID RpcContextHandle, OUT LPBYTE UserSessionKey);
    //    NTSTATUS WINAPI RtlGetUserSessionKeyServer(IN PVOID RpcContextHandle OPTIONAL, OUT LPBYTE UserSessionKey);
    //    BOOLEAN WINAPI RtlEqualLmOwfPassword(IN LPCBYTE LmOwfPassword1, IN LPCBYTE LmOwfPassword2);
    //    BOOLEAN WINAPI RtlEqualNtOwfPassword(IN LPCBYTE NtOwfPassword1, IN LPCBYTE NtOwfPassword2);
    NTSTATUS WINAPI RtlEncryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
    NTSTATUS WINAPI RtlDecryptData2(IN OUT PCRYPT_BUFFER pData, IN PDATA_KEY pkey);
    //    NTSTATUS WINAPI RtlGetUserSessionKeyClientBinding(IN PVOID RpcBindingHandle, OUT HANDLE* RedirHandle, OUT LPBYTE UserSessionKey);
    //    ULONG WINAPI RtlCheckSignatureInFile(IN LPCWSTR filename);

    extern BOOLEAN WINAPI RtlEqualString(IN const STRING* String1, IN const STRING* String2, IN BOOLEAN CaseInSensitive);
    extern BOOLEAN WINAPI RtlEqualUnicodeString(IN PCUNICODE_STRING String1, IN PCUNICODE_STRING String2, IN BOOLEAN CaseInSensitive);
    extern NTSTATUS WINAPI RtlStringFromGUID(IN LPCGUID Guid, PUNICODE_STRING UnicodeString);
    extern VOID WINAPI RtlFreeUnicodeString(IN OUT PUNICODE_STRING UnicodeString);
    extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString, IN PCWSTR SourceString);

    typedef enum _SYSTEM_INFORMATION_CLASS
    {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemNextEventIdInformation,
        SystemEventIdsInformation,
        SystemCrashDumpInformation,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemPlugPlayBusInformation,
        SystemDockInformation,
        KIWI_SystemPowerInformation,
        SystemProcessorSpeedInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        KIWI_SystemMmSystemRangeStart     = 50,
        SystemIsolatedUserModeInformation = 165
    } SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;
    extern NTSTATUS WINAPI NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
                                                    OUT PVOID SystemInformation, IN ULONG SystemInformationLength,
                                                    OUT OPTIONAL PULONG ReturnLength);

    extern NTSTATUS NTAPI NtCompareTokens(IN HANDLE FirstTokenHandle, IN HANDLE SecondTokenHandle, OUT PBOOLEAN Equal);

    #define SE_DEBUG 20
    extern NTSTATUS WINAPI RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable, IN BOOL CurrentThread,
                                              OUT PULONG pPreviousState);

    typedef enum _OBJECT_INFORMATION_CLASS
    {
        ObjectBasicInformation,
        ObjectNameInformation,
        ObjectTypeInformation,
        ObjectAllInformation,
        ObjectDataInformation
    } OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;
    extern NTSTATUS WINAPI NtQueryObject(IN OPTIONAL HANDLE Handle, IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
                                         OUT OPTIONAL PVOID ObjectInformation, IN ULONG ObjectInformationLength,
                                         OUT OPTIONAL PULONG ReturnLength);
}
