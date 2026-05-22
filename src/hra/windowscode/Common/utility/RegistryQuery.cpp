#include "RegistryQuery.h"
#include <stdio.h>

#include "Logger.h"

int RegQueryStrValue(char* pszValue, int nSize, const HKEY RootKey, const char* lpSubKey, const char* lpKeyName)
{
    if (RootKey == NULL || lpSubKey == NULL || lpKeyName == NULL)
    {
        return HRA_BAD_PARAM;
    }

    if (pszValue == NULL || nSize <= 0)
    {
        return HRA_NULL_PTR;
    }

    char szBuffer[MAX_PATH];
    memset(szBuffer, 0, sizeof(szBuffer));
    DWORD dwKeyLen = MAX_PATH;
    DWORD dwBuffLen = MAX_PATH;
    DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
    HKEY hkRKey = NULL;
    if (ERROR_SUCCESS != RegOpenKeyExA(RootKey, lpSubKey, 0, KEY_QUERY_VALUE, &hkRKey))
    {
        LOG_WARN("RegOpenKeyExA(%s) failed, errorCode:%lu.", lpSubKey, GetLastError());
        return HRA_OPEN_FAIL;
    }

    if (ERROR_SUCCESS != RegQueryValueExA(hkRKey, lpKeyName, 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen))
    {
        LOG_WARN("RegQueryValueExA(%s) failed, errorCode:%lu.", lpKeyName, GetLastError());
        RegCloseKey(hkRKey);
        return HRA_FAILED;
    }

    _snprintf_s(pszValue, nSize, nSize-1, "%s", szBuffer);
    RegCloseKey(hkRKey);
    hkRKey = NULL;

    return HRA_OK;
}

int RegQueryIntValue(int& nValue, const HKEY RootKey, const char* lpSubKey, const char* lpKeyName)
{
    if (RootKey == NULL || lpSubKey == NULL || lpKeyName == NULL)
    {
        return HRA_BAD_PARAM;
    }

    char szBuffer[MAX_PATH];
    memset(szBuffer, 0, sizeof(szBuffer));
    DWORD dwKeyLen = MAX_PATH;
    DWORD dwBuffLen = MAX_PATH;
    DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
    HKEY hkRKey = NULL;
    if (ERROR_SUCCESS != RegOpenKeyExA(RootKey, lpSubKey, 0, KEY_QUERY_VALUE, &hkRKey))
    {
        LOG_WARN("RegOpenKeyExA(%s) failed, errorCode:%lu.", lpSubKey, GetLastError());
        return HRA_OPEN_FAIL;
    }

    if (ERROR_SUCCESS != RegQueryValueExA(hkRKey, lpKeyName, 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen))
    {
        LOG_WARN("RegQueryValueExA(%s) failed, errorCode:%lu.", lpKeyName, GetLastError());
        RegCloseKey(hkRKey);
        return HRA_FAILED;
    }

    nValue = *(int*)szBuffer;
    RegCloseKey(hkRKey);
    hkRKey = NULL;

    return HRA_OK;
}