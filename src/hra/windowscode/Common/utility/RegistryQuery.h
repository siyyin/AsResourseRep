#pragma once
#include <windows.h>
#include "comm.h"

int HRA_UTILITY_EXPORT RegQueryStrValue(char* pszValue, int nSize, const HKEY RootKey, const char* lpSubKey, const char* lpKeyName);
int HRA_UTILITY_EXPORT RegQueryIntValue(int& nValue, const HKEY RootKey, const char* lpSubKey, const char* lpKeyName);

