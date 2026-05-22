#pragma once
//#include "DolphinCoreDef.h"

int dolphin_hash_code(const char* szPasswd, char hex_format[33]);
int dolphin_hash(const char* pszPasswd, char* pszHash, int nSize);