#pragma once
#include "DolphinCoreDef.h"

//HRA_DOLPHIN_CORE_EXPORT int dolphin_hash_code(const char* szPasswd, char hex_format[33]);
HRA_DOLPHIN_CORE_EXPORT int dolphin_hash(const char* pszPasswd, char* pszHash, int nSize);