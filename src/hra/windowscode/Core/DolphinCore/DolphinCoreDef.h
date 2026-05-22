#pragma once

//导入导出宏定义
#ifdef HRA_DOLPHIN_CORE_API_COMPILED
#ifdef WIN32
#define HRA_DOLPHIN_CORE_EXPORT __declspec(dllexport)
#else
#define HRA_DOLPHIN_CORE_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_DOLPHIN_CORE_EXPORT __declspec(dllimport)
#else
#define HRA_DOLPHIN_CORE_EXPORT extern
#endif
#endif

#define LM_NTLM_HASH_LENGTH	16
#define MAX_USER_NAME_SIZE 256

typedef struct _USER_PWD_HASH
{
    wchar_t     user_name[MAX_USER_NAME_SIZE];
    wchar_t     pwd_hash[LM_NTLM_HASH_LENGTH * 2 + 1];
} USER_PWD_HASH;

typedef struct _USER_PWD_RESULT
{
    USER_PWD_HASH           stData;
    struct _USER_PWD_RESULT* pNext;
} USER_PWD_RESULT;

