#pragma once
#include "BaseLineDef.h"
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C"
{
#endif

// lua返回值
const int BASE_LINE_LUA_RET_ERROR      = -1;
const int BASE_LINE_LUA_RET_PASS       = 0;
const int BASE_LINE_LUA_RET_UNPASS     = 1;
const int BASE_LINE_LUA_RET_UNINVOLVED = 2;

typedef struct _BASE_LINE_SCAN_CONTEXT
{
    void* pLuaState;
    char** ppszParamList;
    int nParamCount;
} BASE_LINE_SCAN_CONTEXT;

BASE_LINE_SCAN_CONTEXT* BLInitialize();
int BLRegistLoadFunction(BASE_LINE_SCAN_CONTEXT* pScanContext);
int BLAddRequirePath(BASE_LINE_SCAN_CONTEXT* pScanContext, const char* pszPath, const char* pszVersion);
int BLLoadPattern(BASE_LINE_SCAN_CONTEXT* pScanContext, const char* pszPatternFilePath);
int BLExecuteScan(BASE_LINE_SCAN_CONTEXT* pScanContext, int& nRetCode);
void BLUnInitialize(BASE_LINE_SCAN_CONTEXT** ppScanContext);

//std::wstring FindBaseLinePatternPathFromLuaPath(const std::wstring& strLuaPath, const std::wstring& strVersion);
//std::wstring FindRequirePath(const std::wstring& strFindPath, const std::wstring& strVersion);

/// <summary>
/// 执行lua扫描，并返回结果
/// </summary>
/// <param name="nRetCode"></param>
/// <param name="strRetDetail"></param>
/// <param name="strLuaPath"></param>
/// <returns></returns>
HRA_BASELINE_EXPORT int BaseLineExcuteScan(int& nRetCode, const std::string& strLuaFilePath,
                                           const std::vector<std::string>& vctParams);


#ifdef __cplusplus
}
#endif