#pragma once
#include "VulnPocDef.h"
#include <string>

#ifdef __cplusplus
extern "C"
{
#endif

const int VULN_POC_RET_DEFAULT_ERROR = -1;
const int VULN_POC_RET_PASS          = 0;
const int VULN_POC_RET_UNINVOLVED    = 1;

typedef struct _VULN_POC_SCAN_CONTEXT
{
    void* pLuaState;
} VULN_POC_SCAN_CONTEXT;

VULN_POC_SCAN_CONTEXT* VPEInitialize();
int VPERegistLoadFunction(VULN_POC_SCAN_CONTEXT* pScanContext);
int VPEAddRequirePath(VULN_POC_SCAN_CONTEXT* pScanContext, const char* pszPath, const char* pszVersion);
int VPELoadPattern(VULN_POC_SCAN_CONTEXT* pScanContext, const char* pszPatternFilePath);
int VPEExecuteScan(VULN_POC_SCAN_CONTEXT* pScanContext, int& nRetCode, std::string& strRetDetail);
void VPEUnInitialize(VULN_POC_SCAN_CONTEXT** ppScanContext);

/// <summary>
/// 执行lua扫描，并返回结果
/// </summary>
/// <param name="nRetCode"></param>
/// <param name="strRetDetail"></param>
/// <param name="strLuaPath"></param>
/// <returns></returns>
HRA_VULNPOC_EXPORT int VulnPocExecuteScan(int& nRetCode, std::string& strRetDetail, const std::string& strLuaFilePath);


#ifdef __cplusplus
}
#endif