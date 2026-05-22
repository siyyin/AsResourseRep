#pragma once
#ifndef _SYS_SCAN_ENGINE_API_H_
#define _SYS_SCAN_ENGINE_API_H_
#include "Vaeng/VAScan.h"
#include <iostream>
#include "utility/comm.h"
#include "utility/Logger.h"

#define MAX_LEN_1024       1024
#define TRUST_ONE_IPC_NAME              "hra_for_esm_ipcsrv"
#define DS_IPC_NAME                     "AsiDSIpcHRA"

struct OsScanEngineApi
{
	// 引擎上下文
	VA_SCAN_CONTEXT* pVAScanContext;
	unsigned char ucPatternIsLoad;
};

int OsScanPatternLoad(const char *pscPatternPath, struct OsScanEngineApi *pstOsScanEngineApi);
int OsScanEngineDoScan(struct OsScanEngineApi *pstOsScanEngineApi, std::string &strScanResultData, bool bIsAllCveScan = false);
// 初始化引擎
int OsScanEngineInit(struct OsScanEngineApi *pstOsScanEngineApi, const std::string& strPatternPath);
// 恢复IOA引擎状态
void OsScanEngineUnInit(struct OsScanEngineApi *pstOsScanEngineApi);


#endif /* _SYS_SCAN_ENGINE_API_H_ */