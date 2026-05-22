#pragma once
#ifndef _SYS_SCAN_H_
#define _SYS_SCAN_H_

#include "utility/comm.h"
#include "utility/HraPatternUpdateUtils.h"
#include <string>
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
#include "HRATaskScheduler\\HRATaskScheduler.h"

//导入导出宏定义
#ifdef HRA_OSSCAN_API_COMPILED
#ifdef WIN32
#define HRA_OSSCAN_EXPORT __declspec(dllexport)
#else
#define HRA_OSSCAN_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_OSSCAN_EXPORT __declspec(dllimport)
#else
#define HRA_OSSCAN_EXPORT extern
#endif
#endif

extern CPatternUpdateUtils g_OsScanPatternUpdateUtils;

#define OS_SCAN_TASK_ID_MAX_LEN      (128)

struct HRA_OSSCAN_EXPORT OsScanWorkEntry
{
	uint64_t pre_task_seq;
	char ascTaskId[OS_SCAN_TASK_ID_MAX_LEN];   //任务id，结束后在结果中返回给到manager
	//int lScanType;								//扫描类型
};

int HRA_OSSCAN_EXPORT OsScanInit(void);
int HRA_OSSCAN_EXPORT OsScanDestroy(void);
int HRA_OSSCAN_EXPORT OsScanCfgHandle(const Json::Value& jsContect);
int HRA_OSSCAN_EXPORT OsScanCfgParse(struct OsScanWorkEntry *pstOsScanWorkEntry, const Json::Value& jsContect);
int HRA_OSSCAN_EXPORT OsScanCfgApply(struct OsScanWorkEntry *pstOsScanWorkEntry);
int HRA_OSSCAN_EXPORT OsScanPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir);
int HRA_OSSCAN_EXPORT OsScanCopyPattPack(std::string& strTempDir, const std::string& strPatternFile);

int HRA_OSSCAN_EXPORT OsScanCancelInit(void);
int HRA_OSSCAN_EXPORT OsScanCancelDestroy(void);
int HRA_OSSCAN_EXPORT OsScanCancelHandle(const Json::Value& jsContect);

#endif /* _SYS_SCAN_H_ */