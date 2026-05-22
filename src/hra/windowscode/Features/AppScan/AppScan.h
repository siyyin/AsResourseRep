#ifndef _APP_SCAN_H_
#define _APP_SCAN_H_

#include "json/json.h"
#include "utility/comm.h"
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
#include "HRATaskScheduler\HRATaskScheduler.h"

//#define APPSCAN_TASK_ID_MAX_LEN      (128)

//导入导出宏定义
#ifdef HRA_APPSCAN_API_COMPILED
#ifdef WIN32
#define HRA_APPSCAN_EXPORT __declspec(dllexport)
#else
#define HRA_APPSCAN_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_APPSCAN_EXPORT __declspec(dllimport)
#else
#define HRA_APPSCAN_EXPORT extern
#endif
#endif


struct HRA_APPSCAN_EXPORT AppScanWorkEntry
{
	char ascTaskId[128];        //任务id，结束后在结果中返回给到manager
	//char scScanEnable;     //周期性扫描功能开关，0：关闭（主要针对周期性扫描）1：开启 
	//int  lScanType;				//扫描类型
    uint64_t pre_task_seq;
};

int HRA_APPSCAN_EXPORT AppScanInit(void);
int HRA_APPSCAN_EXPORT AppScanDestroy(void);
int HRA_APPSCAN_EXPORT AppScanCfgHandle(const Json::Value& jsContect);

int HRA_APPSCAN_EXPORT AppScanCancelInit(void);
int HRA_APPSCAN_EXPORT AppScanCancelDestroy(void);
int HRA_APPSCAN_EXPORT AppScanCancelHandle(const Json::Value& jsContect);
#endif /* _APP_SCAN_H_ */