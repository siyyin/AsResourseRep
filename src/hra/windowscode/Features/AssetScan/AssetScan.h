#pragma once
#ifndef _ASSET_SCAN_H_
#define _ASSET_SCAN_H_

#include "json/json.h"
#include "utility/comm.h"
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
#include "HRATaskScheduler/HRATaskScheduler.h"

//导入导出宏定义
#ifdef HRA_ASSETSCAN_API_COMPILED
#ifdef WIN32
#define HRA_ASSETSCAN_EXPORT __declspec(dllexport)
#else
#define HRA_ASSETSCAN_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_ASSETSCAN_EXPORT __declspec(dllimport)
#else
#define HRA_ASSETSCAN_EXPORT extern
#endif
#endif

#define ASSETS_TASK_ID_MAX_LEN      (128)
#define ASSETS_REPORT_MAX_TIME      (60*24*31) // 最长支持31天 一个周期
#define ASSETS_REPORT_DEFAULT_TIME  (60)       // 默认时间
#define ASSETS_DEFAULT_SCANENABLE_OFF (0)      // 资产发现默认状态
//#define ASSETS_REPORT_TIME (15) //资产上报时间
#define ASSETS_DEFAULT_TIMER_INTERVAL (60) // 定时器默认频率

#define ASSETS_SELF_TRIGGER_TASK "self_trigger_task" // hra主动上报的task_id，hrm自动接收入库
//下面两个task_id在上报给HRM时task_id都会上报self_trigger_task
#define ASSETS_TIMER_TRIGGER_TASK   "timer_trigger_task"    // 资产定时器触发task_id
#define ASSETS_VULN_DEPENDENT_TASK  "vuln_dependent_task"   // 漏洞模块依赖task_id

struct HRA_ASSETSCAN_EXPORT AssetScanWorkEntry 
{
    char task_id[ASSETS_TASK_ID_MAX_LEN];
    unsigned int timer_enable;   // 定时器功能开关,1:开启,0:关闭
    unsigned int timer_interval; // 定时器频率
};

HRA_ASSETSCAN_EXPORT int AssetScanInit(void);
HRA_ASSETSCAN_EXPORT int AssetScanDestroy(void);
HRA_ASSETSCAN_EXPORT int AssetScanCfgHandle(const Json::Value& jsContent);
HRA_ASSETSCAN_EXPORT int AssetScanCancelInit(void);
HRA_ASSETSCAN_EXPORT int AssetScanCancelDestroy(void);
HRA_ASSETSCAN_EXPORT int AssetScanCancelHandle(const Json::Value& jsContent);
HRA_ASSETSCAN_EXPORT int AssetPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir);
HRA_ASSETSCAN_EXPORT int AssetCopyPattPack(std::string& strTempDir, const std::string& strPatternFile);

/// <summary>
/// 向队列插入任务
/// </summary>
/// <param name="lpParameter">为null时，自动从config.db读取参数</param>
HRA_ASSETSCAN_EXPORT uint64_t AssetScanAddTask(const Json::Value& jsContent);

int AssetScanReport(const char* pszTaskId, const std::string& strAssetScanResultInfo, int lRet /*, int lScanType*/);
void* AssetScanWorker(void* pArg);
std::string GetTaskIdFromCmd(const Json::Value& jsContent);
int AssetScanCfgParse(AssetScanWorkEntry& sAssetScanWorkEntry, const Json::Value& jsContent);
int AssetScanSaveCfg(const AssetScanWorkEntry& sAssetScanWorkEntry);

//pattern相关
int AssetPreparePattern(void);

char AssetGetModuleWorkStatus(void);
void AssetSetModuleWorkStatus(char scAssetModuleWork);

#endif