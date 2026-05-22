#pragma once
#include <stdint.h>
#include "VulnPocDef.h"
#include "json/json.h"
#include "utility/comm.h"

HRA_VULNPOC_EXPORT int VulnPocInit(void);
HRA_VULNPOC_EXPORT int VulnPocDestroy(void);
HRA_VULNPOC_EXPORT int VulnPocCfgHandle(const Json::Value& jsContect);

HRA_VULNPOC_EXPORT int VulnPocCancelInit(void);
HRA_VULNPOC_EXPORT int VulnPocCancelDestroy(void);
HRA_VULNPOC_EXPORT int VulnPocCancelHandle(const Json::Value& jsContect);

HRA_VULNPOC_EXPORT int VulnPocCopyPattPack(std::string& strTempDir, const std::string& strPatternFile);
HRA_VULNPOC_EXPORT int VulnPocPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir);


struct VulnPocScanItem
{
    int scan_id;
    int os_type;
    int vuln_type;
    std::string cve_id;
    std::string scan_script;

    void clear()
    {
        scan_id = 0;
        os_type = 0;
        vuln_type = 0;
        cve_id.clear();
        scan_script.clear();
    }

    VulnPocScanItem()
    {
        clear();
    }
};

struct VulnPocWorkEntry
{
    std::string task_id;
    std::vector<VulnPocScanItem> scan_items;
    uint64_t pre_task_seq;

    void clear()
    {
        task_id.clear();
        scan_items.clear();
        pre_task_seq = 0;
    }

    VulnPocWorkEntry()
    {
        clear();
    }
};

/// <summary>
/// POC检测线程工作函数入口
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
void* VulnPocWorker(void* pArg);

/// <summary>
/// 设置、获取pattern工作状态
/// </summary>
/// <param name=""></param>
/// <returns></returns>
char VulnPocGetModuleWorkStatus(void);
void VulnPocSetModuleWorkStatus(char scModuleWork);

/// <summary>
/// 解析指令
/// </summary>
/// <param name="stWorkEntry"></param>
/// <param name="jsContect"></param>
/// <returns></returns>
int VulnPocCfgParse(VulnPocWorkEntry& stWorkEntry, const Json::Value& jsContect);

/// <summary>
/// 将任务添加到队列
/// </summary>
/// <param name="stWorkEntry"></param>
/// <param name="jsContect"></param>
/// <returns></returns>
int VulnPocCfgApply(const VulnPocWorkEntry& stWorkEntry, const Json::Value& jsContect);

/// <summary>
/// Poc漏扫结果上报
/// </summary>
/// <param name="pscTaskId"></param>
/// <param name="lRet"></param>
/// <param name="strScanResult"></param>
/// <returns></returns>
int VulnPocReport(const char* pscTaskId, int lRet, const std::string& strScanResult);

/// <summary>
/// 解析vuln_poc.json
/// </summary>
/// <param name="entry"></param>
/// <returns></returns>
int VulnPocParseJsonPattern(VulnPocWorkEntry& entry);

/// <summary>
/// 执行lua扫描
/// </summary>
/// <param name="nRetCode"></param>
/// <param name="strDetail"></param>
/// <param name="entry"></param>
/// <returns></returns>
int VulnPocLuaScan(int& nRetCode, std::string& strRetDetail, const VulnPocScanItem& stScanItem);


/// <summary>
/// 启动时检查pattern是否解压，未解压搜索最新的解压
/// </summary>
/// <param name=""></param>
/// <returns></returns>
int VulnPocPreparePattern(void);

