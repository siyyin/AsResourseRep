#pragma once

/* 宏定义 */
#define HRA_ELMT_REG_REPORT_CMD             1001//注册信息上报
#define HRA_ELMT_LOG_LEVEL_CMD              3000//日志等级调整

#define HRA_ELMT_ASSETS_SCAN_CFG            6002//资产扫描
#define HRA_ELMT_APP_SCAN_CFG               6003//应用漏扫
#define HRA_ELMT_OS_SCAN_CFG                6004//系统漏扫
#define HRA_ELMT_BASE_LINE_CFG              6005//基线扫描
#define HRA_PATTERN_UPDATE_CMD              6006//pattern更新
#define HRA_ELMT_WP_SACN_CFG                6007//弱口令扫描
#define HRA_ELMT_HOST_DISCOVERY_CFG         6008//未知资产发现
#define HRA_ELMT_VULN_POC_CFG               6009//漏洞POC扫描

#define HRA_ELMT_ASSETS_SCAN_CANCEL         6102//资产扫描取消
#define HRA_ELMT_APP_SCAN_CANCEL            6103//应用漏扫取消
#define HRA_ELMT_OS_SCAN_CANCEL             6104//系统漏扫取消
#define HRA_ELMT_BASE_LINE_CANCEL           6105//基线扫描取消
#define HRA_ELMT_WP_SACN_CANCEL             6107//弱口令扫描取消
#define HRA_ELMT_HOST_DISCOVERY_CANCEL      6108//未知资产发现取消
#define HRA_ELMT_VULN_POC_CANCEL            6109//漏洞POC扫描取消

/// <summary>
/// 上报管理端的msg类型
/// </summary>
enum RspMsgType
{
    AGENT_REG_INFO = 0,         // 0-上报agent信息
    ASSET_SCAN_RESULT,          // 1-上报资产扫描结果
    APP_SCAN_RESULT,            // 2-上报应用漏洞扫描结果
    OS_SCAN_RESULT,             // 3-上报系统漏洞扫描结果
    BASELINE_RESULT,            // 4-上报基线扫描结果
    CONFIG_RESULT,              // 5-上报下发配置结果
    DOLPHIN_RESULT,             // 6-上报弱口令扫描结果
    HOST_DISCOVERY_RESULT,      // 7-上报主机发现扫描结果
    VULN_POC_RESULT,            // 8-上报漏洞POC扫描结果
    REPORT_LAST
};