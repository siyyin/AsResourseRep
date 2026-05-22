// HRAModuleInterface.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "HRAModule.h"
#include "HRAModuleInterface.h"
#include "utility/Logger.h"
#include "utility/HraTaskType.h"
#include "AppScan/AppScan.h"
#include "AssetScan/AssetScan.h"
#include "OsScan/OsScan.h"
#include "PatternUpdate/HraPatternUpdate.h"
#include "Dolphin/Dolphin.h"
#include "BaseLine/BaseLine.h"
#include "VulnPoc/VulnPoc.h"
#include "LogMgr/LogMgr.h"
#include "RegReport/RegReport.h"
#include "HostDiscovery/HostDiscovery.h"

HraModuleElmtFunMap g_astHraModuleElmtFunTable[] = 
{
    //上报注册信息指令
    {HRA_ELMT_REG_REPORT_CMD, RegReportInit, RegReportDestroy, RegReportCfgHandle},
    //日志等级指令
    {HRA_ELMT_LOG_LEVEL_CMD, LogMgrInit, LogMgrDestroy, LogMgrCfgHandle},
    //扫描任务指令
	{HRA_ELMT_ASSETS_SCAN_CFG,  AssetScanInit, AssetScanDestroy, AssetScanCfgHandle},
	{HRA_ELMT_APP_SCAN_CFG,  AppScanInit, AppScanDestroy, AppScanCfgHandle},
	{HRA_ELMT_OS_SCAN_CFG,  OsScanInit, OsScanDestroy, OsScanCfgHandle},
	{HRA_ELMT_BASE_LINE_CFG, BaseLineInit, BaseLineDestroy, BaseLineCfgHandle},
    {HRA_ELMT_WP_SACN_CFG, DolphinInit, DolphinDestroy, DolphinCfgHandle},
    {HRA_ELMT_HOST_DISCOVERY_CFG, HostDiscoveryInit, HostDiscoveryDestroy, HostDiscoveryCfgHandle},
    {HRA_ELMT_VULN_POC_CFG, VulnPocInit, VulnPocDestroy, VulnPocCfgHandle},
    //取消指令
    {HRA_ELMT_ASSETS_SCAN_CANCEL,  AssetScanCancelInit, AssetScanCancelDestroy, AssetScanCancelHandle},
    {HRA_ELMT_APP_SCAN_CANCEL,  AppScanCancelInit, AppScanCancelDestroy, AppScanCancelHandle},
    {HRA_ELMT_OS_SCAN_CANCEL,  OsScanCancelInit, OsScanCancelDestroy, OsScanCancelHandle},
    {HRA_ELMT_BASE_LINE_CANCEL, BaseLineCancelInit, BaseLineCancelDestroy, BaseLineCancelHandle},
    {HRA_ELMT_WP_SACN_CANCEL, DolphinCancelInit, DolphinCancelDestroy, DolphinCancelHandle},
    {HRA_ELMT_HOST_DISCOVERY_CANCEL, HostDiscoveryCancelInit, HostDiscoveryCancelDestroy, HostDiscoveryCancelHandle},
    {HRA_ELMT_VULN_POC_CANCEL, VulnPocCancelInit, VulnPocCancelDestroy, VulnPocCancelHandle}
};

#define HRA_MODULE_ELM_FUN_TABLE_LEN (sizeof(g_astHraModuleElmtFunTable)/sizeof(struct HraModuleElmtFunMap))

/*****************************************************************
* DESCRIPTION: FindElmtHandler
*     寻找command对应的回调处理函数
* INPUTS:
*     ulMsgType   : json 中的command
* OUTPUTS:
*     无
* RETURNS:
*     NULL : 没有找到
*     module的回调结构体
* CAUTIONS:
*       none
*****************************************************************/
HRA_MODULEINTERFACE_EXPORT struct HraModuleElmtFunMap * FindElmtHandler(unsigned int ulMsgType)
{
	int i;

	for(i = 0; i < HRA_MODULE_ELM_FUN_TABLE_LEN; i++)
	{
		if(g_astHraModuleElmtFunTable[i].ulMsgType == ulMsgType)
		{
			return &g_astHraModuleElmtFunTable[i];
		}
	}

	return NULL;
}

/*****************************************************************
* DESCRIPTION: ModuleInit
*     模块的统一初始化
* INPUTS:
*     无
* OUTPUTS:
*     无
* RETURNS:
*     0 : 成功
*     其他 : 失败
* CAUTIONS:
*       none
*****************************************************************/
HRA_MODULEINTERFACE_EXPORT int ModuleInit(void)
{
	int i;

	for(i = 0; i < HRA_MODULE_ELM_FUN_TABLE_LEN; i++)
	{
		if(g_astHraModuleElmtFunTable[i].init)
		{
			int lRet = g_astHraModuleElmtFunTable[i].init();
			if (HRA_OK != lRet)
			{
				LOG_ERROR("Command %u Moudle init faild, ret = %d.", g_astHraModuleElmtFunTable[i].ulMsgType, lRet);
				//return HRA_FAILED;
			}
		}
	}
	return HRA_OK;
}

/*****************************************************************
* DESCRIPTION: ModuleDeinit
*     模块的统一资源释放函数
* INPUTS:
*     无
* OUTPUTS:
*     无
* RETURNS:
*     无
* CAUTIONS:
*       none
*****************************************************************/
HRA_MODULEINTERFACE_EXPORT int ModuleDeinit(void)
{
	int i;

	for(i = 0; i < HRA_MODULE_ELM_FUN_TABLE_LEN; i++)
	{
		if(g_astHraModuleElmtFunTable[i].deinit)
		{
			int lRet = g_astHraModuleElmtFunTable[i].deinit();
			if (HRA_OK != lRet)
			{
				LOG_WARN("Command %u moudle deinit faild, ret = %d.", g_astHraModuleElmtFunTable[i].ulMsgType, lRet);
				return HRA_FAILED;
			}
            LOG_INFO("ModuleDeinit:%u finished!", g_astHraModuleElmtFunTable[i].ulMsgType);
		}
	}
	return HRA_OK;
}
