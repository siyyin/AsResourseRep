#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "AppScan.h"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
#include "utility/Logger.h"
#include "utility/HraCtrlCmd.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraTaskType.h"
#include "HraIpcInterface/HraIpcCommDef.h"
#include "AppInfo.h"

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描工作函数. </summary>
///
/// <remarks>	, 2022/1/4. </remarks>
///
/// <param name="pArg">	[in,out] If non-null, the argument. </param>
///
/// <returns>	Null if it fails, else a pointer to a void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void *AppScanWorker(void *pArg)
{
	int lRet = HRA_OK;
	std::string strScanResult = "";
	struct AppScanWorkEntry *pstAppScanWorkEntry = NULL;

	if(!pArg)
	{
		return NULL;
	}

    //执行扫描开始
    LOG_INFO("App scan(%d) start.", HRA_ELMT_APP_SCAN_CFG);

	pstAppScanWorkEntry = (struct AppScanWorkEntry *)pArg;

    //埋点
    int iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
    if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
    {
        lRet = HRA_Code::HRA_USER_CANCEL;
    }
    else
    {
        //执行扫描
        AppInfo* pAppInfo = new AppInfo();
        if (pAppInfo)
        {
            strScanResult = pAppInfo->GetAppInfo();
            delete pAppInfo;
            pAppInfo = NULL;
        }
        else
        {
            LOG_ERROR("AppInfo new error!");
            lRet = HRA_Code::HRA_FAILED;
        }
    }

    //埋点
    //如果取消则上报取消，让管理端丢弃数据
    iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
    if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
    {
        lRet = HRA_Code::HRA_USER_CANCEL;
    }

    LOG_INFO("Get report result info start, size %u!", (unsigned int)(strScanResult.size()));
    std::string strResultInfo =
        GetReportResultInfo(pstAppScanWorkEntry->ascTaskId, lRet, strScanResult.c_str(), LOG_LEVEL_INFO);

	//结果上报
	CReportInfo cReportAppInfo;
	cReportAppInfo.SetCompress(NEED_COMPRESSION);
	cReportAppInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, APP_SCAN_RESULT, strResultInfo.c_str(), strResultInfo.size());
	cReportAppInfo.ShowRspHdr();

    //执行扫描开始
    LOG_INFO("App scan(%d) end.", HRA_ELMT_APP_SCAN_CFG);

	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描配置解析函数. </summary>
///
/// <remarks>	, 2022/1/4. </remarks>
///
/// <param name="pstAppScanWorkEntry">	[out] 配置存储结构体. </param>
/// <param name="jsContect">		  	The js contect. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int AppScanCfgParse(struct AppScanWorkEntry *pstAppScanWorkEntry,const Json::Value& jsContect)
{
	if (!pstAppScanWorkEntry)
	{
		LOG_ERROR("Work entry is null.");
		return HRA_NULL_PTR;
	}

    // hra添加信息pre_task_seq
    if (jsContect.isMember("pre_task_seq") && jsContect["pre_task_seq"].isUInt64())
    {
        pstAppScanWorkEntry->pre_task_seq = jsContect["pre_task_seq"].asUInt64();
        LOG_INFO("Get pre_task_seq:%llu", pstAppScanWorkEntry->pre_task_seq);
    }

	if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        //return HRA_BAD_PARAM;
    }
    else
    {
        _snprintf_s(pstAppScanWorkEntry->ascTaskId, sizeof(pstAppScanWorkEntry->ascTaskId), "%s",
                    jsContect["task_id"].asString().c_str());
    }

	//if (jsContect.isMember("scan_type"))
	//{
 //       int lScanType = jsContect["scan_type"].asInt();
 //       pstAppScanWorkEntry->lScanType = lScanType;
	//}

	//std::string strTaskid = jsContect["task_id"].asCString();
	//int lCopyLen = strTaskid.size();
	//if (lCopyLen > APPSCAN_TASK_ID_MAX_LEN - 1)
	//{
	//	LOG_ERROR("Support task id max len %d, current len is %d.", APPSCAN_TASK_ID_MAX_LEN - 1, lCopyLen);
	//	return HRA_BAD_PARAM;
	//}
	//memcpy(pstAppScanWorkEntry->ascTaskId, strTaskid.c_str(), lCopyLen);

    LOG_INFO("Parse json parameter finish.");
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描配置应用函数. </summary>
///
/// <remarks>	, 2022/1/4. </remarks>
///
/// <param name="pstAppScanWork">	[in] 配置存储结构体. </param>
///
/// <returns>	
///      0  : success
///      -1 : failed
///	     -2 : Null pointer
///	     -3 : Parameter Error. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int AppScanCfgApply(struct AppScanWorkEntry *pstAppScanWork)
{
	if (!pstAppScanWork)
	{
		LOG_ERROR("App scan work entry is null.");
		return HRA_NULL_PTR;
	}

	LOG_INFO("Thread add AppScan Worker start.");

	//添加到工作队列
    uint64_t nTaskSeq = HraTask_AddWorker(pstAppScanWork->ascTaskId, HRA_ELMT_APP_SCAN_CFG, ProMsgHead::MsgType::NOTIFIER,
                          AppScanWorker, pstAppScanWork, sizeof(struct AppScanWorkEntry), pstAppScanWork->pre_task_seq);

    LOG_INFO("Hra Task add AppScan Worker end.");
    if (nTaskSeq <= 0)
	{
		LOG_ERROR("Hra Task pool add worker failed .");
		return HRA_FAILED;
	}

	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描初始化函数. </summary>
///
/// <remarks>	, 2022/1/4. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int AppScanInit(void)
{
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描去初始化函数. </summary>
///
/// <remarks>	, 2022/1/4. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int AppScanDestroy(void)
{
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	对外暴露的配置处理函数. </summary>
///
/// <remarks>	, 2022/1/4. </remarks>
///
/// <param name="jsContect">	The js contect. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int AppScanCfgHandle(const Json::Value& jsContect)
{
	int lRet = HRA_OK;
	struct AppScanWorkEntry stAppScanWorkEntry;
	//解析
	memset(&stAppScanWorkEntry, 0, sizeof(struct AppScanWorkEntry));
    //stAppScanWorkEntry.lScanType = -1;

	lRet = AppScanCfgParse(&stAppScanWorkEntry, jsContect);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("AppScanCfgParse Failed.");
		goto _out;
	}
	//应用
	lRet = AppScanCfgApply(&stAppScanWorkEntry);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("AppScanCfgApply Failed.");
		goto _out;
	}

_out:
	return lRet;
}


int AppScanCancelInit(void)
{
    return HRA_OK;
}

int AppScanCancelDestroy(void)
{
    return HRA_OK;
}

int AppScanCancelHandle(const Json::Value& jsContect)
{
    std::string task_id;
    if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        //return HRA_BAD_PARAM;
    }
    else
    {
        task_id = jsContect["task_id"].asString();
    }

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_APP_SCAN_CFG, ProMsgHead::MsgType::NOTIFIER);
    return HRA_OK;
}