#include "Dolphin.h"
#include "utility/comm.h"
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
#include "HRATaskScheduler/HRATaskScheduler.h"
#include "DolphinWorker.h"
#include "HraIpcInterface/HraIpcCommDef.h"

/// <summary>
/// 初始化弱口令扫描
/// </summary>
/// <returns></returns>
int DolphinInit()
{
    DolphinSetModuleWorkStatus(0);
    //解压最新的pattern压缩包
    LOG_INFO("The Dolphin module starts to prepare the Pattern file.");
    int lRet = DolphinPreparePattern();
    if (lRet != HRA_OK)
    {
        LOG_ERROR("The Dolphin failed to decompress the Pattern package.");
        return lRet;
    }

    UtilsStoreDolphinPatternVersionFromFile();
    DolphinSetModuleWorkStatus(1);

    return HRA_OK;
}

/// <summary>
/// 弱口令扫描结束释放
/// </summary>
/// <returns></returns>
int DolphinDestroy()
{
    return HRA_OK;
}

/// <summary>
/// 弱口令扫描指令执行
/// </summary>
/// <param name="jsContect"></param>
/// <returns></returns>
int DolphinCfgHandle(const Json::Value& jsContect)
{
    //if (DolphinGetModuleWorkStatus() == 0)
    //{
    //    LOG_ERROR("Dolphin is not init, can not work.");
    //    return HRA_NOT_SUPPORTED;
    //}

    DolphinWorkEntry stDolphinWorkEntry;
    int lRet = DolphinCfgParse(stDolphinWorkEntry, jsContect);
    if (lRet != HRA_OK)
    {
        LOG_ERROR("DolphinCfgParse error!");
        return lRet;
    }

    lRet = DolphinCfgApply(stDolphinWorkEntry, jsContect);
    if (lRet != HRA_OK)
    {
        LOG_ERROR("DolphinCfgApply error!");
        return lRet;
    }

    return HRA_OK;
}

/// <summary>
/// pattern更新
/// </summary>
/// <param name="strPatternFile"></param>
/// <param name="strTempDir"></param>
/// <returns></returns>
int DolphinPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir)
{
    return DolphinEnginePatternUpdate(strPatternFile, strTempDir);
}

/// <summary>
/// 从DSA拷贝pattern包到临时目录
/// </summary>
/// <param name="strTmpDir"></param>
/// <param name="strPatternFile"></param>
/// <returns></returns>
int DolphinCopyPattPack(std::string& strTmpDir, const std::string& strPatternFile)
{
    return DolphinEngineCopyPatternFromDsa(strTmpDir, strPatternFile);
}

int DolphinCancelInit()
{
    return HRA_OK;
}

int DolphinCancelDestroy()
{
    return HRA_OK;
}

int DolphinCancelHandle(const Json::Value& jsContect)
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

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_WP_SACN_CFG, ProMsgHead::MsgType::NOTIFIER);
    return HRA_OK;
}