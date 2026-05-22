//#include "Repairation.h"
#include "utility/Logger.h"
#include <time.h>
#include <atomic>
#include "AssetScan.h"
#include "AssetEngineWrapper/AssetEngineWrapper.h"
#include "utility/HraJson.h"
#include "utility/HraUtils.h"
#include "utility/ConfigSave.h"
#include "utility/HraCtrlCmd.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraTaskType.h"
#include "HraIpcInterface/HraIpcCommDef.h"
#include "utility/HraAppDef.h"
#include "utility/HraPatternUpdateUtils.h"

#pragma comment(lib, "Winmm.lib")

std::atomic<char> g_scAssetModuleWork = 1;
CPatternUpdateUtils g_AssetPatternUpdateUtils;

// di_rest_client::Repairation *g_pRepairation=NULL;
// 所有子模块是否扫描标识
const unsigned int g_nAssetScannedCategory = 0x3FFFF;

//计时器句柄
HANDLE g_hTimerQueue      = NULL;
HANDLE g_hTimerQueueTimer = NULL;

// timer回调函数
VOID CALLBACK AssetTimerCallback(PVOID lpParameter, BOOLEAN TimerOrWaitFired)
{
    Json::Value jsCmdJson;
    jsCmdJson["task_id"] = ASSETS_TIMER_TRIGGER_TASK;
    AssetScanAddTask(jsCmdJson);
}

/// <summary>
/// 创建资产扫描定时器
/// 注意：不是立即执行，会延时nReportTime后执行
/// </summary>
/// <param name="nReportTime"></param>
/// <returns></returns>
int AssetScanAddTimer(unsigned int nTimerInterval)
{
    if (nTimerInterval <= 0)
    {
        LOG_ERROR("nTimerInterval:%u error!", nTimerInterval);
        return HRA_BAD_PARAM;
    }

    //创建定时器队列
    if (g_hTimerQueue == NULL)
    {
        g_hTimerQueue = CreateTimerQueue();
        if (NULL == g_hTimerQueue)
        {
            LOG_ERROR("Create Timer Queue failed!");
            return HRA_FAILED;
        }
        LOG_INFO("Create Timer Queue succeed!");
    }

    //更新定时器之前先销毁老的
    if (g_hTimerQueueTimer != NULL)
    {
        if (!DeleteTimerQueueTimer(g_hTimerQueue, g_hTimerQueueTimer, INVALID_HANDLE_VALUE))
        {
            LOG_ERROR("Delete Timer Queue Timer failed!");
            return HRA_FAILED;
        }
        g_hTimerQueueTimer = NULL;
        LOG_INFO("Delete Timer Queue Timer succeed!");
    }

    // 参数说明：计时器句柄，计时器队列句柄，回调函数，回调函数参数，首次执行等待时间，计时周期，线程flag
    DWORD dwTime = nTimerInterval * 1000; // 时间单位：分钟
    if (!CreateTimerQueueTimer(&g_hTimerQueueTimer, g_hTimerQueue, (WAITORTIMERCALLBACK)AssetTimerCallback, NULL,
                               dwTime, dwTime, WT_EXECUTEDEFAULT))
    {
        // g_hTimerQueue = NULL;
        g_hTimerQueueTimer = NULL;
        LOG_ERROR("Create Timer Queue Timer failed!");
        return HRA_FAILED;
    }
    LOG_INFO("Create Timer Queue Timer succeed! Time:%lu", dwTime);

    return HRA_OK;
}

int AssetScanDeleteTimer(void)
{
    //删除计时器队列中的计时器
    if (g_hTimerQueueTimer != NULL)
    {
        //参数说明：计时器队列的句柄，计时器队列中计数器的句柄，函数在返回之前等待任何正在运行的计时器回调函数完成
        if (!DeleteTimerQueueTimer(g_hTimerQueue, g_hTimerQueueTimer, INVALID_HANDLE_VALUE))
        {
            LOG_ERROR("Delete Timer Queue Timer failed!");
            return HRA_FAILED;
        }
        g_hTimerQueueTimer = NULL;
        LOG_INFO("Delete Timer Queue Timer succeed!");
    }

    //删除计时器队列
    if (g_hTimerQueue != NULL)
    {
        //参数说明：计时器队列的句柄，函数在返回之前等待所有回调函数完成
        if (!DeleteTimerQueueEx(g_hTimerQueue, INVALID_HANDLE_VALUE))
        {
            LOG_ERROR("Delete Timer Queue failed!");
            return HRA_FAILED;
        }
        g_hTimerQueue = NULL;
        LOG_INFO("Delete Timer Queue succeed!");
    }
    return HRA_OK;
}

int AssetScanLoadCfg(AssetScanWorkEntry* pstAssetScanWorkEntry)
{
    if (!pstAssetScanWorkEntry)
    {
        LOG_ERROR("pstAssetScanWorkEntry null!");
        return HRA_NULL_PTR;
    }
    pstAssetScanWorkEntry->timer_enable = g_ConfigSave.ConfigSaveGetIntegerValue(ASSETSCAN_CFG_TABLE, "timer_enable");
    pstAssetScanWorkEntry->timer_interval =
        g_ConfigSave.ConfigSaveGetIntegerValue(ASSETSCAN_CFG_TABLE, "timer_interval");
    if (pstAssetScanWorkEntry->timer_interval <= 0)
    {
        pstAssetScanWorkEntry->timer_interval = ASSETS_DEFAULT_TIMER_INTERVAL;
        LOG_WARN("Load config timer_interval error! Set defalut:%u", pstAssetScanWorkEntry->timer_interval);
    }

    return HRA_OK;
}

int AssetScanSaveCfg(const AssetScanWorkEntry& sAssetScanWorkEntry)
{
    g_ConfigSave.ConfigSaveSetIntegerValue(ASSETSCAN_CFG_TABLE, "timer_enable", sAssetScanWorkEntry.timer_enable);
    g_ConfigSave.ConfigSaveSetIntegerValue(ASSETSCAN_CFG_TABLE, "timer_interval", sAssetScanWorkEntry.timer_interval);
    return HRA_OK;
}

int AssetScanReport(const char* pszTaskId, const std::string& strAssetScanResultInfo, int lRet /*, int lScanType*/)
{
    std::string strResultInfo = GetReportResultInfo(pszTaskId, lRet, strAssetScanResultInfo.c_str(), LOG_LEVEL_INFO);

    //结果上报
    CReportInfo cReportAssetInfo;
    cReportAssetInfo.SetCompress(NEED_COMPRESSION);
    cReportAssetInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, ASSET_SCAN_RESULT, strResultInfo.c_str(), (unsigned int)strResultInfo.size());
    cReportAssetInfo.ShowRspHdr();

    return 0;
}

void* AssetScanWorker(void* pArg)
{
    std::string strResult;
    Json::Value jsResult;
    int nRetCode = HRA_FAILED;
    std::string strRetDetail;
    std::string strTaskId;
    //AssetScanWorkEntry sAssetScanWorkEntry;
    //memset(&sAssetScanWorkEntry, 0, sizeof(sAssetScanWorkEntry));
    Json::Value jsCmdParam;

    const char* pszCmdParam = (const char*)pArg;
    if (pszCmdParam == NULL)
    {
        LOG_ERROR("pArg NULL!");
        goto _exit;
    }
    jsCmdParam = StringToJson(pszCmdParam, (unsigned int)strlen(pszCmdParam));

    //解析json
    strTaskId = GetTaskIdFromCmd(jsCmdParam);
    if (_strnicmp(strTaskId.c_str(), ASSETS_VULN_DEPENDENT_TASK, strlen(ASSETS_VULN_DEPENDENT_TASK)) == 0)
    {
        strTaskId = ASSETS_SELF_TRIGGER_TASK;
    }
    else if (_strnicmp(strTaskId.c_str(), ASSETS_TIMER_TRIGGER_TASK, strlen(ASSETS_TIMER_TRIGGER_TASK)) == 0)
    {
        strTaskId = ASSETS_SELF_TRIGGER_TASK;
    }

    //执行扫描开始
    LOG_INFO("asset scan(%d) start.", HRA_ELMT_ASSETS_SCAN_CFG);
    if (!AssetEngineWrapper::getInstance().EngineScan(strResult, pszCmdParam))
    {
        LOG_ERROR("AssetEngineWrapper ExcuteCmd error!");
        goto _exit;
    }
    LOG_INFO("AssetEngineWrapper ExcuteCmd succeed!");

    jsResult = StringToJson(strResult.c_str(), (unsigned int)strResult.length());
    if (!jsResult.isMember("ret_detail") || !jsResult["ret_detail"].isString())
    {
        LOG_ERROR("ret_detail not found!");
        goto _exit;
    }
    strRetDetail = jsResult["ret_detail"].asString();

    if (!jsResult.isMember("ret_code") || !jsResult["ret_code"].isInt())
    {
        LOG_ERROR("ret_code not found!");
        goto _exit;
    }
    nRetCode = jsResult["ret_code"].asInt();

_exit:
    //上报扫描结果
    if (!(strTaskId == ASSETS_SELF_TRIGGER_TASK && strRetDetail.empty()))
    {
        AssetScanReport(strTaskId.c_str(), strRetDetail, nRetCode);
    }
    //执行扫描结束
    LOG_INFO("asset scan(%d) end.", HRA_ELMT_ASSETS_SCAN_CFG);
    return NULL;
}

/// <summary>
/// 像队列添加资产扫描任务
/// </summary>
/// <param name="jsContent"></param>
/// <returns></returns>
uint64_t AssetScanAddTask(const Json::Value& jsContent)
{
    uint64_t nTaskSeq          = 0;
    char* pszCmdJsonTmp        = NULL;
    size_t nCmdJsonSize           = 0;
    std::string strTaskID      = GetTaskIdFromCmd(jsContent);
    std::string strJsonContent = JsonToString(jsContent);
    nCmdJsonSize               = strJsonContent.length() + 1;
    pszCmdJsonTmp              = (char*)malloc(nCmdJsonSize);
    memset(pszCmdJsonTmp, 0, nCmdJsonSize);
    _snprintf_s(pszCmdJsonTmp, nCmdJsonSize, nCmdJsonSize - 1, "%s", strJsonContent.c_str());

    nTaskSeq = HraTask_AddWorker(strTaskID.c_str(), HRA_ELMT_ASSETS_SCAN_CFG, ProMsgHead::MsgType::NOTIFIER,
                                 AssetScanWorker, pszCmdJsonTmp, nCmdJsonSize);
    if (nTaskSeq <= 0)
    {
        LOG_ERROR("Hra Task Add AssetScan Worker failed.");
        goto _exit;
    }
    LOG_INFO("Hra Task Add AssetScan Worker succeed. task_seq:%llu, task_id:%s", nTaskSeq, strTaskID.c_str());

_exit:
    if (pszCmdJsonTmp)
    {
        free(pszCmdJsonTmp);
        pszCmdJsonTmp = NULL;
    }
    return nTaskSeq;
}

int AssetScanCfgParse(AssetScanWorkEntry& sAssetScanWorkEntry, const Json::Value& jsContent)
{
    if (!jsContent.isMember("task_id") || !jsContent["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        //return HRA_BAD_PARAM;
    }
    else
    {
        _snprintf_s(sAssetScanWorkEntry.task_id, sizeof(sAssetScanWorkEntry.task_id), "%s",
                    jsContent["task_id"].asString().c_str());
    }

    if (!jsContent.isMember("service_enable") || !jsContent["service_enable"].isUInt())
    {
        LOG_ERROR("service_enable not found!");
        return HRA_BAD_PARAM;
    }
    sAssetScanWorkEntry.timer_enable = jsContent["service_enable"].asUInt();
    sAssetScanWorkEntry.timer_interval = ASSETS_DEFAULT_TIMER_INTERVAL;

    //if (!jsContent.isMember("report_time") || !jsContent["report_time"].isUInt())
    //{
    //    LOG_ERROR("report_time not found!");
    //    return HRA_BAD_PARAM;
    //}
    //unsigned int nReportTime = jsContent["report_time"].asUInt();
    //if (nReportTime <= 0)
    //{
    //    LOG_ERROR("report_time:%u error!", nReportTime);
    //    return HRA_BAD_PARAM;
    //}
    //sAssetScanWorkEntry.nReportTime = nReportTime;

    return HRA_OK;
}


int AssetScanCfgHandle(const Json::Value& jsContect)
{
    int                       lRet = HRA_OK;
    struct AssetScanWorkEntry stAssetScanWorkEntry;

    //解析
    memset(&stAssetScanWorkEntry, 0, sizeof(struct AssetScanWorkEntry));
    lRet = AssetScanCfgParse(stAssetScanWorkEntry, jsContect);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("AssetScanCfgParse Failed.");
        return lRet;
    }

    //应用
    // LOG_INFO("scan category %u", pstAssetScanWorkEntry->ulScanCategory);
    AssetScanSaveCfg(stAssetScanWorkEntry);

    // 不管是取消定时还是激活定时，都立即增加扫描任务
    uint64_t nTaskSeq = AssetScanAddTask(jsContect);
    if (nTaskSeq <= 0)
    {
        LOG_ERROR("AssetScanAddTask error!");
        return HRA_FAILED;
    }

    // 如果配置是开启，再开定时
    if (stAssetScanWorkEntry.timer_enable == 1)
    {
        lRet = AssetScanAddTimer(stAssetScanWorkEntry.timer_interval);
    }
    else
    {
        lRet = AssetScanDeleteTimer();
    }

    return lRet;
}

int AssetScanInit(void)
{
    //INT     rc;
    //WSADATA wsaData;
    int     iRet = HRA_FAILED;
    bool    bRet  = true;

    ////加载socket库,初始化winsock DLL
    //rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
    //if (rc)
    //{
    //    LOG_ERROR("wss: WSAStartup Failed.");
    //    return HRA_FAILED;
    //}

    //// 加载asset.db文件
    std::string strDataDir     = g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_DATA_DIR);
    std::string strAssetDbPath = strDataDir.append("asset\\asset.db");
    iRet                       = g_AssetDataDB.ConfigSaveInit(strAssetDbPath.c_str());
    if (iRet != HRA_OK)
    {
        LOG_ERROR("Init asset db file failed! file:%s", strAssetDbPath.c_str());
        return HRA_FAILED;
    }

    // 解压最新的pattern压缩包
    LOG_INFO("The Asset module starts to prepare the Pattern file.");
    int ret = AssetPreparePattern();
    if (ret != HRA_OK)
    {
        LOG_ERROR("The Asset failed to decompress the Pattern package.");
        AssetSetModuleWorkStatus(0);
        return HRA_FAILED;
    }

    UtilsStoreAssetPatternVersionFromFile();
    AssetSetModuleWorkStatus(1);

    struct AssetScanWorkEntry stAssetScanWorkEntry;
    ::memset(&stAssetScanWorkEntry, 0, sizeof(struct AssetScanWorkEntry));
    AssetScanLoadCfg(&stAssetScanWorkEntry);
    if (stAssetScanWorkEntry.timer_enable == 1)
    {
        AssetScanAddTimer(stAssetScanWorkEntry.timer_interval);
    }

    return HRA_OK;
}

int AssetScanDestroy(void)
{
    //终止Winsock2 DLL
    //WSACleanup();

    return HRA_OK;
}

int AssetScanCancelInit(void)
{
    return HRA_OK;
}

int AssetScanCancelDestroy(void)
{
    return HRA_OK;
}

int AssetScanCancelHandle(const Json::Value& jsContect)
{
    std::string strResult;
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

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_ASSETS_SCAN_CFG, ProMsgHead::MsgType::NOTIFIER);
    AssetEngineWrapper::getInstance().EngineCancel(strResult, JsonToString(jsContect));

    return HRA_OK;
}

/// <summary>
/// 从指令json串当中获取task_id
/// </summary>
/// <param name="jsContent"></param>
/// <returns></returns>
std::string GetTaskIdFromCmd(const Json::Value& jsContent)
{
    std::string task_id;
    if (!jsContent.isMember("task_id") || !jsContent["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        goto _exit;
    }

    task_id = jsContent["task_id"].asString();
    LOG_DEBUG("Get task_id:%s!", task_id.c_str());

_exit:
    return task_id;
}

/// <summary>
/// 程序初始化时准备pattern
/// </summary>
/// <param name=""></param>
/// <returns></returns>
int AssetPreparePattern(void)
{
    std::string strPatternDir = UtilsGetMetaInfoDir(ASSET_PATTERN_DIR);

    // pattern压缩包已经解压，进程重启的情况
    struct stat stFileStat;
    std::string strPattInfoFile = strPatternDir + PATTERN_INFORMATION;
    std::string strPattDataDir  = strPatternDir + PATTERN_DATA_DIR;
    if (stat(strPattInfoFile.c_str(), &stFileStat) == 0 && stat(strPattDataDir.c_str(), &stFileStat) == 0)
    {
        LOG_INFO("The pattern file already exists.");
        return HRA_OK;
    }

    std::string strPackageName = UtilsFindNewestPattPack(strPatternDir);
    if (strPackageName.size() == 0)
    {
        LOG_ERROR("Failed to find the latest pattern compression package.");
        return HRA_FAILED;
    }

    // 解压
    LOG_INFO("Find the latest Pattern package and start unpacking. %s", strPackageName.c_str());
    int lRet = UtilsUnzip(strPatternDir + strPackageName);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Unpack the failure.");
    }

    std::string strLocalTime = UtilsGetLocalTime();
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "AssetPatternUpdateTime", strLocalTime);
    return lRet;
}

char AssetGetModuleWorkStatus(void)
{
    return g_scAssetModuleWork;
}

void AssetSetModuleWorkStatus(char scAssetModuleWork)
{
    g_scAssetModuleWork = scAssetModuleWork;
}

/// <summary>
/// pattern更新线程调用
/// </summary>
/// <param name="strPatternFile"></param>
/// <param name="strTempDir"></param>
/// <returns></returns>
int AssetPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir)
{
    int lRet = HRA_OK;
    std::string strPatternPath; // pattern文件夹路径
    std::string strTemp;
    // std::string strCmd;
    char szCmd[MAX_COMD_BUFF_LEN] = {0};
    size_t lIndex                 = 0;
    bool bRet                     = FALSE;

    if (strPatternFile.size() == 0 || strTempDir.size() == 0)
    {
        LOG_ERROR("Parameter is null");
        lRet = HRA_NULL_PTR;
        goto _out;
    }

    // 获取Pattern所在的文件夹路径
    strPatternPath = UtilsGetMetaInfoDir(ASSET_PATTERN_DIR);
    if (strPatternPath.size() == 0)
    {
        LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
        lRet = HRA_FAILED;
        goto _out;
    }

    // 在临时文件夹里解压
    lIndex = strPatternFile.rfind("\\");

    if (lIndex != std::string::npos)
    {
        strTemp = strPatternFile.substr(lIndex + 1);
    }
    else
    {
        strTemp = strPatternFile;
    }

    strTemp = strTempDir + strTemp;
    LOG_INFO(" The decompressed file is: %s .", strTemp.c_str());
    lRet = UtilsUnzip(strTemp);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Failed to decompress the Pattern package.");
        goto _out;
    }
    LOG_INFO("Decompressed file %s succeed.", strTemp.c_str());

    // 在临时文件夹中校验sha256值
    bRet = g_AssetPatternUpdateUtils.VerifyPackageSha256(strTempDir);
    if (bRet != TRUE)
    {
        LOG_ERROR("The file has been modified or corrupted.");
        lRet = HRA_FAILED;
        goto _out;
    }

    AssetSetModuleWorkStatus(0);
    //	校验成功，将pattern拷到工作目录
    g_AssetPatternUpdateUtils.PatternLock(); //	加锁
    g_AssetPatternUpdateUtils.DeleteFileExceptPatternZIP(strPatternPath);
    // strCmd = "xcopy /q /e /y /h " + strTempDir + "*  " + strPatternPath;
    // ExecuteCmd(strCmd.c_str(), NULL);
    //_snprintf_s(szCmd, sizeof(szCmd), "xcopy /q /e /y /h \"%s*\" \"%s\"", strTempDir.c_str(), strPatternPath.c_str());
    // system(szCmd);
    UtilsCopyDirFiles(UtilsStringToUnicode(strTempDir).c_str(), UtilsStringToUnicode(strPatternPath).c_str());
    //	更新版本信息
    UtilsStoreAssetPatternVersionFromFile(true);
    g_AssetPatternUpdateUtils.PatternUnLock(); //	解锁
    AssetSetModuleWorkStatus(1);

_out:
    //	该函数退出时，删除pattern更新的临时目录
    // strCmd = "rmdir /q /s " + strTempDir;
    if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
    {
        LOG_ERROR("RemoveDirectory:%s error!", strTempDir.c_str());
    }
    LOG_INFO("RemoveDirectory:%s succeed!", strTempDir.c_str());

    // 删除遗留pattern
    UtilsRemoveOldPattPack(strPatternPath);
    return lRet;
}

/// <summary>
/// 从产品侧拷贝pattern zip包
/// </summary>
/// <param name="strTmpDir"></param>
/// <param name="strPatternFile"></param>
/// <returns></returns>
int AssetCopyPattPack(std::string& strTempDir, const std::string& strPatternFile)
{
    //	获取Pattern所在的文件夹路径
    std::string strPatternPath = UtilsGetMetaInfoDir(ASSET_PATTERN_DIR);
    if (strPatternPath.size() == 0)
    {
        LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
        return HRA_BAD_FILE;
    }

    //	创建临时文件夹用于保存patten，验证通过后再拷贝到对应目录
    // strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetTimestamp() + "\\";
    strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetNanoTimestamp() + "\\";
    if (!CreateDirectoryA(strTempDir.c_str(), NULL))
    {
        LOG_ERROR("CreateDirectory:%s error! Code:%lu", strTempDir.c_str(), GetLastError());
        return HRA_FAILED;
    }
    LOG_INFO("CreateDirectory:%s succeed!", strTempDir.c_str());

    int lRet = g_AssetPatternUpdateUtils.CopyPatternFromDSA(strTempDir, strPatternFile);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Failed to copy pattern package.");
        if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
        {
            LOG_ERROR("RemoveDirectory:%s error!", strTempDir.c_str());
        }
        LOG_INFO("RemoveDirectory:%s succeed!", strTempDir.c_str());
    }

    return lRet;
}
