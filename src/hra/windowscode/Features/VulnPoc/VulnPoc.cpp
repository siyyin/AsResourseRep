#include "VulnPoc.h"
#include "utility/HraAssetDef.h"
#include "utility/HraUtils.h"
#include "utility/Logger.h"
#include "utility/HraPatternUpdateUtils.h"
#include "utility/HraTaskType.h"
#include "utility/HraCtrlCmd.h"
#include "utility/HraReport.h"
#include "utility/ConfigSave.h"
#include "HRATaskScheduler/HRATaskScheduler.h"
#include "HraIpcInterface/HraIpcCommDef.h"
#include "VulnPocEngine.h"
//#include "../AssetScan/AssetScan.h"
#include <algorithm>

//lua脚本支持的操作系统
#define VULN_POC_LUA_OS_TYPE_LINUX 1
#define VULN_POC_LUA_OS_TYPE_WINDOWS 2
#define VULN_POC_LUA_OS_TYPE_LINUX_WINDOWS 3

CPatternUpdateUtils g_VulnPocPatternUpdateUtils;
char g_scVulnPocModuleWork = 1;

int VulnPocInit(void)
{
    //解压最新的pattern压缩包
    LOG_INFO("The VulnPoc module starts to prepare the Pattern file.");
    int ret = VulnPocPreparePattern();
    if (ret != HRA_OK)
    {
        LOG_ERROR("The VulnPoc failed to decompress the Pattern package.");
        goto _err;
    }

    UtilsStoreVulnPocPatternVersionFromFile();

    VulnPocSetModuleWorkStatus(1);
    return HRA_OK;
_err:
    VulnPocSetModuleWorkStatus(0);
    return HRA_FAILED;
}

int VulnPocDestroy(void)
{
    return HRA_OK;
}

int VulnPocCfgHandle(const Json::Value& jsContect)
{
    VulnPocWorkEntry stWorkEntry;
    //解析
    int iRet = VulnPocCfgParse(stWorkEntry, jsContect);
    if (iRet != HRA_OK)
    {
        LOG_ERROR("VulnPocCfgParse Failed!");
        return iRet;
    }

    //应用
    iRet = VulnPocCfgApply(stWorkEntry, jsContect);
    if (HRA_OK != iRet)
    {
        LOG_ERROR("VulnPocCfgApply Failed!");
        return iRet;
    }

    return HRA_OK;
}

int VulnPocCancelInit(void)
{
    return HRA_OK;
}

int VulnPocCancelDestroy(void)
{
    return HRA_OK;
}

int VulnPocCancelHandle(const Json::Value& jsContect)
{
    std::string task_id;
    if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        // return HRA_BAD_PARAM;
    }
    else
    {
        task_id = jsContect["task_id"].asString();
    }

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_VULN_POC_CFG, ProMsgHead::MsgType::NOTIFIER);
    return HRA_OK;
}

/// <summary>
/// 设置、获取pattern工作状态
/// </summary>
/// <param name=""></param>
/// <returns></returns>
char VulnPocGetModuleWorkStatus(void)
{
    return g_scVulnPocModuleWork;
}
void VulnPocSetModuleWorkStatus(char scModuleWork)
{
    g_scVulnPocModuleWork = scModuleWork;
}

/// <summary>
/// 解析指令
/// </summary>
/// <param name="stWorkEntry"></param>
/// <param name="jsContect"></param>
/// <returns></returns>
int VulnPocCfgParse(VulnPocWorkEntry& stWorkEntry, const Json::Value& jsContect)
{
    stWorkEntry.clear();

    // hra添加信息pre_task_seq
    if (jsContect.isMember("pre_task_seq") && jsContect["pre_task_seq"].isUInt64())
    {
        stWorkEntry.pre_task_seq = jsContect["pre_task_seq"].asUInt64();
        LOG_INFO("Get pre_task_seq:%llu", stWorkEntry.pre_task_seq);
    }

    // task_id
    if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        // return HRA_BAD_PARAM;
    }
    else
    {
        stWorkEntry.task_id = jsContect["task_id"].asString();
    }

    // scan_items
    if (!jsContect.isMember("scan_items") || !jsContect["scan_items"].isArray())
    {
        LOG_ERROR("There is no scan_items array object in Json data.");
        return HRA_NOT_FOUND;
    }
    const Json::Value jsArrayObj = jsContect["scan_items"];
    for (int i = 0; i < (int)jsArrayObj.size(); ++i)
    {
        VulnPocScanItem stItemTmp;
        // scan_id
        if (!jsArrayObj[i].isMember("scan_id") || !jsArrayObj[i]["scan_id"].isInt())
        {
            LOG_ERROR("There is no scan_id int object in Json data.");
            return HRA_NOT_FOUND;
        }
        stItemTmp.scan_id = jsArrayObj[i]["scan_id"].asInt();

        stWorkEntry.scan_items.push_back(stItemTmp);
    }

    if (stWorkEntry.scan_items.empty())
    {
        LOG_ERROR("Param error! scan_items empty!");
        return HRA_BAD_PARAM;
    }

    LOG_INFO("Parse json parameter finish.");
    return HRA_OK;
}

/// <summary>
/// 将任务添加到队列
/// </summary>
/// <param name="stWorkEntry"></param>
/// <param name="jsContect"></param>
/// <returns></returns>
int VulnPocCfgApply(const VulnPocWorkEntry& stWorkEntry, const Json::Value& jsContect)
{
    //int lRet = HRA_OK;
    LOG_INFO("[HRA] Thread add VulnPoc Worker start.");

    std::string strContect = jsContect.toStyledString();
    int iSize              = (int)strContect.length() + 1;
    char* pszParam         = (char*)malloc(iSize);
    if (!pszParam)
    {
        LOG_ERROR("malloc error!");
        return HRA_MALLOC_FAIL;
    }
    memset(pszParam, 0, iSize);
    strncpy_s(pszParam, iSize, strContect.c_str(), strContect.length());

    //添加到工作队列
    uint64_t nVulnPocSeq =
        HraTask_AddWorker(stWorkEntry.task_id.c_str(), HRA_ELMT_VULN_POC_CFG, ProMsgHead::MsgType::NOTIFIER,
                          VulnPocWorker, pszParam, iSize, stWorkEntry.pre_task_seq);

    LOG_INFO("Hra Task add VulnPoc Worker end.");
    if (pszParam)
    {
        free(pszParam);
        pszParam = NULL;
    }

    if (nVulnPocSeq <= 0)
    {
        LOG_ERROR("Hra Task pool add worker failed.");
        return HRA_FAILED;
    }

    return HRA_OK;
}

/// <summary>
/// POC检测线程工作函数入口
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
void* VulnPocWorker(void* pArg)
{
    int lRet     = HRA_OK;
    int iCtrlCmd = HraCtrlCmd::CmdDef::cmd_init;
    Json::Value jsScanResults;
    VulnPocWorkEntry workEntry;
    std::string strContect;
    Json::Value jsScanRet;
    Json::Value jsValue; 
    Json::Value jsRetDetail;
    
    LOG_INFO("VulnPoc Worker(%d) start.", HRA_ELMT_VULN_POC_CFG);
    //加锁
    g_VulnPocPatternUpdateUtils.PatternLock(); 

    if (!pArg)
    {
        LOG_ERROR("Baseline work input paramater is null.");
        lRet = HRA_Code::HRA_NULL_PTR;
        goto _exit;
    }

    //解析指令
    strContect = (char*)pArg;
    jsValue    = StringToJson(strContect.c_str(), (unsigned int)strContect.length());
    lRet       = VulnPocCfgParse(workEntry, jsValue);
    if (lRet != HRA_OK)
    {
        goto _exit;
    }

    if (VulnPocGetModuleWorkStatus() == 0)
    {
        LOG_ERROR("VulnPoc is not init, can not work.");
        lRet = HRA_COND_CHK_FAIL;
        goto _exit;
    }

    //埋点
    iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
    if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
    {
        lRet = HRA_Code::HRA_USER_CANCEL;
        goto _exit;
    }

    //加载json
    lRet = VulnPocParseJsonPattern(workEntry);
    if (lRet != HRA_OK)
    {
        LOG_ERROR("The Baseline failed to parse the Pattern file.");
        goto _exit;
    }

    //执行扫描
    for (std::vector<VulnPocScanItem>::const_iterator it = workEntry.scan_items.begin();
         workEntry.scan_items.end() != it; ++it)
    {
        // 埋点
        iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
        if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
        {
            lRet = HRA_Code::HRA_USER_CANCEL;
            goto _exit;
        }

        //执行单个扫描
        int nLuaRet = 0;
        std::string strRetDetail;
        lRet = VulnPocLuaScan(nLuaRet, strRetDetail, *it);
        if (lRet != HRA_OK)
        {
            LOG_ERROR("VulnPocLuaScan error!");
            if (nLuaRet >= 0)
            {
                nLuaRet = VULN_POC_RET_DEFAULT_ERROR;
            }
            lRet = HRA_OK;
            //goto _exit;
        }

        //将RetDetail转换为json object
        jsRetDetail.clear();
        if (!strRetDetail.empty())
        {
            jsRetDetail = StringToJson(strRetDetail.c_str(), strRetDetail.length());
            if (jsRetDetail.isNull())
            {
                LOG_ERROR("Parse RetDetail error!");
                if (nLuaRet >= 0)
                {
                    nLuaRet = VULN_POC_RET_DEFAULT_ERROR;
                }
                //lRet = HRA_DATA_PARSE_FAIL;
                //goto _exit;
            }
        }

        jsScanRet.clear();
        jsScanRet["scan_id"]    = it->scan_id;
        jsScanRet["vuln_type"]  = it->vuln_type;
        jsScanRet["ret_code"]   = nLuaRet;
        jsScanRet["ret_detail"] = jsRetDetail;
        jsScanResults.append(jsScanRet);
    }

_exit:
    //解锁
    g_VulnPocPatternUpdateUtils.PatternUnLock(); 

    if (jsScanResults.empty())
    {
        jsScanResults.resize(0);
    }
    Json::Value jsResult;
    jsResult["result"]        = jsScanResults;
    std::string strScanResult = JsonToString(jsResult);
    LOG_DEBUG("VulnPoc scan result:%s", strScanResult.c_str());
    VulnPocReport(workEntry.task_id.c_str(), lRet, strScanResult);
    LOG_INFO("VulnPoc Worker(%d) end.", HRA_ELMT_VULN_POC_CFG);
    return NULL;
}

/// <summary>
/// Poc漏扫结果上报
/// </summary>
/// <param name="pscTaskId"></param>
/// <param name="lRet"></param>
/// <param name="strScanResult"></param>
/// <returns></returns>
int VulnPocReport(const char* pscTaskId, int lRet, const std::string& strScanResult)
{
    std::string strResultInfo = GetReportResultInfo(pscTaskId, lRet, strScanResult.c_str(), LOG_LEVEL_INFO);

    //结果上报
    CReportInfo cReportBaseLineInfo;
    cReportBaseLineInfo.SetCompress(NEED_COMPRESSION);
    cReportBaseLineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, VULN_POC_RESULT, strResultInfo.c_str(),
                                strResultInfo.size());

    return HRA_OK;
}

/// <summary>
/// 解析vuln_poc.json
/// </summary>
/// <param name="entry"></param>
/// <returns></returns>
int VulnPocParseJsonPattern(VulnPocWorkEntry& entry)
{
    std::string strWorkPath    = UtilsGetWorkPath();
    std::string strPatternPath = UtilsGetVulnPocPatternVersionPath();
    if (strPatternPath.empty())
    {
        LOG_ERROR("VulnPoc pattern path empty!");
        return HRA_FAILED;
    }
    std::string strPatternVersion = UtilsGetVulnPocPatternVersion();
    if (strPatternVersion.empty())
    {
        LOG_ERROR("VulnPoc pattern version empty!");
        return HRA_FAILED;
    }

    //读文件
    std::string strJsonPattern = UtilsFileDecryption(strPatternPath);
    if (strJsonPattern.empty())
    {
        LOG_ERROR("Read VulnPoc pattern failed! file:%s", strPatternPath.c_str());
        return HRA_FAILED;
    }

    Json::Value jsPattern = StringToJson(strJsonPattern.c_str(), (int)strJsonPattern.length());
    if (jsPattern.empty())
    {
        LOG_ERROR("StringToJson error! file:%s, content:%s", strPatternPath.c_str(), strJsonPattern.c_str());
        return HRA_FAILED;
    }

    if (!jsPattern.isMember("scan_items") || !jsPattern["scan_items"].isArray())
    {
        LOG_ERROR("There is no scan_items array in json! file:%s", strPatternPath.c_str());
        return HRA_FAILED;
    }

    for (int i = 0; i < (int)jsPattern["scan_items"].size(); ++i)
    {
        Json::Value jsIterm = jsPattern["scan_items"][i];

        // os_type
        if (!jsIterm.isMember("os_type") || !jsIterm["os_type"].isInt())
        {
            LOG_ERROR("There is no os_type string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        int tmp_os_type = jsIterm["os_type"].asInt();

        // scan_id
        if (!jsIterm.isMember("scan_id") || !jsIterm["scan_id"].isInt())
        {
            LOG_ERROR("There is no scan_id string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        int tmp_scan_id = jsIterm["scan_id"].asInt();

        // cve_id
        if (!jsIterm.isMember("cve_id") || !jsIterm["cve_id"].isString())
        {
            LOG_ERROR("There is no cve_id string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        std::string tmp_cve_id = jsIterm["cve_id"].asString();

        // vuln_type
        if (!jsIterm.isMember("vuln_type") || !jsIterm["vuln_type"].isInt())
        {
            LOG_ERROR("There is no vuln_type string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        int tmp_vuln_type = jsIterm["vuln_type"].asInt();

        // scan_script
        if (!jsIterm.isMember("scan_script") || !jsIterm["scan_script"].isString())
        {
            LOG_ERROR("There is no scan_script string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        std::string tmp_scan_script = strWorkPath + VULNPOC_PATTERN_DIR + jsIterm["scan_script"].asString();
        std::replace(tmp_scan_script.begin(), tmp_scan_script.end(), '/', '\\');


        //填充entry
        for (std::vector<VulnPocScanItem>::iterator it = entry.scan_items.begin(); entry.scan_items.end() != it; ++it)
        {
            if (it->scan_id == tmp_scan_id)
            {
                it->cve_id      = tmp_cve_id;
                it->os_type     = tmp_os_type;
                it->vuln_type   = tmp_vuln_type;
                it->scan_script = tmp_scan_script + "$" + strPatternVersion;
            }
        }
    }

    return HRA_OK;
}

/// <summary>
/// 执行lua扫描
/// </summary>
/// <param name="nRetCode"></param>
/// <param name="strDetail"></param>
/// <param name="entry"></param>
/// <returns></returns>
int VulnPocLuaScan(int& nRetCode, std::string& strRetDetail, const VulnPocScanItem& stScanItem)
{
    if (stScanItem.os_type != VULN_POC_LUA_OS_TYPE_WINDOWS && stScanItem.os_type != VULN_POC_LUA_OS_TYPE_LINUX_WINDOWS)
    {
        nRetCode = VULN_POC_RET_UNINVOLVED;
        strRetDetail.clear();
        LOG_WARN("OS not support! scan_id:%d, path:%s", stScanItem.scan_id, stScanItem.scan_script.c_str());
        return HRA_OK;
    }

    return VulnPocExecuteScan(nRetCode, strRetDetail, stScanItem.scan_script);
}

/// <summary>
/// 启动时检查pattern是否解压，未解压搜索最新的解压
/// </summary>
/// <param name=""></param>
/// <returns></returns>
int VulnPocPreparePattern(void)
{
    std::string strPatternDir = UtilsGetMetaInfoDir(VULNPOC_PATTERN_DIR);

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

    //解压
    LOG_INFO("Find the latest Pattern package and start unpacking. %s", strPackageName.c_str());
    int lRet = UtilsUnzip(strPatternDir + strPackageName);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Unpack the failure.");
    }

    std::string strLocalTime = UtilsGetLocalTime();
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "VulnPocPatternUpdateTime", strLocalTime);
    return lRet;
}

/// <summary>
/// 将pattern文件拷贝到临时目录
/// </summary>
/// <param name="strTempDir"></param>
/// <param name="strPatternFile"></param>
/// <returns></returns>
int VulnPocCopyPattPack(std::string& strTempDir, const std::string& strPatternFile)
{
    //	获取Pattern所在的文件夹路径
    std::string strPatternPath = UtilsGetMetaInfoDir(VULNPOC_PATTERN_DIR);
    if (strPatternPath.size() == 0)
    {
        LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
        return HRA_FAILED;
    }

    //	创建临时文件夹用于保存patten，验证通过后再拷贝到对应目录
    //strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetTimestamp() + "\\";
    strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetNanoTimestamp() + "\\";
    if (!CreateDirectoryA(strTempDir.c_str(), NULL))
    {
        LOG_ERROR("CreateDirectory:%s error! Code:%lu", strTempDir.c_str(), GetLastError());
        return HRA_FAILED;
    }
    LOG_INFO("CreateDirectory:%s succeed!", strTempDir.c_str());

    int lRet = g_VulnPocPatternUpdateUtils.CopyPatternFromDSA(strTempDir, strPatternFile);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Failed to copy pattern package.");
        if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
        {
            LOG_ERROR("UtilsRemoveDirectory:%s error!", strTempDir.c_str());
        }
        LOG_INFO("UtilsRemoveDirectory:%s succeed!", strTempDir.c_str());
        return lRet;
    }

    return lRet;
}

/// <summary>
/// pattern更新线程调用
/// </summary>
/// <param name="strPatternFile"></param>
/// <param name="strTempDir"></param>
/// <returns></returns>
int VulnPocPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir)
{
    int lRet = HRA_OK;
    std::string strPatternPath; // pattern文件夹路径
    std::string strTemp;
    // std::string strCmd;
    char szCmd[MAX_COMD_BUFF_LEN] = {0};
    int lIndex                    = 0;
    bool bRet                     = FALSE;
    VulnPocWorkEntry entry;

    if (strPatternFile.size() == 0 || strTempDir.size() == 0)
    {
        LOG_ERROR("Parameter is null");
        lRet = HRA_NULL_PTR;
        goto _out;
    }

    //获取Pattern所在的文件夹路径
    strPatternPath = UtilsGetMetaInfoDir(VULNPOC_PATTERN_DIR);
    if (strPatternPath.size() == 0)
    {
        LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
        lRet = HRA_FAILED;
        goto _out;
    }

    //在临时文件夹里解压
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

    //在临时文件夹中校验sha256值
    bRet = g_VulnPocPatternUpdateUtils.VerifyPackageSha256(strTempDir);
    if (bRet != TRUE)
    {
        LOG_ERROR("The file has been modified or corrupted.");
        lRet = HRA_FAILED;
        goto _out;
    }

    //	校验成功，将pattern拷到工作目录
    g_VulnPocPatternUpdateUtils.PatternLock(); //	加锁
    g_VulnPocPatternUpdateUtils.DeleteFileExceptPatternZIP(strPatternPath);
    UtilsCopyDirFiles(UtilsStringToUnicode(strTempDir).c_str(), UtilsStringToUnicode(strPatternPath).c_str());

    //	更新版本信息
    UtilsStoreVulnPocPatternVersionFromFile(true);
    //	测试引擎加载情况
    lRet = VulnPocParseJsonPattern(entry);
    if (lRet != HRA_OK)
    {
        LOG_ERROR("The VulnPoc failed to parse the Pattern file.");
        VulnPocSetModuleWorkStatus(0);
        g_VulnPocPatternUpdateUtils.PatternUnLock(); //	解锁
        goto _out;
    }
    else
    {
        VulnPocSetModuleWorkStatus(1);
    }

    g_VulnPocPatternUpdateUtils.PatternUnLock(); //	解锁

_out:
    //	该函数退出时，删除pattern更新的临时目录
    if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
    {
        LOG_ERROR("Delete %s error!", strTempDir.c_str());
    }
    else
    {
        LOG_INFO("Delete %s succeed!", strTempDir.c_str());
    }

    // 删除遗留pattern
    UtilsRemoveOldPattPack(strPatternPath);
    return lRet;
}