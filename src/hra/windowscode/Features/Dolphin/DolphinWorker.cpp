#include "DolphinWorker.h"
#include "utility/comm.h"
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "utility/HraPatternUpdateUtils.h"
#include "utility/HraTaskType.h"
#include "utility/HraReport.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraCtrlCmd.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraTaskType.h"
#include "utility/ConfigSave.h"
#include "HRATaskScheduler/HRATaskScheduler.h"
#include "DolphinCore/DolphinCore.h"
#include "DolphinCore/DolphinNTLMCode.h"
#include "HraIpcInterface/HraIpcCommDef.h"
#include <list>

int g_DolphinModuleWorkStatus = 0;
CPatternUpdateUtils g_DolphinPatternUpdateUtils;
//std::string g_strDolphinDataPath;
std::list<DolphinResult> g_listScanResult;

int DolphinGetModuleWorkStatus()
{
    return g_DolphinModuleWorkStatus;
}

void DolphinSetModuleWorkStatus(int iStat)
{
    g_DolphinModuleWorkStatus = iStat;
}

/// <summary>
/// 检查pattern目录下的pattern是否准备好，如果是zip包则解压
/// </summary>
/// <returns></returns>
int DolphinPreparePattern()
{
    std::string strPatternDir = UtilsGetMetaInfoDir(DOLPHIN_PATTERN_DIR);

    //pattern压缩包已经解压，进程重启的情况
    struct stat stFileStat;
    std::string strPattInfoFile = strPatternDir + PATTERN_INFORMATION;
    std::string strPattDataDir = strPatternDir + PATTERN_DATA_DIR;
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
    LOG_INFO("Find the latest Pattern package and start unpacking.");
    int lRet = UtilsUnzip(strPatternDir + strPackageName);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Unpack the failure.");
    }

    std::string strLocalTime = UtilsGetLocalTime();
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "WpscanPatternUpdateTime", strLocalTime);

    return lRet;
}

/// <summary>
/// 解析管理端下发的扫描指令信息
/// </summary>
/// <param name="stEntry"></param>
/// <param name="jsContect"></param>
/// <returns></returns>
int DolphinCfgParse(DolphinWorkEntry& stEntry, const Json::Value& jsContect)
{
    stEntry.clear();
    if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        //return HRA_BAD_PARAM;
    }
    else
    {
        stEntry.task_id = jsContect["task_id"].asString();
    }

    //passwd_type
    if (!jsContect.isMember("passwd_type"))
    {
        LOG_ERROR("Parse json passwd_type error!");
        return HRA_NOT_FOUND;
    }
    stEntry.iPasswdType = jsContect["passwd_type"].asInt();

    //scan_type
    //if (jsContect.isMember("scan_type"))
    //{
    //    stEntry.iScanType = jsContect["scan_type"].asInt();
    //}

    //scan_category
    if (!jsContect.isMember("scan_category")
        || !jsContect["scan_category"].isArray())
    {
        LOG_ERROR("Parse json scan_category error!");
        return HRA_NOT_FOUND;
    }
    for (unsigned int i = 0; i < jsContect["scan_category"].size(); i++)
    {
        DolphinCategroy stCategroy;
        
        //type
        if (!jsContect["scan_category"][i].isMember("type"))
        {
            continue;
        }
        stCategroy.iType = jsContect["scan_category"][i]["type"].asInt();
        
        //user
        if (jsContect["scan_category"][i].isMember("user")
            && jsContect["scan_category"][i]["user"].isArray())
        {
            for (unsigned int j=0; j< jsContect["scan_category"][i]["user"].size(); ++j)
            {
                stCategroy.setUser.insert(jsContect["scan_category"][i]["user"][j].asCString());
            }
        }

        //password
        if (jsContect["scan_category"][i].isMember("password")
            && jsContect["scan_category"][i]["password"].isArray())
        {
            for (unsigned int j = 0; j < jsContect["scan_category"][i]["password"].size(); ++j)
            {
                stCategroy.setOnlinePasswd.insert(jsContect["scan_category"][i]["password"][j].asCString());
            }
        }

        //port
        if (jsContect["scan_category"][i].isMember("port")
            && jsContect["scan_category"][i]["port"].isArray())
        {
            for (unsigned int j = 0; j < jsContect["scan_category"][i]["port"].size(); ++j)
            {
                stCategroy.setPort.insert(jsContect["scan_category"][i]["port"][j].asInt());
            }
        }

        //pwd_file
        if (jsContect["scan_category"][i].isMember("pwd_file")
            && jsContect["scan_category"][i]["pwd_file"].isArray())
        {
            for (unsigned int j = 0; j < jsContect["scan_category"][i]["pwd_file"].size(); ++j)
            {
                stCategroy.setPasswdFile.insert(jsContect["scan_category"][i]["pwd_file"][j].asCString());
            }
        }

        stEntry.mapScanCategroy.insert(std::map<int, DolphinCategroy>::value_type(stCategroy.iType, stCategroy));
    }

    //解析完成，参数检查，必须有system
    if (stEntry.mapScanCategroy.empty()
        || stEntry.mapScanCategroy.find((int)WPAPP_TYPE_SYSTEM) == stEntry.mapScanCategroy.end())
    {
        LOG_ERROR("Param error! type:%d not found!", (int)WPAPP_TYPE_SYSTEM);
        return HRA_NOT_FOUND;
    }

    return HRA_OK;
}

/// <summary>
/// 具体扫描线程入口函数
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
void* DolphinWorker(void* pArg)
{
    int iRet = HRA_OK;
    std::string strResult;
    DolphinWorkEntry stWorkEntry;
    int iCtrlCmd = (int)HraCtrlCmd::CmdDef::cmd_init;

    LOG_INFO("Dolphin Worker(%d) start.", HRA_ELMT_WP_SACN_CFG);
    do
    {
        if (!pArg)
        {
            LOG_ERROR("Scan work input paramater is null.");
            iRet = HRA_NULL_PTR;
            break;
        }

        std::string strContect = (char*)pArg;
        Json::Value jsValue    = StringToJson(strContect.c_str(), (unsigned int)strContect.length());
        iRet                   = DolphinCfgParse(stWorkEntry, jsValue);
        if (iRet != HRA_OK)
        {
            break;
        }

        if (DolphinGetModuleWorkStatus() == 0)
        {
            LOG_ERROR("Dolphin is not init, can not work.");
            iRet = HRA_NOT_SUPPORTED;
            break;
        }

        //埋点
        iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
        if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
        {
            iRet = HRA_Code::HRA_USER_CANCEL;
            break;
        }

        g_DolphinPatternUpdateUtils.PatternLock(); //加锁
        iRet = DolphinEngineInit(stWorkEntry);
        if (HRA_OK == iRet)
        {
            iRet = DolphinEngineDoScan(stWorkEntry);
        }
        DolphinEngineGenerateResultString(stWorkEntry, strResult);
        DolphinEngineDestory(stWorkEntry);
        g_DolphinPatternUpdateUtils.PatternUnLock(); //解锁

        //埋点
        iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
        if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
        {
            //什么也不做，弱口令扫描扫了一半也需要上报结果
            // iRet = HRA_Code::HRA_USER_CANCEL;
        }
    } while (false);

    DolphinEngineReport(stWorkEntry, iRet, strResult);
    LOG_INFO("Dolphin Worker(%d) end.", HRA_ELMT_WP_SACN_CFG);
    return NULL;
}

/// <summary>
/// 启动扫描任务
/// </summary>
/// <param name="stEntry"></param>
/// <returns></returns>
int DolphinCfgApply(const DolphinWorkEntry& stEntry, const Json::Value& jsContect)
{
    LOG_INFO("Thread add Dolphin Worker start.");

    std::string strContect = jsContect.toStyledString();
    int arraySize = (int)strContect.length() + 1;
    char* pszContect = (char*)malloc(arraySize);
    memset(pszContect, 0, arraySize);
    _snprintf_s(pszContect, arraySize, arraySize - 1, "%s", strContect.c_str());
    //添加到工作队列
    uint64_t nTaskSeq = HraTask_AddWorker(stEntry.task_id.c_str(), HRA_ELMT_WP_SACN_CFG, ProMsgHead::MsgType::NOTIFIER,
                                 DolphinWorker, pszContect, arraySize);
    if (pszContect != NULL)
    {
        free(pszContect);
        pszContect = NULL;
    }

    LOG_INFO("Hra Task add Dolphin Worker end.");
    if (nTaskSeq <= 0)
    {
        LOG_ERROR("Hra Task pool add worker Dolphin failed.");
        return HRA_FAILED;
    }

    return HRA_OK;
}

/// <summary>
/// 从DSA拷贝pattern包到临时目录
/// </summary>
/// <param name="strTmpDir"></param>
/// <param name="strPatternFile"></param>
/// <returns></returns>
int DolphinEngineCopyPatternFromDsa(std::string& strTempDir, const std::string& strPatternFile)
{
    //	获取Pattern所在的文件夹路径
    std::string strPatternPath = UtilsGetMetaInfoDir(DOLPHIN_PATTERN_DIR);
    if (strPatternPath.size() == 0)
    {
        LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
        return HRA_BAD_FILE;
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

    int lRet = g_DolphinPatternUpdateUtils.CopyPatternFromDSA(strTempDir, strPatternFile);
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

/// <summary>
/// pattern更新
/// </summary>
/// <param name="strPatternFile"></param>
/// <param name="strTmpDir"></param>
/// <returns></returns>
int DolphinEnginePatternUpdate(const std::string& strPatternFile, const std::string& strTempDir)
{
    int lRet = HRA_OK;
    std::string strPatternPath;     // pattern文件夹路径
    std::string strTemp;
    //std::string strCmd;
    char szCmd[MAX_COMD_BUFF_LEN] = {0};
    size_t lIndex = 0;
    bool bRet = FALSE;

    if (strPatternFile.size() == 0 || strTempDir.size() == 0)
    {
        LOG_ERROR("Parameter is null");
        lRet = HRA_NULL_PTR;
        goto _out;
    }

    //获取Pattern所在的文件夹路径
    strPatternPath = UtilsGetMetaInfoDir(DOLPHIN_PATTERN_DIR);
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
    bRet = g_DolphinPatternUpdateUtils.VerifyPackageSha256(strTempDir);
    if (bRet != TRUE)
    {
        LOG_ERROR("The file has been modified or corrupted.");
        lRet = HRA_FAILED;
        goto _out;
    }

    DolphinSetModuleWorkStatus(0);
    //	校验成功，将pattern拷到工作目录
    g_DolphinPatternUpdateUtils.PatternLock(); //	加锁
    g_DolphinPatternUpdateUtils.DeleteFileExceptPatternZIP(strPatternPath);
    //strCmd = "xcopy /q /e /y /h " + strTempDir + "*  " + strPatternPath;
    //ExecuteCmd(strCmd.c_str(), NULL);
    //_snprintf_s(szCmd, sizeof(szCmd), "xcopy /q /e /y /h \"%s*\" \"%s\"", strTempDir.c_str(), strPatternPath.c_str());
    //system(szCmd);
    UtilsCopyDirFiles(UtilsStringToUnicode(strTempDir).c_str(), UtilsStringToUnicode(strPatternPath).c_str());
    //	更新版本信息
    UtilsStoreDolphinPatternVersionFromFile(true);
    g_DolphinPatternUpdateUtils.PatternUnLock(); //	解锁
    DolphinSetModuleWorkStatus(1);

_out:
    //	该函数退出时，删除pattern更新的临时目录
    //strCmd = "rmdir /q /s " + strTempDir;
    if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
    {
        LOG_ERROR("RemoveDirectory:%s error!", strTempDir.c_str());
    }
    LOG_INFO("RemoveDirectory:%s succeed!", strTempDir.c_str());

    //删除遗留pattern
    UtilsRemoveOldPattPack(strPatternPath);
    return lRet;
}

/// <summary>
/// 弱口令扫描引擎初始化
/// </summary>
/// <param name="stEntry"></param>
/// <returns></returns>
int DolphinEngineInit(const DolphinWorkEntry& stEntry)
{
    LOG_INFO("DolphinEngineInit start!");
    //检查并创建数据目录
    //std::string strDataPath = UtilsGetWorkPath() + "data\\Dolphin\\";
    //if (!ExecuteCmd(NULL, "IF NOT EXIST %s MD %s", strDataPath.c_str(), strDataPath.c_str()))
    //{
    //    LOG_ERROR("Create dir:%s error!", strDataPath.c_str());
    //    return HRA_FAILED;
    //}
    //g_strDolphinDataPath = strDataPath;

    LOG_INFO("DolphinEngineInit end!");
    return HRA_OK;
}

/// <summary>
/// 弱口令扫描引擎具体扫描任务处理
/// </summary>
/// <returns></returns>
int DolphinEngineDoScan(const DolphinWorkEntry& stEntry)
{
    LOG_INFO("DolphinEngineDoScan start!");
    int ret = HRA_OK;
    std::string strCmdRet;
    //清理原先的结果
    g_listScanResult.clear();
    //wchar_t szCmd[MAX_PATH * 3];

    DolphinCore_FreeResult();
    ret = DolphinCore_DoWorker();

    if (ret == HRA_OK)
    {
        ret = DolphinEngineDoScanSystem(stEntry);
    }

    LOG_INFO("DolphinEngineDoScan end!");
    return ret;
}

/// <summary>
/// 弱口令扫描引擎结束释放
/// </summary>
/// <returns></returns>
int DolphinEngineDestory(const DolphinWorkEntry& stEntry)
{
    ////删除导出的临时文件
    //std::string strSamFile = g_strDolphinDataPath + "sam.hive";
    //if (!ExecuteCmd(NULL, "IF EXIST %s DEL %s", strSamFile.c_str(), strSamFile.c_str()))
    //{
    //    LOG_ERROR("Del file:%s error!", strSamFile.c_str());
    //}
    //std::string strSystemFile = g_strDolphinDataPath + "system.hive";
    //if (!ExecuteCmd(NULL, "IF EXIST %s DEL %s", strSystemFile.c_str(), strSystemFile.c_str()))
    //{
    //    LOG_ERROR("Del file:%s error!", strSystemFile.c_str());
    //}

    return HRA_OK;
}

/// <summary>
/// 上报扫描结果
/// </summary>
/// <param name="stEntry"></param>
/// <returns></returns>
int DolphinEngineReport(const DolphinWorkEntry& stEntry, int iRet, const std::string& strResult)
{
    std::string strRest = GetReportResultInfo(stEntry.task_id.c_str(), iRet, strResult.c_str(), LOG_LEVEL_DEBUG);
    //结果上报
    CReportInfo cReportBaseLineInfo;
    //cReportBaseLineInfo.SetPringLog(false);
    cReportBaseLineInfo.SetCompress(NEED_COMPRESSION);
    cReportBaseLineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, DOLPHIN_RESULT, strRest.c_str(), (unsigned int)strRest.size());
    cReportBaseLineInfo.ShowRspHdr();

    return HRA_OK;
}

/// <summary>
/// 操作系统弱口令匹配
/// </summary>
/// <param name="stEntry"></param>
/// <returns></returns>
int DolphinEngineDoScanSystem(const DolphinWorkEntry& stEntry)
{
    LOG_INFO("DolphinEngineDoScanSystem start!");
    DolphinResult stWpRet;
    char szHexHash[33];
    int iFileLine = 0;
    std::string strPatternPath = UtilsGetMetaInfoDir(DOLPHIN_PATTERN_DIR) + PATTERN_DATA_DIR + "\\";

    const USER_PWD_RESULT* pRstTmp = DolphinCore_GetResult();
    while(pRstTmp != NULL)
    {
        bool bMatch = false;
        std::string strUserName = UtilsUnicodeToString(pRstTmp->stData.user_name);
        std::string strPwdHash  = UtilsUnicodeToString(pRstTmp->stData.pwd_hash);
        LOG_INFO("Check user:%s start", strUserName.c_str());
        LOG_DEBUG("pwd_hash:%s", strPwdHash.c_str());

        //空密码无需匹配直接报弱口令
        if (strPwdHash.empty())
        {
            stWpRet.clear();
            stWpRet.iAppType = (int)WPAPP_TYPE_SYSTEM;
            stWpRet.strUserName = strUserName;
            stWpRet.iPasswdClass = PASSWD_CLASS_EMPTY;
            bMatch = true;
            pRstTmp = pRstTmp->pNext;
            g_listScanResult.push_back(stWpRet);
            LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());
            continue;
        }

        //空字符串加密
        //dolphin_hash_code("", szHexHash);
        dolphin_hash("", szHexHash, sizeof(szHexHash));
        if (strPwdHash == std::string(szHexHash))
        {
            stWpRet.clear();
            stWpRet.iAppType = (int)WPAPP_TYPE_SYSTEM;
            stWpRet.strUserName = strUserName;
            stWpRet.iPasswdClass = PASSWD_CLASS_EMPTY;
            bMatch = true;
            pRstTmp = pRstTmp->pNext;
            g_listScanResult.push_back(stWpRet);
            LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());
            continue;
        }

        //用户名加密，验证密码、用户名是否相等
        dolphin_hash(strUserName.c_str(), szHexHash, sizeof(szHexHash));
        if (strPwdHash == std::string(szHexHash))
        {
            stWpRet.clear();
            stWpRet.iAppType    = (int)WPAPP_TYPE_SYSTEM;
            stWpRet.strUserName = strUserName;
            stWpRet.strPasswd   = strUserName;
            stWpRet.iPasswdClass = PASSWD_CLASS_EQUAL_NAME;
            bMatch              = true;
            pRstTmp             = pRstTmp->pNext;
            g_listScanResult.push_back(stWpRet);
            LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());
            continue;
        }

        //在线编辑密码匹配
        std::map<int, DolphinCategroy>::const_iterator it = stEntry.mapScanCategroy.find((int)WPAPP_TYPE_SYSTEM);
        if (stEntry.mapScanCategroy.end() == it)
        {
            LOG_ERROR("Type:%d not found!", (int)WPAPP_TYPE_SYSTEM);
            return HRA_NOT_FOUND;
        }

        iFileLine = 0;
        for (std::set<std::string>::const_iterator it_online = it->second.setOnlinePasswd.begin();
            it->second.setOnlinePasswd.end() != it_online; ++it_online)
        {
            ++iFileLine;
            //if (dolphin_hash_code(it_online->c_str(), szHexHash) < 0)
            if (dolphin_hash(it_online->c_str(), szHexHash, sizeof(szHexHash)) < 0)
            {
                LOG_WARN("Pwd line error, online line:%d", iFileLine);
                continue;
            }

            if (strPwdHash == std::string(szHexHash))
            {
                stWpRet.clear();
                stWpRet.iAppType = (int)WPAPP_TYPE_SYSTEM;
                stWpRet.strUserName = strUserName;
                stWpRet.strPasswd = it_online->c_str();
                stWpRet.iPasswdClass = PASSWD_CLASS_COMMON;
                bMatch = true;
                g_listScanResult.push_back(stWpRet);
                LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());
                break;
            }
        }
        if (bMatch)
        {
            pRstTmp = pRstTmp->pNext;
            continue;
        }

        //读取密码文件字典
        for (std::set<std::string>::const_iterator it_file = it->second.setPasswdFile.begin();
            it->second.setPasswdFile.end() != it_file; ++it_file)
        {
            std::string strFilePath = strPatternPath + *it_file;
            std::ifstream ifs;
            ifs.open(strFilePath.c_str(), std::ios::in);
            if (!ifs.is_open())
            {
                LOG_WARN("Open file:%s error!", strFilePath.c_str());
                //return HRA_FAILED;
                continue;
            }

            iFileLine = 0;
            std::string strLine;
            while (std::getline(ifs, strLine))
            {
                ++iFileLine;
                //strLine = AiiscToUtf8(strLine.c_str());
                //if (dolphin_hash_code(strLine.c_str(), szHexHash) < 0)
                if (dolphin_hash(strLine.c_str(), szHexHash, sizeof(szHexHash)) < 0)
                {
                    LOG_WARN("Pwd line error, file:%s, line:%d", it_file->c_str(), iFileLine);
                    continue;
                }
                if (strPwdHash == std::string(szHexHash))
                {
                    stWpRet.clear();
                    stWpRet.iAppType = (int)WPAPP_TYPE_SYSTEM;
                    stWpRet.strUserName = strUserName;
                    stWpRet.strPasswd = strLine;
                    stWpRet.iPasswdClass = PASSWD_CLASS_COMMON;
                    bMatch = true;
                    g_listScanResult.push_back(stWpRet);
                    LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());
                    break;
                }
            }
            if (bMatch)
            {
                ifs.close();
                break;
            }
        }

        pRstTmp = pRstTmp->pNext;
    }

    LOG_INFO("DolphinEngineDoScanSystem end!");
    return HRA_OK;
}

/// <summary>
/// 整理结果字符串
/// </summary>
/// <param name="stEntry"></param>
/// <param name="strResult"></param>
/// <returns></returns>
int DolphinEngineGenerateResultString(const DolphinWorkEntry& stEntry, std::string& strResult)
{
    Json::Value root;
    Json::Value arrayObj;
    Json::Value item;
    std::string strPasswd;
    for (std::list<DolphinResult>::const_iterator it = g_listScanResult.begin();
        g_listScanResult.end() != it; ++it)
    {
        item["type"] = it->iAppType;
        item["user"] = it->strUserName;
        strPasswd = it->strPasswd;
        if (stEntry.iPasswdType == (int)PASSWD_TYPE_FUZZ)
        {
            UtilsPasswdFuzz(strPasswd);
        }
        item["passwd"] = strPasswd;
        if (it->iPort >= 0)
        {
            item["port"] = it->iPort;
        }
        item["passwd_class"] = it->iPasswdClass;
        arrayObj.append(item);
    }
    if (!arrayObj.empty())
    {
        root["result"] = arrayObj;
    }
    strResult = JsonToString(root);
    g_listScanResult.clear();
    return HRA_OK;
}

/// <summary>
/// 判断是否在hram下发的用户列表里面
/// </summary>
/// <param name="stEntry"></param>
/// <param name="iAppType"></param>
/// <param name="pszUserName"></param>
/// <returns></returns>
//bool IsInHrmUserList(const DolphinWorkEntry& stEntry, int iAppType, const std::string& strUserName)
//{
//    std::map<int, DolphinCategroy>::const_iterator itType = stEntry.mapScanCategroy.find(iAppType);
//    if (stEntry.mapScanCategroy.end() == itType)
//    {
//        return false;
//    }
//
//    std::set<std::string>::const_iterator itUser = itType->second.setUser.find(strUserName);
//    if (itType->second.setUser.end() == itUser)
//    {
//        return false;
//    }
//
//    return true;
//}