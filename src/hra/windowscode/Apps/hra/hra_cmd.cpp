#include "stdafx.h"
#include <string>
#include <Windows.h>

#include "hra_cmd.h"
#include "utility/HraUtils.h"
#include "utility/Logger.h"
#include "utility/ConfigSave.h"
#include "utility/HraJson.h"
#include "utility/HraTaskType.h"
#include "HraInstall/InstallUtility.h"
#include "HraIpcInterface/HraIpcClient.h"
#include "HraIpcInterface/HraIpcServer.h"


#define HRA_CMD_PARAM_FEATURE L"feature"   // 扫描命令、取消命令等
#define HRA_CMD_PARAM_PATTERN L"pattern"   // pattern更新命令
#define HRA_CMD_PARAM_CMD_JSON L"cmd_json" // 透传的json指令
#define HRA_CMD_PARAM_CMD_FILE L"cmd_file" // 透传的json指令文件

//判断是否log指令
bool is_cmd_log(const char* pCmdJson)
{
    Json::Value jsCmdJson = StringToJson(pCmdJson, strlen(pCmdJson));
    if (!jsCmdJson.isMember("cmd_data") || !jsCmdJson["cmd_data"].isArray())
    {
        LOG_ERROR("cmd_data not found!");
        return false;
    }
    if (jsCmdJson["cmd_data"].size() != 1)
    {
        LOG_ERROR("cmd_data size error! %d", (int)jsCmdJson["cmd_data"].size());
        return false;
    }
    Json::Value jsLogInfo = jsCmdJson["cmd_data"][0];
    if (!jsLogInfo.isMember("command_type") || !jsLogInfo["command_type"].isInt())
    {
        LOG_ERROR("command_type not found!");
        return false;
    }
    int nCmdType = jsLogInfo["command_type"].asInt();
    if (nCmdType != HRA_ELMT_LOG_LEVEL_CMD)
    {
        LOG_ERROR("command_type error! %d", nCmdType);
        return false;
    }

    return true;
}

int ReadCmdFile(const std::string& strFilePath, std::string& strFileContent)
{
    int ret  = HRA_OK;
    FILE* fp = NULL;
    ret      = fopen_s(&fp, strFilePath.c_str(), "r");
    if (fp == NULL)
    {
        LOG_ERROR("Open file(%s) error!", strFilePath.c_str());
        return HRA_OPEN_FAIL;
    }

    strFileContent.clear();
    int iStrLen = 0;
    while (!feof(fp))
    {
        char szTmp[1024];
        memset(szTmp, 0, sizeof(szTmp));
        if (fgets(szTmp, sizeof(szTmp), fp) == NULL && errno != 0)
        {
            char szError[1024] = {0};
            strerror_s(szError, sizeof(szError), errno);
            LOG_ERROR("Read file(%s) error! %s", strFilePath.c_str(), szError);
            ret = HRA_BAD_FILE;
            break;
        }

        strFileContent += szTmp;
    }
    fclose(fp);

    if (ret == HRA_OK)
    {
        LOG_INFO("Read file(%s) succeed!", strFilePath.c_str());
    }
    return ret;
}

int SendCmdToHra(ProMsgHead::MsgType nReqType, const char* pHraIpcName, const char* pCmdJson)
{
    if (!pCmdJson)
    {
        LOG_ERROR("pCmdJson NULL!");
        return -1;
    }

    /////////////////////////////////////////////////// 暂时只允许日志
    if (nReqType != ProMsgHead::MsgType::NOTIFIER)
    {
        LOG_ERROR("MsgType:%d error!", (int)nReqType);
        return -1;
    }
    if (!is_cmd_log(pCmdJson))
    {
        LOG_ERROR("Not log cmd!");
        return -1;
    }
    /////////////////////////////////////////////////// 暂时只允许日志

    char szOutBuff[1024];
    memset(szOutBuff, 0, sizeof(szOutBuff));
    ProMsgHead sHead;
    memset(&sHead, 0, sizeof(sHead));
    sHead.emMsgType = nReqType;
    sHead.nSeq      = 1;
    sHead.nVersion  = HRA_IPC_INTERFACE_VERSION;
    sHead.nDataLen  = (unsigned int)strlen(pCmdJson);

    int nSendDatLen          = sizeof(sHead) + sHead.nDataLen;
    unsigned char* pSendData = (unsigned char*)malloc(nSendDatLen + 1);
    memset(pSendData, 0, nSendDatLen + 1);
    memcpy(pSendData, &sHead, sizeof(sHead));
    memcpy(pSendData + sizeof(sHead), pCmdJson, sHead.nDataLen);
    LOG_INFO("cmd_json:\n%s", pCmdJson);
    int ret = HraIpcSendMsg(pHraIpcName, HRA_CMD_HANDLE, pSendData, nSendDatLen, (unsigned char*)szOutBuff,
                            sizeof(szOutBuff) - 1);
    if (ret == 0)
    {
        LOG_INFO("Send cmd succeed!");
    }
    else
    {
        LOG_ERROR("Send cmd error! %d", ret);
    }
    free(pSendData);
    return ret;
}

int hra_cmd_run(int argc, wchar_t* argv[])
{
    // 设置工作目录
    wchar_t szPath[MAX_PATH];
    DWORD length = GetModuleFileName(NULL, szPath, MAX_PATH);
    std::wstring strWorkPath(szPath);
    strWorkPath = strWorkPath.substr(0, strWorkPath.rfind(L'\\') + 1);
    SetCurrentDirectory(strWorkPath.c_str());

    std::wstring strInParam;
    for (int i = 0; i < argc; ++i)
    {
        strInParam += argv[i];
        strInParam += L" ";
    }

    CLoger::SetLogLevel(LOG_LEVEL_DEBUG);
    // 初始化配置文件
    std::string strDbPath = UtilsUnicodeToString(strWorkPath) + "\\config\\config.db";
    int iRet              = g_ConfigSave.ConfigSaveInit(strDbPath.c_str());
    if (iRet != HRA_OK)
    {
        LOG_ERROR("Init config save failed! file:%s", strDbPath.c_str());
        return -1;
    }
    std::string strHraIpcName = UtilsGetHraIpcName();
    if (strHraIpcName.empty())
    {
        LOG_ERROR("UtilsGetHraIpcName empty! file:%s", strDbPath.c_str());
        return -1;
    }

    // 解析操作类型
    DWORD dwError = ERROR_SUCCESS;
    wchar_t szOption[MAX_PATH];
    ZeroMemory(szOption, sizeof(szOption));
    if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_FEATURE, strInParam.c_str()) ==
        ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%s!", HRA_CMD_PARAM_FEATURE);

        wchar_t szCmdJson[MAX_PATH * 100];
        ZeroMemory(szCmdJson, sizeof(szCmdJson));
        if (HraInst_GetParam(szCmdJson, sizeof(szCmdJson) / sizeof(wchar_t), HRA_CMD_PARAM_CMD_JSON,
                             strInParam.c_str()) == ERROR_SUCCESS)
        {
            LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_CMD_JSON, szCmdJson);

            if (SendCmdToHra(ProMsgHead::MsgType::NOTIFIER, strHraIpcName.c_str(),
                             UtilsUnicodeToString(szCmdJson).c_str()) != 0)
            {
                return -1;
            }
        }
        else if (HraInst_GetParam(szCmdJson, sizeof(szCmdJson) / sizeof(wchar_t), HRA_CMD_PARAM_CMD_FILE,
                                  strInParam.c_str()) == ERROR_SUCCESS)
        {
            LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_CMD_FILE, szCmdJson);

            std::string strFileContent;
            if (ReadCmdFile(UtilsUnicodeToString(szCmdJson).c_str(), strFileContent) != 0)
            {
                return -1;
            }
            if (SendCmdToHra(ProMsgHead::MsgType::NOTIFIER, strHraIpcName.c_str(), strFileContent.c_str()) != 0)
            {
                return -1;
            }
        }
        else
        {
            LOGW_ERROR(L"Get param (%s) or (%s) error!", HRA_CMD_PARAM_CMD_JSON, HRA_CMD_PARAM_CMD_FILE);
            return -1;
        }
    }
    else
    {
        LOG_ERROR("Option error!");
        return -1;
    }

    return 0;
}
