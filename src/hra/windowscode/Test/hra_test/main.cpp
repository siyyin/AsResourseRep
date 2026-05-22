#include <iostream>
#include <tchar.h>
#include <Windows.h>
#include "utility/Logger.h"
#include "utility/ConfigSave.h"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
#include "utility/HraAppDef.h"
#include "HraInstall/InstallUtility.h"
#include "HraInstall/HraInstall.h"
#include "HraIpcInterface/HraIpcClient.h"
#include "HraIpcInterface/HraIpcServer.h"
#include "json/json.h"
#include "../../Features/BaseLine/BaseLineEngine.h"
#include "../../Features/VulnPoc/VulnPocEngine.h"

#define HRA_CMD_PARAM_FEATURE L"feature"   // 扫描命令、取消命令等
#define HRA_CMD_PARAM_PATTERN L"pattern"   // pattern更新命令
#define HRA_CMD_PARAM_CMD_JSON L"cmd_json" // 透传的json指令
#define HRA_CMD_PARAM_CMD_FILE L"cmd_file" // 透传的json指令文件

#define HRA_CMD_PARAM_STOP L"stop"                     // 停止hra服务
#define HRA_CMD_PARAM_START L"start"                   // 启动hra服务
#define HRA_CMD_PARAM_INSTALL L"install"               // 安装hra服务
#define HRA_CMD_PARAM_UNINSTALL L"uninstall"           // 卸载hra服务
#define HRA_CMD_PARAM_AUTOINSTALL L"autoinstall"       // 自动安装hra服务
#define HRA_CMD_PARAM_ZIP_PATH L"zip_path"             // 安装包路径
#define HRA_CMD_PARAM_INSTALL_PATH L"install_path"     // 安装路径
#define HRA_CMD_PARAM_DATA_PATH L"data_path"    // 指定数据路径
#define HRA_CMD_PARAM_UNINSTALL_ACTION L"uninstall_action"    // 删除动作
#define HRA_CMD_PARAM_INSTALL_TYPE L"install_type"     // 安装类型
#define HRA_CMD_PARAM_INSTALL_ACTION L"install_action" // 安装后动作

#define HRA_CMD_PARAM_IPC_SERVER L"ipc_server" // 启动一个ipc监听服务

#define HRA_CMD_PARAM_BLSCAN L"blscan"       // 基线扫描lua脚本测试
#define HRA_CMD_PARAM_VULNPOC L"vuln_poc"       // 漏扫POC lua脚本测试
#define HRA_CMD_PARAM_FILE_PATH L"file_path" // lua脚本路径
#define HRA_CMD_PARAM_PARAMS L"params"       // lua传参

#define HRA_CMD_PARAM_KB_DATA L"kb" // 补丁数据
#define HRA_CMD_PARAM_SEQ L"seq"    // 序号
#define HRA_CMD_PARAM_AUTHORITY L"authority" // 授权
#define HRA_CMD_PARAM_PATTERN_VERSION L"pattern_version" // 产品获取HRA各个模块的Pattern版本

int cmdHandler(int iType, unsigned char* params, int paramsLen, unsigned char* pOutBuf, int iOutBufLen)
{
    LOG_INFO("Receive MSG type=%d , len=%d \n", iType, paramsLen);
    HraMsgHead shead;
    memcpy_s(&shead, sizeof(shead), params, sizeof(shead));
    if ((int)shead.nDataLen > 0 && (int)shead.nDataLen < paramsLen)
    {
        unsigned int requestDataLen = shead.nDataLen;
        std::string body(reinterpret_cast<char*>(params + sizeof(shead)), requestDataLen);
        LOG_INFO("%s", body.c_str());
        return HRA_OK;
    }
    const char* pMsg = (char*)(params + sizeof(struct HraMsgHead));
    LOG_INFO("%s", pMsg);

    return HRA_OK;
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
            LOG_ERROR("Read file(%s) error! %s", strFilePath.c_str(), strerror(errno));
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

int wmain(int argc, wchar_t* argv[])
{
    //设置工作目录
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

    //初始化配置文件
    //std::string strDbPath = UtilsUnicodeToString(strWorkPath) + "\\config\\config.db";
    //int iRet              = g_ConfigSave.ConfigSaveInit(strDbPath.c_str());
    //if (iRet != HRA_OK)
    //{
    //    LOG_ERROR("Init config save failed! file:%s", strDbPath.c_str());
    //    return -1;
    //}

    //解析操作类型
    DWORD dwError = ERROR_SUCCESS;
    wchar_t szOption[MAX_PATH];
    ZeroMemory(szOption, sizeof(szOption));
    if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_FEATURE, strInParam.c_str()) ==
        ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%s!", HRA_CMD_PARAM_FEATURE);

        wchar_t szHraIpcName[MAX_PATH];
        ZeroMemory(szHraIpcName, sizeof(szHraIpcName));
        if (HraInst_GetParam(szHraIpcName, sizeof(szHraIpcName) / sizeof(wchar_t), HRA_INSTALL_PARAM_HRA_IPC_NAME,
                             strInParam.c_str()) != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%s) error!", HRA_INSTALL_PARAM_HRA_IPC_NAME);
            return -1;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_IPC_NAME, szHraIpcName);

        wchar_t szCmdJson[MAX_PATH * 10];
        ZeroMemory(szCmdJson, sizeof(szCmdJson));
        if (HraInst_GetParam(szCmdJson, sizeof(szCmdJson) / sizeof(wchar_t), HRA_CMD_PARAM_CMD_JSON,
                             strInParam.c_str()) == ERROR_SUCCESS)
        {
            LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_CMD_JSON, szCmdJson);

            if (SendCmdToHra(ProMsgHead::MsgType::NOTIFIER, UtilsUnicodeToString(szHraIpcName).c_str(),
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
            if (SendCmdToHra(ProMsgHead::MsgType::NOTIFIER, UtilsUnicodeToString(szHraIpcName).c_str(),
                             strFileContent.c_str()) != 0)
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
    // pattern更新
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_PATTERN,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%s!", HRA_CMD_PARAM_PATTERN);

        wchar_t szHraIpcName[MAX_PATH];
        ZeroMemory(szHraIpcName, sizeof(szHraIpcName));
        if (HraInst_GetParam(szHraIpcName, sizeof(szHraIpcName) / sizeof(wchar_t), HRA_INSTALL_PARAM_HRA_IPC_NAME,
                             strInParam.c_str()) != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%s) error!", HRA_INSTALL_PARAM_HRA_IPC_NAME);
            return -1;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_IPC_NAME, szHraIpcName);

        wchar_t szCmdJson[MAX_PATH];
        ZeroMemory(szCmdJson, sizeof(szCmdJson));
        if (HraInst_GetParam(szCmdJson, sizeof(szCmdJson) / sizeof(wchar_t), HRA_CMD_PARAM_CMD_JSON,
                             strInParam.c_str()) == ERROR_SUCCESS)
        {
            LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_CMD_JSON, szCmdJson);
            if (SendCmdToHra(ProMsgHead::MsgType::PATTERN_UPDATE, UtilsUnicodeToString(szHraIpcName).c_str(),
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
            if (SendCmdToHra(ProMsgHead::MsgType::PATTERN_UPDATE, UtilsUnicodeToString(szHraIpcName).c_str(),
                             strFileContent.c_str()) != 0)
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
    //停止
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_STOP, strInParam.c_str()) ==
             ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%ls!", HRA_CMD_PARAM_STOP);
        //获取服务名
        wchar_t szHraServiceName[MAX_PATH];
        ZeroMemory(szHraServiceName, sizeof(szHraServiceName));
        dwError = HraInst_GetParam(szHraServiceName, sizeof(szHraServiceName) / sizeof(wchar_t),
                                   HRA_INSTALL_PARAM_HRA_SERVICE_NAME, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME, szHraServiceName);

        //停止
        dwError = HraStop(szHraServiceName);
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Option return code:%lu!", dwError);
            return dwError;
        }

        LOGW_INFO(L"Option return code:%lu!", dwError);
        return dwError;
    }
    //启动
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_START, strInParam.c_str()) ==
             ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%ls!", HRA_CMD_PARAM_START);

        //获取服务名
        wchar_t szHraServiceName[MAX_PATH];
        ZeroMemory(szHraServiceName, sizeof(szHraServiceName));
        dwError = HraInst_GetParam(szHraServiceName, sizeof(szHraServiceName) / sizeof(wchar_t),
                                   HRA_INSTALL_PARAM_HRA_SERVICE_NAME, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME, szHraServiceName);

        wchar_t szUUID[MAX_PATH];
        ZeroMemory(szUUID, sizeof(szUUID));
        dwError =
            HraInst_GetParam(szUUID, sizeof(szUUID) / sizeof(wchar_t), HRA_INSTALL_PARAM_UUID, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_UUID);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_UUID, szUUID);

        wchar_t szProIpcName[MAX_PATH];
        ZeroMemory(szProIpcName, sizeof(szProIpcName));
        dwError = HraInst_GetParam(szProIpcName, sizeof(szProIpcName) / sizeof(wchar_t), HRA_INSTALL_PARAM_PRO_IPC_NAME,
                                   strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_PRO_IPC_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_PRO_IPC_NAME, szProIpcName);

        wchar_t szHraIpcName[MAX_PATH];
        ZeroMemory(szHraIpcName, sizeof(szHraIpcName));
        dwError = HraInst_GetParam(szHraIpcName, sizeof(szProIpcName) / sizeof(wchar_t), HRA_INSTALL_PARAM_HRA_IPC_NAME,
                                   strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_HRA_IPC_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_IPC_NAME, szHraIpcName);

        dwError = HraStart(szHraServiceName, szUUID, szProIpcName, szHraIpcName);
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Option return code:%lu!", dwError);
            return dwError;
        }

        LOGW_INFO(L"Option return code:%lu!", dwError);
        return dwError;
    }
    // install
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_INSTALL,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%ls!", HRA_CMD_PARAM_INSTALL);
        //获取服务名
        wchar_t szHraServiceName[MAX_PATH];
        ZeroMemory(szHraServiceName, sizeof(szHraServiceName));
        dwError = HraInst_GetParam(szHraServiceName, sizeof(szHraServiceName) / sizeof(wchar_t),
                                   HRA_INSTALL_PARAM_HRA_SERVICE_NAME, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME, szHraServiceName);

        wchar_t szZipPath[MAX_PATH];
        ZeroMemory(szZipPath, sizeof(szZipPath));
        dwError = HraInst_GetParam(szZipPath, MAX_PATH, HRA_CMD_PARAM_ZIP_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_ZIP_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_ZIP_PATH, szZipPath);

        wchar_t szInstallPath[MAX_PATH];
        ZeroMemory(szInstallPath, sizeof(szInstallPath));
        dwError = HraInst_GetParam(szInstallPath, MAX_PATH, HRA_CMD_PARAM_INSTALL_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_INSTALL_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_INSTALL_PATH, szInstallPath);

        wchar_t wszSpecificPath[MAX_PATH] = L"";
        dwError = HraInst_GetParam(wszSpecificPath, MAX_PATH, HRA_CMD_PARAM_DATA_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_INFO(L"Get param:%ls error! Use the default path.", HRA_CMD_PARAM_DATA_PATH);
        }
        else
        {
            LOGW_INFO(L"Get param(%ls:%ls)!", HRA_CMD_PARAM_DATA_PATH, wszSpecificPath);
        }

        dwError = HraInstallEX(szHraServiceName, szZipPath, szInstallPath, wszSpecificPath);
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Option return code:%lu!", dwError);
            return dwError;
        }

        LOGW_INFO(L"Option return code:%lu!", dwError);
        return dwError;
    }
    // uninstall
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_UNINSTALL,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%ls!", HRA_CMD_PARAM_UNINSTALL);

        //获取服务名
        wchar_t szHraServiceName[MAX_PATH];
        ZeroMemory(szHraServiceName, sizeof(szHraServiceName));
        dwError = HraInst_GetParam(szHraServiceName, sizeof(szHraServiceName) / sizeof(wchar_t),
                                   HRA_INSTALL_PARAM_HRA_SERVICE_NAME, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME, szHraServiceName);

        wchar_t wszUninstallAction[MAX_PATH] = {0};
        int nUninstallAction                 = 0;
        dwError = HraInst_GetParam(wszUninstallAction, MAX_PATH, HRA_CMD_PARAM_UNINSTALL_ACTION, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! Use the default number", HRA_CMD_PARAM_UNINSTALL_ACTION);
            //return dwError;
        }
        else
        {
            LOGW_INFO(L"Get param(%ls:%ls)!", HRA_CMD_PARAM_UNINSTALL_ACTION, wszUninstallAction);
            nUninstallAction = _wtoi(wszUninstallAction);
        }

        dwError = HraUninstallEX(szHraServiceName, nUninstallAction);
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Option return code:%lu!", dwError);
            return dwError;
        }

        LOGW_INFO(L"Option return code:%lu!", dwError);
        return dwError;
    }
    // autoinstall
    else if (HraInst_GetParam(szOption, MAX_PATH, HRA_CMD_PARAM_AUTOINSTALL, strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Option:%ls!", HRA_CMD_PARAM_AUTOINSTALL);

        //获取服务名
        wchar_t szHraServiceName[MAX_PATH];
        ZeroMemory(szHraServiceName, sizeof(szHraServiceName));
        dwError = HraInst_GetParam(szHraServiceName, sizeof(szHraServiceName) / sizeof(wchar_t),
                                   HRA_INSTALL_PARAM_HRA_SERVICE_NAME, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME, szHraServiceName);

        wchar_t szZipPath[MAX_PATH];
        ZeroMemory(szZipPath, sizeof(szZipPath));
        dwError = HraInst_GetParam(szZipPath, MAX_PATH, HRA_CMD_PARAM_ZIP_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_ZIP_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_ZIP_PATH, szZipPath);

        wchar_t szInstallPath[MAX_PATH];
        ZeroMemory(szInstallPath, sizeof(szInstallPath));
        dwError = HraInst_GetParam(szInstallPath, MAX_PATH, HRA_CMD_PARAM_INSTALL_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_INSTALL_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_INSTALL_PATH, szInstallPath);

        wchar_t szInstallType[MAX_PATH];
        ZeroMemory(szInstallType, sizeof(szInstallType));
        dwError = HraInst_GetParam(szInstallType, MAX_PATH, HRA_CMD_PARAM_INSTALL_TYPE, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_INSTALL_TYPE);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_INSTALL_TYPE, szInstallType);
        int nInstallType = _wtoi(szInstallType);

        wchar_t szInstallAction[MAX_PATH];
        ZeroMemory(szInstallAction, sizeof(szInstallAction));
        dwError = HraInst_GetParam(szInstallAction, MAX_PATH, HRA_CMD_PARAM_INSTALL_ACTION, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_INSTALL_ACTION);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_INSTALL_ACTION, szInstallAction);
        int nInstallAction = _wtoi(szInstallAction);

        wchar_t wszSpecificPath[MAX_PATH] = L"";
        dwError = HraInst_GetParam(wszSpecificPath, MAX_PATH, HRA_CMD_PARAM_DATA_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! Use the default path.", HRA_CMD_PARAM_DATA_PATH);
        }
        else
        {
            LOGW_INFO(L"Get param(%ls:%ls)!", HRA_CMD_PARAM_DATA_PATH, wszSpecificPath);
        }

        wchar_t szUUID[MAX_PATH];
        ZeroMemory(szUUID, sizeof(szUUID));
        wchar_t szProIpcName[MAX_PATH];
        ZeroMemory(szProIpcName, sizeof(szProIpcName));
        wchar_t szHraIpcName[MAX_PATH];
        ZeroMemory(szHraIpcName, sizeof(szHraIpcName));
        if (nInstallAction == HRA_INSTALL_ACTION_START_SERVER)
        {
            dwError = HraInst_GetParam(szUUID, MAX_PATH, HRA_INSTALL_PARAM_UUID, strInParam.c_str());
            if (dwError != ERROR_SUCCESS)
            {
                LOGW_ERROR(L"Get param:%ls error! ", HRA_INSTALL_PARAM_UUID);
                return dwError;
            }
            LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_UUID, szUUID);

            dwError = HraInst_GetParam(szProIpcName, MAX_PATH, HRA_INSTALL_PARAM_PRO_IPC_NAME, strInParam.c_str());
            if (dwError != ERROR_SUCCESS)
            {
                LOGW_ERROR(L"Get param:%ls error! ", HRA_INSTALL_PARAM_PRO_IPC_NAME);
                return dwError;
            }
            LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_PRO_IPC_NAME, szProIpcName);

            dwError = HraInst_GetParam(szHraIpcName, MAX_PATH, HRA_INSTALL_PARAM_HRA_IPC_NAME, strInParam.c_str());
            if (dwError != ERROR_SUCCESS)
            {
                LOGW_ERROR(L"Get param:%ls error! ", HRA_INSTALL_PARAM_HRA_IPC_NAME);
                return dwError;
            }
            LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_IPC_NAME, szHraIpcName);
        }

        dwError = HraAutoInstallEX(szHraServiceName, szZipPath, szInstallPath, nInstallType, nInstallAction, szUUID,
                                   szProIpcName, szHraIpcName, wszSpecificPath, HRA_UNINSTALL_ACTION_UPDATE);
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Option return code:%lu!", dwError);
            return dwError;
        }

        LOGW_INFO(L"Option return code:%lu!", dwError);
        return dwError;
    }
    // ipc监听服务
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_IPC_SERVER,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
        wchar_t szProIpcName[MAX_PATH];
        ZeroMemory(szProIpcName, sizeof(szProIpcName));
        dwError = HraInst_GetParam(szProIpcName, sizeof(szProIpcName) / sizeof(wchar_t), HRA_INSTALL_PARAM_PRO_IPC_NAME,
                                   strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_PRO_IPC_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_PRO_IPC_NAME, szProIpcName);

        //启动监听
        int iRet = HraIpcRegistCallbackFun(UtilsUnicodeToString(szProIpcName).c_str(), HRA_CMD_HANDLE, cmdHandler);
        if (0 != iRet)
        {
            LOGW_ERROR(L"HraIpcRegistCallbackFun error! name:%s", szProIpcName);
            return iRet;
        }

        LOG_INFO("Start Lister service...");
        iRet = HraIpcStartListenService();
        if (0 != iRet)
        {
            LOGW_ERROR(L"HraIpcStartListenService error! name:%s", szProIpcName);
            return iRet;
        }

        while (true)
        {
            Sleep(1000);
        }

        LOG_INFO("Stop Lister service...");
        HraIpcStopListenService();
    }
    // 基线lua脚本测试
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_BLSCAN, strInParam.c_str()) ==
             ERROR_SUCCESS)
    {
        wchar_t szLuaPath[MAX_PATH];
        ZeroMemory(szLuaPath, sizeof(szLuaPath));
        dwError = HraInst_GetParam(szLuaPath, MAX_PATH, HRA_CMD_PARAM_FILE_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_FILE_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_FILE_PATH, szLuaPath);

        wchar_t szLuaParams[MAX_PATH];
        ZeroMemory(szLuaParams, sizeof(szLuaParams));
        dwError = HraInst_GetParam(szLuaParams, MAX_PATH, HRA_CMD_PARAM_PARAMS, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            //LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_PARAMS);
            //return dwError;
        }
        LOGW_INFO(L"Get param(%ls:%ls)!", HRA_CMD_PARAM_PARAMS, szLuaParams);

        std::vector<std::string> vctLuaParams;
        std::string strJsonLuaParam = UtilsUnicodeToString(szLuaParams);
        if (!strJsonLuaParam.empty())
        {
            Json::Value jsParam = StringToJson(strJsonLuaParam.c_str(), strJsonLuaParam.length());
            if (!jsParam.isArray())
            {
                LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_PARAMS);
                dwError = ERROR_BAD_ARGUMENTS;
                return dwError;
            }           
            //if (jsParam.empty() || !jsParam.isArray() || jsParam.size() <= 0)
            //{
            //    LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_PARAMS);
            //    dwError = ERROR_BAD_ARGUMENTS;
            //    return dwError;
            //}
            for (int i = 0; i < jsParam.size(); ++i)
            {
                vctLuaParams.push_back(jsParam[i].asString());
            }
        }

        // 加载Pattern
        LOG_INFO("ExcuteScan start...");
        int nScanRet = BASE_LINE_LUA_RET_ERROR;
        //std::string strScanDetail;
        int nRet = BaseLineExcuteScan(nScanRet, UtilsUnicodeToString(szLuaPath), vctLuaParams);
        if (nRet != HRA_OK)
        {
            LOG_ERROR("BaseLineExcuteScan error! nRet:%d", nRet);
        }
        else
        {
            LOG_INFO("BaseLineExcuteScan succeed! ret_code:%d", nScanRet);
        }
    }
    //补丁数据发送
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_KB_DATA,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
        wchar_t szHraIpcName[MAX_PATH];
        ZeroMemory(szHraIpcName, sizeof(szHraIpcName));
        if (HraInst_GetParam(szHraIpcName, sizeof(szHraIpcName) / sizeof(wchar_t), HRA_INSTALL_PARAM_HRA_IPC_NAME,
                             strInParam.c_str()) != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%s) error!", HRA_INSTALL_PARAM_HRA_IPC_NAME);
            return -1;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_IPC_NAME, szHraIpcName);

        wchar_t szSeq[MAX_PATH];
        ZeroMemory(szSeq, sizeof(szSeq));
        dwError = HraInst_GetParam(szSeq, MAX_PATH, HRA_CMD_PARAM_SEQ, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_SEQ);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_SEQ, szSeq);
        __int64 nSeq = _wtoi64(szSeq);

        wchar_t szAuthority[MAX_PATH];
        ZeroMemory(szAuthority, sizeof(szAuthority));
        dwError = HraInst_GetParam(szAuthority, MAX_PATH, HRA_CMD_PARAM_AUTHORITY, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_AUTHORITY);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_AUTHORITY, szAuthority);
        int nAuthority = _wtoi(szAuthority);

        wchar_t szFilePath[MAX_PATH];
        ZeroMemory(szFilePath, sizeof(szFilePath));
        dwError = HraInst_GetParam(szFilePath, MAX_PATH, HRA_CMD_PARAM_FILE_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_FILE_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_FILE_PATH, szFilePath);

        //读取文件
        std::string strJsonCont;
        if (ReadCmdFile(UtilsUnicodeToString(szFilePath).c_str(), strJsonCont) != 0)
        {
            return -1;
        }

        Json::Value jsRoot;
        jsRoot["command_seq"] = nSeq;
        jsRoot["kb_data"]     = strJsonCont;
        jsRoot["authority"]   = nAuthority;
        strJsonCont           = jsRoot.toStyledString();
        if (SendCmdToHra(ProMsgHead::MsgType::KB_DATA, UtilsUnicodeToString(szHraIpcName).c_str(),
                         strJsonCont.c_str()) != 0)
        {
            return -1;
        }
    }
    // POC lua脚本测试
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_VULNPOC,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
         //初始化配置文件
        std::string strDbPath = UtilsUnicodeToString(strWorkPath) + "\\config\\config.db";
        int iRet              = g_ConfigSave.ConfigSaveInit(strDbPath.c_str());
        if (iRet != HRA_OK)
        {
            LOG_ERROR("Init config save failed! file:%s", strDbPath.c_str());
            return -1;
        }
        //初始化配置文件
        std::string strAssetsDbPath = g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_DATA_DIR);
        if (strAssetsDbPath.empty())
        {
            LOGW_ERROR(L"Get db path error! ");
            return -1;
        }
        strAssetsDbPath += "\\asset\\asset.db";
        iRet = g_AssetDataDB.ConfigSaveInit(strAssetsDbPath.c_str());
        if (iRet != HRA_OK)
        {
            LOG_ERROR("Init assets save failed! file:%s", strAssetsDbPath.c_str());
            return -1;
        }

        wchar_t szLuaPath[MAX_PATH];
        ZeroMemory(szLuaPath, sizeof(szLuaPath));
        dwError = HraInst_GetParam(szLuaPath, MAX_PATH, HRA_CMD_PARAM_FILE_PATH, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param:%ls error! ", HRA_CMD_PARAM_FILE_PATH);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_CMD_PARAM_FILE_PATH, szLuaPath);

        std::string strLuaPath = UtilsUnicodeToString(szLuaPath);
        int nRetCode;
        std::string strRetDetail;
        int nRet = VulnPocExecuteScan(nRetCode, strRetDetail, strLuaPath);
        return nRet;
    }
    // 产品获取Pattern版本
    else if (HraInst_GetParam(szOption, sizeof(szOption) / sizeof(wchar_t), HRA_CMD_PARAM_PATTERN_VERSION,
                              strInParam.c_str()) == ERROR_SUCCESS)
    {
        //获取服务名
        wchar_t szHraServiceName[MAX_PATH] = {0};
        dwError = HraInst_GetParam(szHraServiceName, sizeof(szHraServiceName) / sizeof(wchar_t),
                                   HRA_INSTALL_PARAM_HRA_SERVICE_NAME, strInParam.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOGW_ERROR(L"Get param(%ls) error!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME);
            return dwError;
        }
        LOGW_INFO(L"Get param(%s:%s)!", HRA_INSTALL_PARAM_HRA_SERVICE_NAME, szHraServiceName);

        wchar_t wszValue[MAX_PATH] = {0};
        dwError                    = GetHraLoadedPatternVersion(wszValue, MAX_PATH, szHraServiceName);
        if (dwError != ERROR_SUCCESS)
        {
                LOGW_ERROR(L"Option return code:%lu!", dwError);
                return dwError;
        }
        LOGW_INFO(L"Option return value:[\n%s]", wszValue);
        return dwError;
    }
    else
    {
        LOG_ERROR("Option error!");
        return -1;
    }

    return 0;
}
