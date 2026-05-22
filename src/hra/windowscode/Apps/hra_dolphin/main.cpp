#include <iostream>
#include <tchar.h>
#include <string>
#include <vector>
#include <list>
#include <fstream>
#include <windows.h>
#include "json/json.h"
#include "utility/HraJson.h"
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "utility/version.hpp"
#include "utility/HraAppDef.h"
#include "utility/StdOutHelper.h"
#include "HraInstall/InstallUtility.h"
#include "DolphinCore/DolphinCore.h"
#include "DolphinCore/DolphinNTLMCode.h"

#define HRA_DOLPHIN_PARAM_SAM_FILE L"sam_file"
#define HRA_DOLPHIN_PARAM_SYSTEM_FILE L"system_file"
#define HRA_DOLPHIN_PARAM_PWD_FILE L"pwd_file"
#define HRA_DOLPHIN_PARAM_DATA_DIR L"data_dir"
#define HRA_DOLPHIN_PARAM_RESULT_FILE L"result_file"
#define HRA_DOLPHIN_PARAM_ELEVATE L"elevate"

#define HRA_DOLPHIN_APP_NAME L"hra_dolphin"
#define HRA_DOLPHIN_LOG_HEAD "hra_dolphin"

#define HRA_DOLPHIN_DEFAULT_RESULT_FILE_NAME L"hra_dolphin_result.json"

#define HRA_DOLPHIN_WEAK_PASSWD_FLAG_TRUE "1"
#define HRA_DOLPHIN_WEAK_PASSWD_FLAG_FALSE "0"

#define HRA_DOLPHIN_LOG_BUFF_SIZE 4096
#define HRA_DOLPHIN_MAX_PWD_FILE_NUM 100

/// <summary>
/// 结果字符串
/// </summary>
struct HraDolphinResult
{
    std::string account_name;
    std::string passwd;
    std::string weak_passwd_flag;
    std::string ntlm_hash;

    void clear()
    {
        account_name.clear();
        passwd.clear();
        weak_passwd_flag.clear();
        ntlm_hash.clear();
    }

    HraDolphinResult()
    {
        clear();
    }
};

/// <summary>
/// 初始化日志
/// </summary>
/// <param name="pszDataDir"></param>
/// <returns></returns>
bool InitLog(const wchar_t* pszDataDir)
{
    if (pszDataDir == NULL || _wcsicmp(pszDataDir, L"") == 0)
    {
        return false;
    }

    if (!CLoger::Initialize(UtilsUnicodeToString(pszDataDir).c_str(), HRA_DOLPHIN_LOG_HEAD))
    {
        return false;
    }
    CLoger::SetLogLevel(LOG_LEVEL_DEBUG);
    LOG_INFO("\n"
             "################################### HRA Dolphin Welcome #############################\n"
             "# Product Name:       AsiaInfo Security Host Hardening Agent\n"
             "# Product Version:    %d.%d.%d.%d\n"
             "#####################################################################################",
             HRA_VER_MAJOR, HRA_VER_MINOR, HRA_VER_PATCH, HRA_VER_BUILD);
    return true;
}

/// <summary>
/// 主函数
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
int wmain(int argc, wchar_t* argv[])
{
    DWORD dwErrCode = ERROR_SUCCESS;
    wchar_t szErrMsg[HRA_DOLPHIN_LOG_BUFF_SIZE];
    ZeroMemory(szErrMsg, sizeof(szErrMsg));
    std::vector<std::wstring> vctPwdFile;//密码文件列表
    std::list<HraDolphinResult> lstScanResult;//扫描结果
    std::wstring strInParam;
    bool bOutResultFile = false;//是否输出结果文件
    bool bElevate       = false;//是否提升权限

    //设置工作目录
    wchar_t szPath[MAX_PATH];
    DWORD length = GetModuleFileName(NULL, szPath, MAX_PATH);
    std::wstring strWorkPath(szPath);
    strWorkPath = strWorkPath.substr(0, strWorkPath.rfind(L'\\') + 1);
    SetCurrentDirectory(strWorkPath.c_str());

    // 禁止屏幕输出
    // 将标准输出重定向到空文件
    StdOutRedirectHelper stdOutRedirectHelper;
    if (!stdOutRedirectHelper.RedirectTo("NUL"))
    {
        dwErrCode = ERROR_FUNCTION_FAILED;
        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"StdOut redirect error!");
        LOGW_ERROR(szErrMsg);
        goto _exit;
    }

    //解析参数
    for (int i = 0; i < argc; ++i)
    {
        strInParam += argv[i];
        strInParam += L" ";
    }
    

    //数据路径校验
    wchar_t szDataDir[MAX_PATH];
    ZeroMemory(szDataDir, sizeof(szDataDir));
    wchar_t szDataDirParam[MAX_PATH];
    ZeroMemory(szDataDirParam, sizeof(szDataDirParam));
    if (HraInst_GetParam(szDataDirParam, sizeof(szDataDirParam) / sizeof(wchar_t), HRA_DOLPHIN_PARAM_DATA_DIR,
                         strInParam.c_str()) == ERROR_SUCCESS)
    {
        if (_wcsicmp(szDataDirParam, L"") == 0)
        {
            dwErrCode = ERROR_INVALID_PARAMETER;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Param:%s empty!", HRA_DOLPHIN_PARAM_DATA_DIR);
            //LOGW_ERROR(szErrMsg);
            goto _exit;
        }
        _snwprintf_s(szDataDir, sizeof(szDataDir) / sizeof(wchar_t), L"%s\\%s", szDataDirParam, HRA_DOLPHIN_APP_NAME);
    }
    else
    {
        _snwprintf_s(szDataDir, sizeof(szDataDir) / sizeof(wchar_t), L"%s\\%s", strWorkPath.c_str(),
                     HRA_DOLPHIN_APP_NAME);
    }

    //初始化日志
    if (!InitLog(szDataDir))
    {
        dwErrCode = ERROR_INVALID_PARAMETER;
        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Init log error! path:%s", szDataDirParam);
        LOGW_ERROR(szErrMsg);
        goto _exit;
    }
    LOGW_INFO(L"%s", strInParam.c_str());

    if (_wcsicmp(szDataDirParam, L"") != 0)
    {
        LOGW_INFO(L"Get param:%s, value:%s", HRA_DOLPHIN_PARAM_DATA_DIR, szDataDirParam);
    }
    LOGW_INFO(L"Data dir:%s", szDataDir);
    
    //密码文件相关校验
    wchar_t szPwdFileList[MAX_PATH * HRA_DOLPHIN_MAX_PWD_FILE_NUM];
    ZeroMemory(szPwdFileList, sizeof(szPwdFileList));
    if (HraInst_GetParam(szPwdFileList, sizeof(szPwdFileList) / sizeof(wchar_t), HRA_DOLPHIN_PARAM_PWD_FILE,
                         strInParam.c_str()) != ERROR_SUCCESS)
    {
        dwErrCode = ERROR_INVALID_PARAMETER;
        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Get param:%s error!", HRA_DOLPHIN_PARAM_PWD_FILE);
        LOGW_ERROR(szErrMsg);
        goto _exit;
    }
    LOGW_INFO(L"Get param:%s, value:%s", HRA_DOLPHIN_PARAM_PWD_FILE, szPwdFileList);
    vctPwdFile = UtilsStringSplit(szPwdFileList, L",");
    if (vctPwdFile.empty())
    {
        dwErrCode = ERROR_INVALID_PARAMETER;
        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Param:%s empty!", HRA_DOLPHIN_PARAM_PWD_FILE);
        LOGW_ERROR(szErrMsg);
        goto _exit;
    }
    for (std::vector<std::wstring>::const_iterator it = vctPwdFile.begin(); vctPwdFile.end() != it; ++it)
    {
        if (!UtilsIsFileExist(it->c_str()))
        {
            dwErrCode = ERROR_FILE_NOT_FOUND;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"File not found! file:%s", it->c_str());
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }
        LOGW_INFO(L"File check succeed! file:%s", it->c_str());
    }

    //是否输出文件校验
    bOutResultFile = false;
    wchar_t szResultFile[MAX_PATH];
    ZeroMemory(szResultFile, sizeof(szResultFile));
    if (HraInst_GetParam(szResultFile, sizeof(szResultFile) / sizeof(wchar_t), HRA_DOLPHIN_PARAM_RESULT_FILE,
                         strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Get param:%s", HRA_DOLPHIN_PARAM_RESULT_FILE);
        bOutResultFile = true;
        _snwprintf_s(szResultFile, sizeof(szResultFile) / sizeof(wchar_t), L"%s\\%s", szDataDir,
                     HRA_DOLPHIN_DEFAULT_RESULT_FILE_NAME);
        LOGW_INFO(L"Result file:%s", szResultFile);
    }

    //是否提升权限
    bElevate = false;
    wchar_t szElevate[MAX_PATH];
    ZeroMemory(szElevate, sizeof(szElevate));
    if (HraInst_GetParam(szElevate, sizeof(szElevate) / sizeof(wchar_t), HRA_DOLPHIN_PARAM_ELEVATE,
                         strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Get param:%s", HRA_DOLPHIN_PARAM_ELEVATE);
        bElevate = true;
    }

    //导出SAM文件相关校验
    wchar_t szSamFilePath[MAX_PATH];
    ZeroMemory(szSamFilePath, sizeof(szSamFilePath));
    if (HraInst_GetParam(szSamFilePath, sizeof(szSamFilePath) / sizeof(wchar_t), HRA_DOLPHIN_PARAM_SAM_FILE,
                         strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Get param:%s, value:%s", HRA_DOLPHIN_PARAM_SAM_FILE, szSamFilePath);
        if (bElevate)
        {
            dwErrCode = ERROR_INVALID_PARAMETER;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Param:%s conflicts with:%s!",
                         HRA_DOLPHIN_PARAM_SAM_FILE, HRA_DOLPHIN_PARAM_ELEVATE);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }

        if (_wcsicmp(szSamFilePath, L"") == 0)
        {
            dwErrCode = ERROR_INVALID_PARAMETER;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Param:%s empty!", HRA_DOLPHIN_PARAM_SAM_FILE);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }
    }
    //导出SYSTEM文件相关校验
    wchar_t szSystemFilePath[MAX_PATH];
    ZeroMemory(szSystemFilePath, sizeof(szSystemFilePath));
    if (HraInst_GetParam(szSystemFilePath, sizeof(szSystemFilePath) / sizeof(wchar_t), HRA_DOLPHIN_PARAM_SYSTEM_FILE,
                         strInParam.c_str()) == ERROR_SUCCESS)
    {
        LOGW_INFO(L"Get param:%s, value:%s", HRA_DOLPHIN_PARAM_SYSTEM_FILE, szSystemFilePath);
        if (bElevate)
        {
            dwErrCode = ERROR_INVALID_PARAMETER;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Param:%s conflicts with:%s!",
                         HRA_DOLPHIN_PARAM_SAM_FILE, HRA_DOLPHIN_PARAM_ELEVATE);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }

        if (_wcsicmp(szSystemFilePath, L"") == 0)
        {
            dwErrCode = ERROR_INVALID_PARAMETER;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Param:%s empty!",
                         HRA_DOLPHIN_PARAM_SYSTEM_FILE);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }
    }
    
    // 参数需要同时指定
    if ((_wcsicmp(szSamFilePath, L"") != 0 && _wcsicmp(szSystemFilePath, L"") == 0) ||
        _wcsicmp(szSamFilePath, L"") == 0 && _wcsicmp(szSystemFilePath, L"") != 0)
    {
        dwErrCode = ERROR_INVALID_PARAMETER;
        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t),
                     L"Param %s and %s must be both specified at the same time or not specified at the same time!",
                     HRA_DOLPHIN_PARAM_SAM_FILE, HRA_DOLPHIN_PARAM_SYSTEM_FILE);
        LOGW_ERROR(szErrMsg);
        goto _exit;
    }
    // 同时指定sam、system文件，校验文件是否存在
    else if (_wcsicmp(szSamFilePath, L"") != 0 && _wcsicmp(szSystemFilePath, L"") != 0)
    {
        if (!UtilsIsFileExist(szSamFilePath))
        {
            dwErrCode = ERROR_FILE_NOT_FOUND;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"File not found! file:%s", szSamFilePath);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }
        LOGW_INFO(L"File check succeed! file:%s", szSamFilePath);
        if (!UtilsIsFileExist(szSystemFilePath))
        {
            dwErrCode = ERROR_FILE_NOT_FOUND;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"File not found! file:%s", szSystemFilePath);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }
        LOGW_INFO(L"File check succeed! file:%s", szSystemFilePath);
    }
    // 两个都空
    else
    {
        // 检查当前用户是否为SYSTEM
        wchar_t szUserName[MAX_PATH];
        ZeroMemory(szUserName, sizeof(szUserName));
        DWORD dwNameLen = MAX_PATH;
        if (!GetUserName(szUserName, &dwNameLen))
        {
            dwErrCode = GetLastError();
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"GetUserName error! code:%lu", dwErrCode);
            LOGW_ERROR(szErrMsg);
            goto _exit;
        }
        if (_wcsicmp(szUserName, L"SYSTEM") == 0)
        {
            ZeroMemory(szSamFilePath, sizeof(szSamFilePath));
            ZeroMemory(szSystemFilePath, sizeof(szSystemFilePath));
        }
        // 检查是否有admin权限
        else
        {
            if (!HraInst_IsAdmin())
            {
                dwErrCode = ERROR_PRIVILEGE_NOT_HELD;
                _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t),
                             L"hra_dolphin.exe requires administrator privileges!");
                LOGW_ERROR(szErrMsg);
                goto _exit;
            }

            if (bElevate)
            {
                if (DolphinCore_Elevate() != HRA_OK)
                {
                    dwErrCode = ERROR_FUNCTION_FAILED;
                    _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"DolphinCore_Elevate error!");
                    LOGW_ERROR(szErrMsg);
                    goto _exit;
                }
            }
            else
            {
                // 导出文件
                _snwprintf_s(szSamFilePath, sizeof(szSamFilePath) / sizeof(wchar_t), L"%s\\sam.hiv", szDataDir);
                if (UtilsIsFileExist(szSamFilePath))
                {
                    if (!DeleteFile(szSamFilePath))
                    {
                        dwErrCode = GetLastError();
                        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t),
                                     L"DeleteFile error! code:%lu, file:%s", dwErrCode, szSamFilePath);
                        LOGW_ERROR(szErrMsg);
                        goto _exit;
                    }
                    LOGW_INFO(L"DeleteFile succeed! file:%s", szSamFilePath);
                }

                std::string strCmdRet;
                wchar_t szExportCmd[MAX_PATH];
                ZeroMemory(szExportCmd, sizeof(szExportCmd));
                // 导出sam文件
                _snwprintf_s(szExportCmd, sizeof(szExportCmd) / sizeof(wchar_t),
                             L"reg save hklm\\sam \"%s\" /y 1>nul 2>nul", szSamFilePath);
                if (!ExecuteCmd(&strCmdRet, UtilsUnicodeToString(szExportCmd).c_str()))
                {
                    dwErrCode = ERROR_BAD_COMMAND;
                    _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Excute command error! cmd:%s, ret:%s",
                                 szExportCmd, UtilsStringToUnicode(strCmdRet).c_str());
                    LOGW_ERROR(szErrMsg);
                    goto _exit;
                }
                LOGW_INFO(L"Export sam file! cmd:%s, ret:%s", szExportCmd, UtilsStringToUnicode(strCmdRet).c_str());

                // 检查导出文件
                if (!UtilsIsFileExist(szSamFilePath))
                {
                    dwErrCode = ERROR_FILE_NOT_FOUND;
                    _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"File not found! file:%s",
                                 szSamFilePath);
                    LOGW_ERROR(szErrMsg);
                    goto _exit;
                }
                LOGW_INFO(L"File check succeed! file:%s", szSamFilePath);

                // 导出system文件
                _snwprintf_s(szSystemFilePath, sizeof(szSystemFilePath) / sizeof(wchar_t), L"%s\\system.hiv",
                             szDataDir);
                if (UtilsIsFileExist(szSystemFilePath))
                {
                    if (!DeleteFile(szSystemFilePath))
                    {
                        dwErrCode = GetLastError();
                        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t),
                                     L"DeleteFile error! code:%lu, file:%s", dwErrCode, szSystemFilePath);
                        LOGW_ERROR(szErrMsg);
                        goto _exit;
                    }
                    LOGW_INFO(L"DeleteFile succeed! file:%s", szSystemFilePath);
                }

                _snwprintf_s(szExportCmd, sizeof(szExportCmd) / sizeof(wchar_t),
                             L"reg save hklm\\system \"%s\" /y 1>nul 2>nul", szSystemFilePath);
                if (!ExecuteCmd(&strCmdRet, UtilsUnicodeToString(szExportCmd).c_str()))
                {
                    dwErrCode = ERROR_BAD_COMMAND;
                    _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Excute command error! cmd:%s, ret:%s",
                                 szExportCmd, UtilsStringToUnicode(strCmdRet).c_str());
                    LOGW_ERROR(szErrMsg);
                    goto _exit;
                }
                LOGW_INFO(L"Export sam system! cmd:%s, ret:%s", szExportCmd, UtilsStringToUnicode(strCmdRet).c_str());

                // 检查导出文件
                if (!UtilsIsFileExist(szSystemFilePath))
                {
                    dwErrCode = ERROR_FILE_NOT_FOUND;
                    _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"File not found! file:%s",
                                 szSystemFilePath);
                    LOGW_ERROR(szErrMsg);
                    goto _exit;
                }
                LOGW_INFO(L"File check succeed! file:%s", szSystemFilePath);
            }
        }
    }
    
    //提取账户hash信息
    DolphinCore_FreeResult();
    if (DolphinCore_DoWorker(szSystemFilePath, szSamFilePath) != 0)
    {
        dwErrCode = ERROR_FILE_NOT_FOUND;
        _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Get user hash info error!");
        LOGW_ERROR(szErrMsg);
        goto _exit;
    }

    const USER_PWD_RESULT* pRstTmp = DolphinCore_GetResult();
    while (pRstTmp != NULL)
    {
        char szHexHash[33];
        memset(szHexHash, 0, sizeof(szHexHash));
        int iFileLine = 0;

        //bool bMatch             = false;
        std::string strUserName = UtilsUnicodeToString(pRstTmp->stData.user_name);
        std::string strPwdHash  = UtilsUnicodeToString(pRstTmp->stData.pwd_hash);
        LOG_INFO("Check user:%s start!", strUserName.c_str());
        LOG_DEBUG("pwd_hash:%s", strPwdHash.c_str());

        HraDolphinResult stWpRet;
        stWpRet.clear();
        stWpRet.account_name     = strUserName;
        stWpRet.ntlm_hash        = strPwdHash;
        stWpRet.weak_passwd_flag = HRA_DOLPHIN_WEAK_PASSWD_FLAG_FALSE;
        stWpRet.passwd           = "";

        //空密码无需匹配直接报弱口令
        if (strPwdHash.empty())
        {
            stWpRet.weak_passwd_flag = HRA_DOLPHIN_WEAK_PASSWD_FLAG_TRUE;
            lstScanResult.push_back(stWpRet);
            LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());

            pRstTmp = pRstTmp->pNext;
            continue;
        }

        //空字符串加密
        dolphin_hash("", szHexHash, sizeof(szHexHash));
        if (strPwdHash == std::string(szHexHash))
        {
            stWpRet.weak_passwd_flag = HRA_DOLPHIN_WEAK_PASSWD_FLAG_TRUE;
            stWpRet.passwd           = "";
            lstScanResult.push_back(stWpRet);
            LOG_INFO("Weak passwd user:%s, add!", strUserName.c_str());

            pRstTmp = pRstTmp->pNext;
            continue;
        }

        //读取密码文件字典
        bool bMatch = false;
        for (std::vector<std::wstring>::const_iterator it_file = vctPwdFile.begin(); vctPwdFile.end() != it_file;
             ++it_file)
        {
            std::string strFilePath = UtilsUnicodeToString(*it_file);
            std::ifstream ifs;
            ifs.open(strFilePath.c_str(), std::ios::in);
            if (!ifs.is_open())
            {
                LOG_WARN("Open file:%s error!", strFilePath.c_str());
                continue;
            }

            iFileLine = 0;
            std::string strLine;
            while (std::getline(ifs, strLine))
            {
                ++iFileLine;
                if (dolphin_hash(strLine.c_str(), szHexHash, sizeof(szHexHash)) < 0)
                {
                    LOG_WARN("Pwd line error, file:%s, line:%d", it_file->c_str(), iFileLine);
                    continue;
                }
                if (strPwdHash == std::string(szHexHash))
                {
                    bMatch = true;
                    stWpRet.weak_passwd_flag = HRA_DOLPHIN_WEAK_PASSWD_FLAG_TRUE;
                    stWpRet.passwd           = strLine;
                    //lstScanResult.push_back(stWpRet);
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

        lstScanResult.push_back(stWpRet);
        pRstTmp = pRstTmp->pNext;
    }

_exit:
    std::string strOutResult;
    Json::Value jsResult;
    jsResult["code"] = (unsigned long long)dwErrCode;
    jsResult["desc"] = dwErrCode == ERROR_SUCCESS ? "Succeed" : UtilsUnicodeToString(szErrMsg);
    jsResult["accounts"].resize(0);
    Json::Value jsAccount;
    for (std::list<HraDolphinResult>::const_iterator it = lstScanResult.begin(); lstScanResult.end() != it; ++it)
    {
        jsAccount["account_name"]     = it->account_name;
        jsAccount["weak_passwd_flag"] = it->weak_passwd_flag;
        jsAccount["passwd"]           = it->passwd;
        jsResult["accounts"].append(jsAccount);
    }
    strOutResult = jsResult.toStyledString();

    //输出文件
    if (bOutResultFile)
    {
        std::ofstream fOutFile;
        fOutFile.open(UtilsUnicodeToString(szResultFile).c_str(), std::ios::trunc);
        if (fOutFile.is_open())
        {
            fOutFile.write(strOutResult.c_str(), strOutResult.length());
            fOutFile.flush();
            fOutFile.close();
            LOGW_INFO(L"Write file succeed! file:%s", szResultFile);
        }
        else
        {
            dwErrCode = errno;
            _snwprintf_s(szErrMsg, sizeof(szErrMsg) / sizeof(wchar_t), L"Open file error! file:%s", szResultFile);
            LOGW_ERROR(szErrMsg);
            jsResult["code"] = (unsigned long long)dwErrCode;
            jsResult["desc"] = dwErrCode == ERROR_SUCCESS ? "Succeed" : UtilsUnicodeToString(szErrMsg);
            strOutResult     = jsResult.toStyledString();
        }
    }

    LOG_INFO("Result json:\n%s", strOutResult.c_str());
    LOG_INFO("hra_dolphin exit! code:%lu", dwErrCode);
    // 恢复标准输出
    stdOutRedirectHelper.Restore();
    printf(strOutResult.c_str());
    return dwErrCode;
}
