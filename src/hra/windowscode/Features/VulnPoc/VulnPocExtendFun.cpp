#include "VulnPocExtendFun.h"
#include "utility/SocketTcp.h"
#include "utility/Logger.h"
#include "utility/ConfigSave.h"
#include "utility/HraCtrlCmd.h"
#include "utility/UtilsWMICom.h"
#include "utility/HraUtils.h"
#include "utility/HraAssetDef.h"
#include "curl/curl.h"
#include "zlib/unzip.h"
#include "zlib/zconf.h"
#include "zlib/zlib.h"
#include "zlib/zip.h"
#include <algorithm>
#include <list>
#include <regex>

SocketTcpClient g_sockPocLua;

int FunPrintLog(lua_State* L)
{
    int iParaCount = lua_gettop(L);
    if (5 != iParaCount)
    {
        return 0;
    }

    int iLevel             = (int)lua_tointeger(L, 1);
    const char* pszFile    = (const char*)lua_tostring(L, 2);
    const char* pszFun     = (const char*)lua_tostring(L, 3);
    int iLine              = (int)lua_tointeger(L, 4);
    const char* pszLogLine = (const char*)lua_tostring(L, 5);
    std::string strLogLine = pszLogLine == NULL ? "" : pszLogLine;
    std::regex percentRegex("%");
    strLogLine = std::regex_replace(strLogLine, percentRegex, "%%");
    CLoger::Log(iLevel, pszFile == NULL ? "" : pszFile, pszFun == NULL ? "" : pszFun, iLine, strLogLine.c_str());

    return 0;
}


int FunCmdPopen(lua_State* L)
{
    char cmd[256] = "0";

    int iParaCount = lua_gettop(L);
    if (iParaCount != 1)
    {
        return 0;
    }

    if (0 == lua_isstring(L, 1))
    {
        return 0;
    }

    char* pcmd = (char*)lua_tostring(L, 1);
    std::string result;
    ExecuteCmd(&result, pcmd);

    lua_pushstring(L, (const char*)result.c_str());
    return 1;
}

int FunGetHraConfigValue(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 2)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        return 0;
    }
    std::string strTable = lua_tostring(L, 1);

    if (lua_isstring(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 2);
        return 0;
    }
    std::string strKey   = lua_tostring(L, 2);
    std::string strValue = g_ConfigSave.ConfigSaveGetValue(strTable, strKey);
    lua_pushstring(L, strValue.c_str());

    return 1;
}

/// <summary>
/// sleep函数，单位毫秒
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunSleep(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isnumber(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 1);
        return 0;
    }

    unsigned long nMillisecond = (unsigned long)lua_tonumber(L, 1);
    ::Sleep(nMillisecond);

    return 0;
}

/// <summary>
/// 获取控制命令
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetCtrlCmd(lua_State* L)
{
    int iCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
    lua_pushinteger(L, iCmd);
    return 1;
}

/// <summary>
/// 获得资产信息
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetAssets(lua_State* L)
{
    int nRet = 0;
    std::string strAssetType;
    std::string strData;

    //判断参数个数
    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        goto _exit;
    }

    //资产类型
    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        goto _exit;
    }
    strAssetType = lua_tostring(L, 1);

    strData = g_AssetDataDB.ConfigSaveGetValue(GLOBAL_ASSET_TABLE, strAssetType.c_str());
    lua_pushstring(L, strData.c_str());
    nRet = 1;

_exit:
    return nRet;
}

/// <summary>
/// http请求回调header
/// </summary>
/// <param name="contents"></param>
/// <param name="size"></param>
/// <param name="nmemb"></param>
/// <param name="userp"></param>
/// <returns></returns>
size_t WriteHeaderCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

/// <summary>
/// http请求回调body
/// </summary>
/// <param name="contents"></param>
/// <param name="size"></param>
/// <param name="nmemb"></param>
/// <param name="userp"></param>
/// <returns></returns>
size_t WriteBodyCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

/// <summary>
/// 发送http请求
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunHttpRequest(lua_State* L)
{
    int nRet = 0;
    std::string strUrl;
    std::string strMethod;
    std::string strHeader;
    std::string strBody;
    int nTimeOut = 0;

    CURL* curl                 = NULL;
    CURLcode res               = CURLE_OK;
    struct curl_slist* headers = NULL;
    std::string strResponseHeader;
    std::string strResponseBody;
    curl_global_init(CURL_GLOBAL_DEFAULT);

    //判断参数个数
    int paramCount = lua_gettop(L);
    if (paramCount != 5)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        goto _exit;
    }

    // url
    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        goto _exit;
    }
    strUrl = lua_tostring(L, 1);

    // method
    if (lua_isstring(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 2);
        goto _exit;
    }
    strMethod = lua_tostring(L, 2);
    std::transform(strMethod.begin(), strMethod.end(), strMethod.begin(), ::toupper);
    if (strMethod != "GET" && strMethod != "PUT" && strMethod != "POST")
    {
        LOG_ERROR("strMethod:%s error!", strMethod.c_str());
        goto _exit;
    }

    // header
    if (lua_isstring(L, 3) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 3);
        goto _exit;
    }
    strHeader = lua_tostring(L, 3);

    // body
    if (lua_isstring(L, 4) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 4);
        goto _exit;
    }
    strBody = lua_tostring(L, 4);

    // time_out，单位秒
    if (lua_isnumber(L, 5) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 5);
        goto _exit;
    }
    nTimeOut = lua_tonumber(L, 5);
    if (nTimeOut <= 0)
    {
        LOG_ERROR("nTimeOut:%d error!", nTimeOut);
        goto _exit;
    }

    //发送请求
    curl = curl_easy_init();
    if (!curl)
    {
        LOG_ERROR("curl_easy_init error!");
        goto _exit;
    }
    curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, strMethod.c_str());
    if (!strHeader.empty())
    {
        headers = curl_slist_append(headers, strHeader.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }
    if (!strBody.empty())
    {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, strBody.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strBody.length());
    }
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, nTimeOut);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, nTimeOut);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, WriteHeaderCallback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &strResponseHeader);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteBodyCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &strResponseBody);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
    {
        LOG_WARN("request failed! msg:%s, code:%d", curl_easy_strerror(res), (int)res);
    }
    else
    {
        LOG_INFO("request succeed!");
    }
        
    lua_pushnumber(L, (int)res);
    lua_pushstring(L, strResponseHeader.c_str());
    lua_pushstring(L, strResponseBody.c_str());
    nRet = 3;

_exit:
    if (headers)
    {
        curl_slist_free_all(headers);
        headers = NULL;
    }

    if (curl)
    {
        curl_easy_cleanup(curl);
        curl = NULL;
    }

    curl_global_cleanup();
    return nRet;
}

/// <summary>
/// socket链接，可传入IPV4、IPV6、域名
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunSocketConnect(lua_State* L)
{
    int nRet = 0;
    std::string strIP;
    int nPort = 0;
    int nTimeOut = 0;

    //判断参数个数
    int paramCount = lua_gettop(L);
    if (paramCount != 3)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        nRet = -1;
        goto _exit;
    }

    // IP
    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        nRet = -2;
        goto _exit;
    }
    strIP = lua_tostring(L, 1);

    // port
    if (lua_isnumber(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 2);
        nRet = -3;
        goto _exit;
    }
    nPort = lua_tonumber(L, 2);

    // timeout
    if (lua_isnumber(L, 3) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 3);
        nRet = -4;
        goto _exit;
    }
    nTimeOut = lua_tonumber(L, 3);
    if (nTimeOut <= 0)
    {
        LOG_ERROR("nTimeOut:%d error!", nTimeOut);
        nRet = -5;
        goto _exit;
    }
    
    //连接
    if (g_sockPocLua.connect(strIP.c_str(), nPort, nTimeOut) != 0)
    {
        LOG_WARN("connect failed! %s", g_sockPocLua.getErrorMsg());
        nRet = -6;
        goto _exit;
    }
    LOG_INFO("connect succeed! %s", g_sockPocLua.getStatStr());

_exit:
    lua_pushinteger(L, nRet);
    return 1;
}

/// <summary>
/// 发送数据，返回发送数据长度，阻塞模式
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunSocketSend(lua_State* L)
{
    int nRet = 0;
    unsigned char* pData = NULL;
    int nLen = 0;
    int nTimeOut = 0;

    //判断参数个数
    int paramCount = lua_gettop(L);
    if (paramCount != 3)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        nRet = -1;
        goto _exit;
    }

    // len
    if (lua_isnumber(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 2);
        nRet = -3;
        goto _exit;
    }
    nLen = lua_tonumber(L, 2);
    if (nLen <= 0)
    {
        LOG_ERROR("nLen:%d error!", nLen);
        nRet = -4;
        goto _exit;
    }
    pData = (unsigned char*)malloc(nLen + 1);
    memset(pData, 0, nLen + 1);

    // data
    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        nRet = -2;
        goto _exit;
    }
    memcpy_s(pData, nLen + 1, lua_tostring(L, 1), nLen);

    // timeout
    if (lua_isnumber(L, 3) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 3);
        nRet = -5;
        goto _exit;
    }
    nTimeOut = lua_tonumber(L, 3);
    if (nTimeOut <= 0)
    {
        LOG_ERROR("nTimeOut:%d error!", nTimeOut);
        nRet = -6;
        goto _exit;
    }

    //发送
    nRet = g_sockPocLua.send(pData, nLen, nTimeOut);
    if (nRet <= 0)
    {
        LOG_WARN("send failed! %s", g_sockPocLua.getErrorMsg());
        nRet = -7;
        goto _exit;
    }
    LOG_INFO("send succeed! len:%d, %s", nLen, g_sockPocLua.getStatStr());

_exit:
    lua_pushinteger(L, nRet);
    if (pData)
    {
        free(pData);
        pData = NULL;
    }
    return 1;
}

/// <summary>
/// 接收数据，返回接收数据内容，阻塞模式
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunSocketReceive(lua_State* L)
{
    int nRet = 0;
    char* pszRcvBuff = NULL;

    //判断参数个数
    int paramCount = lua_gettop(L);
    if (paramCount != 2)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        nRet = -1;
        goto _exit;
    }

    // len
    if (lua_isnumber(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 2);
        nRet = -2;
        goto _exit;
    }
    int nLen = lua_tonumber(L, 1);
    if (nLen <= 0)
    {
        LOG_ERROR("nLen:%d error!", nLen);
        nRet = -3;
        goto _exit;
    }

    // timeout
    if (lua_isnumber(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 2);
        nRet = -4;
        goto _exit;
    }
    int nTimeOut = lua_tonumber(L, 2);
    if (nTimeOut <= 0)
    {
        LOG_ERROR("nTimeOut:%d error!", nTimeOut);
        nRet = -5;
        goto _exit;
    }

    //接收
    pszRcvBuff = (char*)malloc(nLen + 1);
    if (pszRcvBuff == NULL)
    {
        LOG_ERROR("malloc error!");
        nRet = -6;
        goto _exit;
    }
    memset(pszRcvBuff, 0, nLen + 1);
    nRet = g_sockPocLua.receive(pszRcvBuff, nLen, nTimeOut);
    if (nRet <= 0)
    {
        LOG_WARN("receive failed! %s", g_sockPocLua.getErrorMsg());
        nRet = -7;
        goto _exit;
    }
    LOG_INFO("send succeed! len:%d, %s", nLen, g_sockPocLua.getStatStr());

_exit:
    lua_pushstring(L, pszRcvBuff == NULL ? "" : pszRcvBuff);
    if (pszRcvBuff != NULL)
    {
        free(pszRcvBuff);
        pszRcvBuff = NULL;
    }
    return 1;
}

/// <summary>
/// 关闭socket句柄
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunSocketClose(lua_State* L)
{
    g_sockPocLua.close();
    return 0;
}

/// <summary>
/// 操作系统名称：例：Microsoft Windows 10 家庭中文版
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetOsName(lua_State* L)
{
    std::string strOsName = UtilsGetOsReleaseName();
    lua_pushstring(L, strOsName.c_str());
    return 1;
}

/// <summary>
/// //获得操作系统位数，例：64 or 32
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetOsBits(lua_State* L)
{
    int nOsBit = 32;
    SYSTEM_INFO sysInfo;
    memset(&sysInfo, 0, sizeof(sysInfo));
    GetNativeSystemInfo(&sysInfo);
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
        sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
    {
        nOsBit = 64;
    }
    lua_pushnumber(L, nOsBit);
    return 1;
}

/// <summary>
/// 获取zip包中的文件列表
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetZipFileList(lua_State* L)
{
    int nRet   = 0;
    int nIndex = 0;
    std::string strZipPath;
    std::list<std::string> lstFileList;

    unzFile pvZipFile = NULL;
    unz_global_info zGlobalInfo;
    memset(&zGlobalInfo, 0, sizeof(zGlobalInfo));
    unz_file_info zFileInfo;
    memset(&zFileInfo, 0, sizeof(zFileInfo));
    char szSubFileName[MAX_PATH];
    memset(szSubFileName, 0, sizeof(szSubFileName));
    
    //判断参数个数
    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        goto _exit;
    }

    // strZipPath
    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        goto _exit;
    }
    strZipPath = lua_tostring(L, 1);
    if (!UtilsIsFileExist(UtilsStringToUnicode(strZipPath).c_str()))
    {
        LOG_ERROR("File:%s not exist!", strZipPath.c_str());
        goto _exit;
    }

    //打开zip文件
    pvZipFile = unzOpen(strZipPath.c_str());
    if (NULL == pvZipFile)
    {
        char errMsg[MAX_PATH] = {0};
        strerror_s(errMsg, MAX_PATH, errno);
        LOG_ERROR("The file is not a compressed file. file:%s, msg:%s", strZipPath.c_str(), errMsg);
        goto _exit;// 可能不是压缩文件，不处理
    }

    //获取压缩文件的全局信息
    if (unzGetGlobalInfo(pvZipFile, &zGlobalInfo) != UNZ_OK)
    {
        LOG_ERROR("Failed to obtain global information about compressed files. file:%s", strZipPath.c_str());
        goto _exit;
    }

    for (int i = 0; i < zGlobalInfo.number_entry; ++i)
    {
        //从压缩包循环获得子文件信息：文件名， 文件大小
        if (UNZ_OK !=
            unzGetCurrentFileInfo(pvZipFile, &zFileInfo, szSubFileName, sizeof(szSubFileName), NULL, 0, NULL, 0))
        {
            LOG_ERROR(" Failed to get child file information . file:%s", strZipPath.c_str());
            goto _exit;
        }

        if (strlen(szSubFileName) == 0)
        {
            LOG_ERROR("Sub file name empty!");
            goto _exit;
        }

        if (_stricmp(szSubFileName, ".") == 0 || _stricmp(szSubFileName, "..") == 0 || 
            _stricmp(szSubFileName, "./") == 0 || _stricmp(szSubFileName, "../") == 0 ||
            _stricmp(szSubFileName, ".\\") == 0 || _stricmp(szSubFileName, "..\\") == 0 )
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }

        lstFileList.push_back(szSubFileName);
        unzGoToNextFile(pvZipFile);
    }
    
    //组装返回table
    lua_newtable(L);
    nIndex = 0;
    for (std::list<std::string>::const_iterator it = lstFileList.begin(); it != lstFileList.end(); ++it)
    {
        ++nIndex;
        lua_pushinteger(L, nIndex);
        lua_pushstring(L, it->c_str());
        lua_settable(L, -3);
    }
    nRet = 1;

_exit:
    if (pvZipFile)
    {
        unzClose(pvZipFile);
    }

    return nRet;
}
