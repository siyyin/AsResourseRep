#include "VulnPocEngine.h"
#include "VulnPocExtendFun.h"
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "Libs/LibPatternCypher/PatternCypher.h"
#include <vector>
#include <regex>

//PATTERN_HEADER g_pthHeader = {0};
/// <summary>
/// 异常处理函数
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
static int manal_atpanic(lua_State* L)
{
    const char* message = lua_tostring(L, -1);
    if (message != NULL)
    {
        LOG_ERROR(message);
    }
    else
    {
        LOG_ERROR("An unexpected error occurred and forced the lua state to call atpanic");
    }
    return 0;
}

VULN_POC_SCAN_CONTEXT* VPEInitialize()
{
    // 创建lua解释器
    VULN_POC_SCAN_CONTEXT* pScanContext = (VULN_POC_SCAN_CONTEXT*)malloc(sizeof(VULN_POC_SCAN_CONTEXT));
    if (!pScanContext)
    {
        LOG_ERROR("pScanContext malloc failed!");
        return NULL;
    }
    memset(pScanContext, 0, sizeof(VULN_POC_SCAN_CONTEXT));

    // pLuaState
    pScanContext->pLuaState = (void*)luaL_newstate();
    if (pScanContext->pLuaState == NULL)
    {
        LOG_ERROR("luaL_newstate failed");
        VPEUnInitialize(&pScanContext);
        return NULL;
    }
    // 载入Lua解释器会用到库
    luaL_openlibs((lua_State*)pScanContext->pLuaState);
    //注册扩展函数
    luaL_register((lua_State*)pScanContext->pLuaState, "extendFunc", extendFunc);
    lua_atpanic((lua_State*)pScanContext->pLuaState, manal_atpanic);
    lua_pop((lua_State*)pScanContext->pLuaState, 1);

    //LOG_DEBUG("Lua stack num:%d", lua_gettop((lua_State*)pScanContext->pLuaState));
    return pScanContext;
}

int VPEAddRequirePath(VULN_POC_SCAN_CONTEXT* pScanContext, const char* pszPath, const char* pszVersion)
{
    if (pScanContext == NULL || pszPath == NULL || strlen(pszPath) <= 0 || pszVersion == NULL ||
        strlen(pszVersion) <= 0)
    {
        LOG_ERROR("Param NULL!");
        return HRA_BAD_PARAM;
    }

    //判断路径是否存在
    if (!IsDirExist(UtilsStringToUnicode(pszPath).c_str()))
    {
        LOG_ERROR("Path not exist! %s", pszPath);
        return HRA_NOT_FOUND;
    }

    char szFullPath[MAX_PATH] = {0};
    DWORD dwPathLen           = GetFullPathNameA(pszPath, sizeof(szFullPath) - 1, szFullPath, NULL);
    if (dwPathLen == 0)
    {
        LOG_ERROR("GetFullPathNameA error! code:%lu, path:%s", GetLastError(), pszPath);
        return HRA_NOT_FOUND;
    }
    LOG_DEBUG("Full path:%s", szFullPath);

    //获得当前pattern信息
    //std::string strWorkPath    = UtilsGetWorkPath();
    //std::string strVulnVersion = UtilsGetVulnPocPatternVersion();
    char szPathAddTmp[MAX_PATH] = {0};
    _snprintf_s(szPathAddTmp, sizeof(szPathAddTmp), "%s\\?$%s", szFullPath, pszVersion);
    std::string strPathAdd = szPathAddTmp;
    _snprintf_s(szPathAddTmp, sizeof(szPathAddTmp), ";%s\\?.lua", szFullPath);
    strPathAdd += szPathAddTmp;

    //将pszPath及下面子目录添加入包含路径
    std::string strFileFilter = szFullPath;
    strFileFilter += "\\*";
    WIN32_FIND_DATAA FindFileData;
    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATAA));
    HANDLE hFind = FindFirstFileA(strFileFilter.c_str(), &FindFileData);
    if (INVALID_HANDLE_VALUE == hFind)
    {
        LOG_ERROR("hFind INVALID! Path:%s", strFileFilter.c_str());
        return HRA_OPEN_FAIL;
    }
    do
    {
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            if ((strcmp(FindFileData.cFileName, ".") != 0) &&
                (strcmp(FindFileData.cFileName, "..") != 0)) //如果不是"." ".."目录
            {
                _snprintf_s(szPathAddTmp, sizeof(szPathAddTmp), ";%s\\%s\\?$%s", szFullPath, FindFileData.cFileName,
                            pszVersion);
                strPathAdd += szPathAddTmp;
                _snprintf_s(szPathAddTmp, sizeof(szPathAddTmp), ";%s\\%s\\?.lua", szFullPath, FindFileData.cFileName);
                strPathAdd += szPathAddTmp;
            }
        }
    } while (FindNextFileA(hFind, &FindFileData) != 0);
    FindClose(hFind);

    //添加require搜索路径
    lua_getglobal((lua_State*)pScanContext->pLuaState, "package");//index +1
    lua_getfield((lua_State*)pScanContext->pLuaState, -1, "path");//index +1
    std::string strPackagePath = lua_tostring((lua_State*)pScanContext->pLuaState, -1);
    LOG_DEBUG("VulnPoc package.path:%s", strPackagePath.c_str());
    if (!strPackagePath.empty())
    {
        strPackagePath += ";";
    }
    strPackagePath += strPathAdd;
    LOG_DEBUG("VulnPoc package.path:%s", strPackagePath.c_str());

    lua_pushstring((lua_State*)pScanContext->pLuaState, strPackagePath.c_str());//index +1
    lua_setfield((lua_State*)pScanContext->pLuaState, -3, "path");//index -1
    lua_pop((lua_State*)pScanContext->pLuaState, 2);//index -2

    //LOG_DEBUG("Lua stack num:%d", lua_gettop((lua_State*)pScanContext->pLuaState));
    return HRA_OK;
}

int VPELoadPattern(VULN_POC_SCAN_CONTEXT* pScanContext, const char* pszPatternFilePath)
{
    //PATTERN_HEADER stPatternHeader;
    FILE* fEncrypt     = NULL;
    char *pOriginalBuf = NULL, *pEncryptBuf = NULL;
    unsigned long ulOriginalSize = 0, ulEncryptSize = 0;
    int iRet = HRA_OK;

    // 参数校验
    if (!pScanContext || !pszPatternFilePath || strlen(pszPatternFilePath) == 0)
    {
        LOG_ERROR("parameter check failed");
        iRet = HRA_BAD_PARAM;
        return iRet;
    }

    //加载pattern并且解密
#ifdef _WIN32
    fopen_s(&fEncrypt, pszPatternFilePath, "rb");
#else
    fEncrypt = fopen(pszPatternFilePath, "rb");
#endif // _WIN32
    if (!fEncrypt)
    {
        LOG_ERROR("open pattern file failed! %s", pszPatternFilePath);
        iRet = HRA_NULL_PTR;
        goto load_finish;
    }
    //读入加密pattern内容，校验MD5, 解析pattern header
    fseek(fEncrypt, 0, SEEK_END);
    ulEncryptSize = ftell(fEncrypt);
    pEncryptBuf = (char*)malloc(ulEncryptSize);
    if (!pEncryptBuf)
    {
        LOG_ERROR("memory alloc failed");
        iRet = HRA_NULL_PTR;
        goto load_finish;
    }

    memset(pEncryptBuf, 0, ulEncryptSize);
    fseek(fEncrypt, 0, SEEK_SET);
    fread(pEncryptBuf, ulEncryptSize, 1, fEncrypt);
    
    //解密
    int nVersion = 0;
    iRet         = LuaBuffDecode((unsigned char*)pEncryptBuf, ulEncryptSize, nVersion, (unsigned char**)&pOriginalBuf,
                                 ulOriginalSize);
    if (iRet != HRA_OK)
    {
        LOG_ERROR("LuaCypherDecode failed! code:%d", iRet);
        goto load_finish;
    }
    LOG_DEBUG("LuaBuffDecode succeed! file:%s, version:%d", pszPatternFilePath, nVersion);

    int iLuaRet = luaL_dostring((lua_State*)pScanContext->pLuaState, pOriginalBuf);
    if (iLuaRet != 0)
    {
        LOG_ERROR("%s ERROR! Code:%d", pszPatternFilePath, iLuaRet);
        iRet = HRA_FAILED;
        lua_pop((lua_State*)pScanContext->pLuaState, -1);
        goto load_finish;
    }
    LOG_INFO("Lua load succeed! file:%s, version:%d", pszPatternFilePath, nVersion);

load_finish:
    if (pOriginalBuf)
    {
        FreeCypherBuff((unsigned char**) &pOriginalBuf);
        pOriginalBuf = NULL;
    }
    if (pEncryptBuf)
    {
        free(pEncryptBuf);
        pEncryptBuf = NULL;
    }
    if (fEncrypt)
    {
        fclose(fEncrypt);
    }

    // LOG_DEBUG("Lua stack num:%d", lua_gettop((lua_State*)pScanContext->pLuaState));
    return iRet;
}

int VPEExecuteScan(VULN_POC_SCAN_CONTEXT* pScanContext, int& nRetCode, std::string& strRetDetail)
{
    int iRet = HRA_OK;
    //参数检查
    if (!pScanContext || !pScanContext->pLuaState)
    {
        LOG_ERROR("pScanContext or pLuaState NULL!");
        iRet = HRA_BAD_PARAM;
        return iRet;
    }

    ///////////////////////////////////////////////////测试代码
    // 输出全局命名空间表
    //lua_pushvalue((lua_State*)pScanContext->pLuaState, LUA_GLOBALSINDEX);
    //lua_pushnil((lua_State*)pScanContext->pLuaState);
    //while (lua_next((lua_State*)pScanContext->pLuaState, -2))
    //{
    //    // 输出键值对信息
    //    const char* key   = lua_tostring((lua_State*)pScanContext->pLuaState, -2);
    //    const char* value =
    //        lua_typename((lua_State*)pScanContext->pLuaState, lua_type((lua_State*)pScanContext->pLuaState, -1));
    //    LOG_DEBUG("%s = %s", key, value);

    //    // 弹出值，保留键
    //    lua_pop((lua_State*)pScanContext->pLuaState, 1);
    //}
    //lua_pop((lua_State*)pScanContext->pLuaState, 1);
    ///////////////////////////////////////////////////测试代码

    // 扫描函数入栈
    lua_getglobal((lua_State*)pScanContext->pLuaState, "ScanFun");
    if (!lua_isfunction((lua_State*)pScanContext->pLuaState, -1))
    {
        int nCount = lua_gettop((lua_State*)pScanContext->pLuaState);
        for (int i = -1; i >= nCount * (-1); --i)
        {
            LOG_DEBUG("%d lua_type:%s", i,
                lua_typename((lua_State*)pScanContext->pLuaState, lua_type((lua_State*)pScanContext->pLuaState, i)));
        }

        LOG_ERROR("LuaStack top is not function %s, param count:%d",
                  lua_tostring((lua_State*)pScanContext->pLuaState, -1),
                  lua_gettop((lua_State*)pScanContext->pLuaState));
        iRet = HRA_FAILED;
        return iRet;
    }

    // 扫描参数入栈
    //__try {
    do
    {
        // 执行扫描函数
        if (lua_pcall((lua_State*)pScanContext->pLuaState, 0, 2, 0) != 0)
        {
            LOG_ERROR("BLExecuteScan lua_pcall error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
            iRet = HRA_FAILED;
            break;
        }

        // 从虚拟栈中取出扫描结果
        if (!lua_isnumber((lua_State*)pScanContext->pLuaState, -2))
        {
            LOG_ERROR("lua_isnumber error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -2));
            iRet = HRA_FAILED;
            break;
        }
        // 获取返回结果
        nRetCode = (int)lua_tointeger((lua_State*)pScanContext->pLuaState, -2);
        LOG_INFO("Lua ret_code:%d", nRetCode);

        if (!lua_isstring((lua_State*)pScanContext->pLuaState, -1))
        {
            LOG_ERROR("lua_isstring error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
            iRet = HRA_FAILED;
            break;
        }
        strRetDetail = lua_tostring((lua_State*)pScanContext->pLuaState, -1);
        LOG_INFO("Lua ret_detail:%s", strRetDetail.c_str());

    } while (false);
    lua_pop((lua_State*)pScanContext->pLuaState, 2);

    //}
    //__except (EXCEPTION_EXECUTE_HANDLER) {
    //	return false;
    //}

    //LOG_DEBUG("Lua stack num:%d", lua_gettop((lua_State*)pScanContext->pLuaState));
    return iRet;
}


void VPEUnInitialize(VULN_POC_SCAN_CONTEXT** ppScanContext)
{
    if (ppScanContext != NULL && *ppScanContext != NULL)
    {
        if ((*ppScanContext)->pLuaState)
        {
            lua_close((lua_State*)(*ppScanContext)->pLuaState);
            (*ppScanContext)->pLuaState = NULL;
        }

        free(*ppScanContext);
        *ppScanContext = NULL;
    }
}

/// <summary>
/// 重载lua loader
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
static int RequireLoader(lua_State* L)
{
    //int nRet = 0;
    // 获取模块名
    std::string module_name = luaL_checkstring(L, 1);
    LOG_DEBUG("module_name:%s", module_name.c_str());
    // 将.替换为/
    std::string::size_type nDotPos;
    while ((nDotPos = module_name.find(".")) != std::string::npos)
    {
        module_name.replace(nDotPos, 1, "\\");
    }

    std::string strRequireLuaPath;
    lua_getglobal(L, "package"); // index +1
    lua_getfield(L, -1, "path"); // index +1
    std::string strPackagePath = lua_tostring(L, -1);
    lua_pop(L, 2);

    //LOG_DEBUG("strPackagePath:%s", strPackagePath.c_str());

    bool bFind                              = false;
    std::vector<std::string> vctPackagePath = UtilsStringSplit(strPackagePath, ";");
    for (std::vector<std::string>::const_iterator it = vctPackagePath.begin(); it != vctPackagePath.end(); ++it)
    {
        std::string::size_type nPos;
        strRequireLuaPath = *it;
        //将?替换为module_name
        while ((nPos = strRequireLuaPath.find("?")) != std::string::npos)
        {
            strRequireLuaPath.replace(nPos, 1, module_name);
        }
        //判断文件是否存在
        if (!UtilsIsFileExist(UtilsStringToUnicode(strRequireLuaPath).c_str()))
        {
            continue;
        }

        //文件存在
        bFind = true;
        break;
    }
    if (!bFind)
    {
        LOG_WARN("Moudle:%s not found!", module_name.c_str());
        return 0; // 未找到模块文件，返回 0 表示搜索器无法处理该模块
    }
    
    //判断文件名结束符，来判断文件是否加密
    bool bCrypt = false;
    std::regex strFileNamePattern(".+\\$[0-9]+$");
    std::smatch retMatch;
    if (std::regex_search(strRequireLuaPath, retMatch, strFileNamePattern))
    {
        bCrypt = true;
    }

    // 尝试打开模块文件
    FILE* file = fopen(strRequireLuaPath.c_str(), "rb");
    if (file == NULL)
    {
        char errMsg[MAX_PATH] = {0};
        strerror_s(errMsg, MAX_PATH, errno);
        LOG_ERROR("Open file:%s error! code:%d, msg:%s", strRequireLuaPath.c_str(), errno, errMsg);
        return 0; // 未找到模块文件，返回 0 表示搜索器无法处理该模块
    }

    // 读取模块文件内容
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* file_content = (char*)malloc(file_size);
    if (file_content == NULL)
    {
        LOG_ERROR("malloc error!");
        return 0; 
    }
    memset(file_content, 0, file_size);
    fread(file_content, file_size, 1, file);
    fclose(file);

    //如果是加密文件则解密
    char* pOriginalBuf = NULL;
    unsigned long ulOriginalSize = 0;
    int nVersion                 = 0;
    if (bCrypt)
    {
        if (LuaBuffDecode((unsigned char*)file_content, file_size, nVersion, (unsigned char**)&pOriginalBuf,
                          ulOriginalSize) != HRA_OK)
        {
            LOG_ERROR("LuaBuffDecode error! %s", strRequireLuaPath.c_str());
            if (file_content)
            {
                free(file_content);
                file_content = NULL;
            }
            if (pOriginalBuf)
            {
                FreeCypherBuff((unsigned char**)&pOriginalBuf);
                file_content = NULL;
            }
            return 0;
        }
        LOG_DEBUG("LuaBuffDecode succeed! %s", strRequireLuaPath.c_str());
    }
    else
    {
        pOriginalBuf = (char*)malloc(file_size + 1);
        if (!pOriginalBuf)
        {
            LOG_ERROR("malloc error! size:%d", (int)(file_size + 1));
            if (file_content)
            {
                free(file_content);
                file_content = NULL;
            }
            return 0;
        }
        memset(pOriginalBuf, 0, file_size + 1);
        memcpy(pOriginalBuf, file_content, file_size);
        ulOriginalSize = file_size;
    }
    LOG_DEBUG("Read file succeed! %s", strRequireLuaPath.c_str());

    // 编译模块文件内容为函数并压入栈顶
    if (luaL_loadbuffer(L, pOriginalBuf, ulOriginalSize, module_name.c_str()) != 0)
    {
        const char* error_msg = lua_tostring(L, -1);
        LOG_ERROR("loadbuffer error: %s, %s", error_msg, strRequireLuaPath.c_str());
        if (file_content)
        {
            free(file_content);
            file_content = NULL;
        }
        if (pOriginalBuf)
        {
            free(pOriginalBuf);
            //FreeCypherBuff((unsigned char**)&pOriginalBuf);
            pOriginalBuf = NULL;
        }
        return 0; // 编译出错，返回 0 表示搜索器无法处理该模块
    }
    LOG_INFO("Load file succeed! %s", strRequireLuaPath.c_str());

    // 释放资源并返回 1 表示成功加载模块
    if (file_content)
    {
        free(file_content);
        file_content = NULL;
    }
    if (pOriginalBuf)
    {
        free(pOriginalBuf);
        //FreeCypherBuff((unsigned char**)&pOriginalBuf);
        pOriginalBuf = NULL;
    }
    return 1;
}

/// <summary>
/// 注册自定义搜索器函数
/// </summary>
/// <param name="pScanContext"></param>
/// <returns></returns>
int VPERegistLoadFunction(VULN_POC_SCAN_CONTEXT* pScanContext)
{
    int iRet = HRA_OK;
    if (pScanContext == NULL || pScanContext->pLuaState == NULL)
    {
        iRet = HRA_NULL_PTR;
        return iRet;
    }

    lua_State* L = (lua_State*)pScanContext->pLuaState;
    // 获取 package 表
    lua_getglobal(L, "package");
    // 获取 loaders 字段，并将其压入栈顶
    lua_getfield(L, -1, "loaders");
    // 将自定义搜索器函数压入栈顶
    lua_pushcfunction(L, RequireLoader);
    // 将自定义搜索器函数添加到 loaders 数组的末尾
    //lua_rawseti(L, -2, (int)lua_objlen(L, -2) + 1);
    lua_rawseti(L, -2, 2);
    // 弹出栈顶的 loaders 数组和 package 表
    lua_pop(L, 2);


    return iRet;
}

/// <summary>
/// 执行lua脚本
/// </summary>
/// <param name="nRetCode"></param>
/// <param name="strRetDetail"></param>
/// <param name="strLuaPath"></param>
/// <returns></returns>
int VulnPocExecuteScan(int& nRetCode, std::string& strRetDetail, const std::string& strLuaFilePath)
{
    if (strLuaFilePath.empty())
    {
        LOG_ERROR("Path empty!");
        return HRA_BAD_PARAM;
    }
    LOG_INFO("VulnPocExecuteScan start! path:%s", strLuaFilePath.c_str());

    int nRet = HRA_OK;
    std::string strLuaPath;
    std::string strLuaFileName;
    std::string strVersion;
    std::string::size_type nPos = strLuaFilePath.rfind("\\");
    if (nPos == std::string::npos)
    {
        LOG_ERROR("Lua file path error! path:%s", strLuaFilePath.c_str());
        return HRA_FAILED;
    }

    strLuaPath     = strLuaFilePath.substr(0, nPos);
    strLuaFileName = strLuaFilePath.substr(nPos + 1, strLuaFilePath.length() - nPos - 1);

    nPos = strLuaFileName.rfind("$");
    if (nPos == std::string::npos)
    {
        LOG_ERROR("Lua file name error!");
        return HRA_FAILED;
    }
    strVersion = strLuaFileName.substr(nPos + 1, strLuaFileName.length() - nPos - 1);

    //初始化
    VULN_POC_SCAN_CONTEXT* pScanContext = VPEInitialize();
    if (pScanContext == NULL)
    {
        LOG_ERROR("VPEInitialize error!");
        return HRA_FAILED;
    }

    //添加require搜索路径
    nRet = VPEAddRequirePath(pScanContext, strLuaPath.c_str(), strVersion.c_str());
    if (nRet != HRA_OK)
    {
        LOG_ERROR("VPEAddRequirePath error!");
        VPEUnInitialize(&pScanContext);
        return nRet;
    }

    //自定义loader函数
    nRet = VPERegistLoadFunction(pScanContext);
    if (nRet != HRA_OK)
    {
        LOG_ERROR("VPERegistLoadFunction error!");
        VPEUnInitialize(&pScanContext);
        return nRet;
    }

    //加载pattern进内存
    nRet = VPELoadPattern(pScanContext, strLuaFilePath.c_str());
    if (nRet != HRA_OK)
    {
        LOG_ERROR("VPELoadPattern error!");
        VPEUnInitialize(&pScanContext);
        return nRet;
    }

    //执行
    nRet = VPEExecuteScan(pScanContext, nRetCode, strRetDetail);
    if (nRet != HRA_OK)
    {
        LOG_ERROR("VPEExecuteScan error!");
        VPEUnInitialize(&pScanContext);
        return nRet;
    }

    LOG_INFO("VPEExecuteScan succeed! RetCode:%d, RetDetail:%s", nRetCode, strRetDetail.c_str());
    VPEUnInitialize(&pScanContext);
    return HRA_OK;
}