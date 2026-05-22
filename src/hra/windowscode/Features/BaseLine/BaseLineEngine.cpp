#include "BaseLineEngine.h"
#include "./ExtendFunc/ExtendFunc.h"
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "Libs/LibPatternCypher/PatternCypher.h"
#include <vector>
#include <regex>

#define FIND_PATTERN_PATH_COUNT 3

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

BASE_LINE_SCAN_CONTEXT* BLInitialize()
{
    // 创建lua解释器
    BASE_LINE_SCAN_CONTEXT* pScanContext = (BASE_LINE_SCAN_CONTEXT*)malloc(sizeof(BASE_LINE_SCAN_CONTEXT));
    if (!pScanContext)
    {
        LOG_ERROR("pScanContext malloc failed!");
        return NULL;
    }
    memset(pScanContext, 0, sizeof(BASE_LINE_SCAN_CONTEXT));

    // pLuaState
    pScanContext->pLuaState = (void*)luaL_newstate();
    if (pScanContext->pLuaState == NULL)
    {
        LOG_ERROR("luaL_newstate failed");
        BLUnInitialize(&pScanContext);
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

int BLAddRequirePath(BASE_LINE_SCAN_CONTEXT* pScanContext, const char* pszPath, const char* pszVersion)
{
    if (pScanContext == NULL || pszPath == NULL || strlen(pszPath) <= 0 || pszVersion == NULL ||
        strlen(pszVersion) <= 0)
    {
        LOG_ERROR("Param NULL!");
        return HRA_BAD_PARAM;
    }

    char szForamtTmp[MAX_PATH * 3] = {0};
    _snprintf_s(szForamtTmp, sizeof(szForamtTmp), "%s\\?$%s;%s\\?.lua", pszPath, pszVersion, pszPath);

    //添加require搜索路径
    lua_getglobal((lua_State*)pScanContext->pLuaState, "package");//index +1
    lua_getfield((lua_State*)pScanContext->pLuaState, -1, "path");//index +1
    std::string strPackagePath = lua_tostring((lua_State*)pScanContext->pLuaState, -1);
    //LOG_DEBUG("BaseLine package.path:%s", strPackagePath.c_str());
    if (!strPackagePath.empty())
    {
        strPackagePath += ";";
    }
    strPackagePath += szForamtTmp;
    LOG_DEBUG("BaseLine package.path:%s", strPackagePath.c_str());

    lua_pushstring((lua_State*)pScanContext->pLuaState, strPackagePath.c_str());//index +1
    lua_setfield((lua_State*)pScanContext->pLuaState, -3, "path");//index -1
    lua_pop((lua_State*)pScanContext->pLuaState, 2);//index -2

    //LOG_DEBUG("Lua stack num:%d", lua_gettop((lua_State*)pScanContext->pLuaState));
    return HRA_OK;
}

int BLLoadPattern(BASE_LINE_SCAN_CONTEXT* pScanContext, const char* pszPatternFilePath)
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

int BLExecuteScan(BASE_LINE_SCAN_CONTEXT* pScanContext, int& nRetCode)
{
    int iRet = HRA_OK;
    //参数检查
    if (!pScanContext || !pScanContext->pLuaState)
    {
        LOG_ERROR("pScanContext or pLuaState NULL!");
        iRet = HRA_BAD_PARAM;
        return iRet;
    }

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
        for (int i = 0; i < pScanContext->nParamCount; ++i)
        {
            lua_pushstring((lua_State*)pScanContext->pLuaState, pScanContext->ppszParamList[i]);
        }

        //执行前栈数量
        int nStackSizeBefore = lua_gettop((lua_State*)pScanContext->pLuaState);
        LOG_DEBUG("Stack size before excute:%d", nStackSizeBefore);
        // 执行扫描函数
        if (lua_pcall((lua_State*)pScanContext->pLuaState, pScanContext->nParamCount, LUA_MULTRET, 0) != 0)
        {
            LOG_ERROR("BLExecuteScan lua_pcall error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
            iRet = HRA_FAILED;
            break;
        }

        //获取返回
        int nStackSizeAfter = lua_gettop((lua_State*)pScanContext->pLuaState);
        LOG_DEBUG("Stack size after excute:%d", nStackSizeAfter);
        int nReturnCount    = nStackSizeAfter;
        if (nReturnCount == 1)
        {
            // 从虚拟栈中取出扫描结果
            if (!lua_isnumber((lua_State*)pScanContext->pLuaState, -1))
            {
                LOG_ERROR("lua_isnumber error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
                iRet = HRA_FAILED;
                break;
            }
            // 获取返回结果
            nRetCode = (int)lua_tointeger((lua_State*)pScanContext->pLuaState, -1);
            LOG_INFO("Lua ret_code:%d", nRetCode);
        }
        //else if (nReturnCount == 2)
        //{
        //    // 从虚拟栈中取出扫描结果
        //    //result_code
        //    if (!lua_isnumber((lua_State*)pScanContext->pLuaState, -2))
        //    {
        //        LOG_ERROR("lua_isnumber error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -2));
        //        iRet = HRA_FAILED;
        //        break;
        //    }
        //    nRetCode = (int)lua_tointeger((lua_State*)pScanContext->pLuaState, -2);
        //    LOG_INFO("Lua ret_code:%d", nRetCode);

        //    //detail
        //    if (!lua_isstring((lua_State*)pScanContext->pLuaState, -1))
        //    {
        //        LOG_ERROR("lua_isstring error %s", lua_tostring((lua_State*)pScanContext->pLuaState, -1));
        //        iRet = HRA_FAILED;
        //        break;
        //    }
        //    strRetDetail = lua_tostring((lua_State*)pScanContext->pLuaState, -1);
        //    LOG_INFO("Lua ret_detail:%s", strRetDetail.c_str());
        //}
        else
        {
            LOG_ERROR("Lua return result number error! %d", nReturnCount);
            iRet = HRA_FAILED;
            break;
        }
    } while (false);
    lua_pop((lua_State*)pScanContext->pLuaState, 0);//移除所有栈当中的元素

    //}
    //__except (EXCEPTION_EXECUTE_HANDLER) {
    //	return false;
    //}

    //LOG_DEBUG("Lua stack num:%d", lua_gettop((lua_State*)pScanContext->pLuaState));
    return iRet;
}


void BLUnInitialize(BASE_LINE_SCAN_CONTEXT** ppScanContext)
{
    if (ppScanContext != NULL && *ppScanContext != NULL)
    {
        for (int i = 0; i < (*ppScanContext)->nParamCount; ++i)
        {
            if ((*ppScanContext)->ppszParamList && (*ppScanContext)->ppszParamList[i])
            {
                free((*ppScanContext)->ppszParamList[i]);
                (*ppScanContext)->ppszParamList[i] = NULL;
            }
        }

        if ((*ppScanContext)->ppszParamList)
        {
            free((*ppScanContext)->ppszParamList);
            (*ppScanContext)->ppszParamList = NULL;
        }

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
int BLRegistLoadFunction(BASE_LINE_SCAN_CONTEXT* pScanContext)
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
int BaseLineExcuteScan(int& nRetCode, const std::string& strLuaFilePath, const std::vector<std::string>& vctParams)
{
    int nRet = HRA_OK;
    BASE_LINE_SCAN_CONTEXT* pScanContext = NULL;
    std::string strLuaPath;
    std::string strLuaFileName;
    std::string strVersion;
    std::string::size_type nPos = std::string::npos;
    std::string strLogParamList;
    int nParamCountTmp = 0;
    std::string strRequirePath;

    if (strLuaFilePath.empty())
    {
        LOG_ERROR("Path empty!");
        nRet = HRA_BAD_PARAM;
        goto _exit;
    }
    LOG_INFO("BaseLineExcuteScan start! path:%s", strLuaFilePath.c_str());

    
    //path
    nPos = strLuaFilePath.rfind("\\");
    if (nPos == std::string::npos)
    {
        LOG_ERROR("Lua file path error! path:%s", strLuaFilePath.c_str());
        nRet = HRA_FAILED;
        goto _exit;
    }

    strLuaPath     = strLuaFilePath.substr(0, nPos);
    strLuaFileName = strLuaFilePath.substr(nPos + 1, strLuaFilePath.length() - nPos - 1);

    nPos = strLuaFileName.rfind("$");
    if (nPos == std::string::npos)
    {
        LOG_ERROR("Lua file name error!");
        nRet = HRA_FAILED;
        goto _exit;
    }
    strVersion = strLuaFileName.substr(nPos + 1, strLuaFileName.length() - nPos - 1);

    //初始化
    pScanContext = BLInitialize();
    if (pScanContext == NULL)
    {
        LOG_ERROR("BLInitialize error!");
        nRet = HRA_FAILED;
        goto _exit;
    }

    // 申请参数内存
    pScanContext->nParamCount   = (int)vctParams.size();
    pScanContext->ppszParamList = (char**)malloc(pScanContext->nParamCount * sizeof(char*));
    if (pScanContext->ppszParamList == NULL)
    {
        LOG_ERROR("malloc error!");
        nRet = HRA_FAILED;
        goto _exit;
    }
    memset(pScanContext->ppszParamList, 0, pScanContext->nParamCount * sizeof(char*));

    strLogParamList = "[";
    nParamCountTmp  = 0;
    for (std::vector<std::string>::const_iterator it = vctParams.begin(); vctParams.end() != it; ++it)
    {
        // 前端会将空字符串填充成“NULL”传入，这里需要转换回空字符串
        std::string strParamTmp = it->c_str();
        if (stricmp(strParamTmp.c_str(), "NULL") == 0)
        {
            strParamTmp = "";
        }

        int nSizeParam                              = strParamTmp.length() + 1;
        pScanContext->ppszParamList[nParamCountTmp] = (char*)malloc(nSizeParam);
        if (pScanContext->ppszParamList[nParamCountTmp] == NULL)
        {
            LOG_ERROR("malloc error!");
            nRet = HRA_FAILED;
            goto _exit;
        }
        memset(pScanContext->ppszParamList[nParamCountTmp], 0, nSizeParam);
        _snprintf_s(pScanContext->ppszParamList[nParamCountTmp], nSizeParam, nSizeParam - 1, "%s", strParamTmp.c_str());
        if (nParamCountTmp > 0)
        {
            strLogParamList += ",";
        }
        strLogParamList += strParamTmp;
        ++nParamCountTmp;
    }
    strLogParamList += "]";
    LOG_INFO("Lua param:%s, path:%s", strLogParamList.c_str(), strLuaFilePath.c_str());

    //添加require搜索路径
    strRequirePath = UtilsGetBaselinePatternVersionPath();
    if (strRequirePath.empty())
    {
        LOG_ERROR("UtilsGetBaselinePatternVersionPath empty!");
        goto _exit;
    }
    nPos = strRequirePath.rfind("\\");
    if (nPos == std::string::npos)
    {
        LOG_ERROR("UtilsGetBaselinePatternVersionPath error!");
        goto _exit;
    }
    strRequirePath = strRequirePath.substr(0, nPos);
    nRet           = BLAddRequirePath(pScanContext, strRequirePath.c_str(), strVersion.c_str());
    if (nRet != HRA_OK)
    {
        LOG_ERROR("BLAddRequirePath error!");
        goto _exit;
    }
    LOG_INFO("BLAddRequirePath:%s", strRequirePath.c_str());

    //自定义loader函数
    nRet = BLRegistLoadFunction(pScanContext);
    if (nRet != HRA_OK)
    {
        LOG_ERROR("BLRegistLoadFunction error!");
        goto _exit;
    }

    //加载pattern进内存
    nRet = BLLoadPattern(pScanContext, strLuaFilePath.c_str());
    if (nRet != HRA_OK)
    {
        LOG_ERROR("BLLoadPattern error!");
        goto _exit;
    }

    //执行
    nRet = BLExecuteScan(pScanContext, nRetCode);
    if (nRet != HRA_OK)
    {
        LOG_ERROR("BLExecuteScan error!");
        goto _exit;
    }
    LOG_INFO("BLExecuteScan succeed! RetCode:%d", nRetCode);

_exit:
    BLUnInitialize(&pScanContext);
    return nRet;
}

/// <summary>
/// 通过lua
/// </summary>
/// <param name="strLuaPath"></param>
/// <returns></returns>
//std::wstring FindBaseLinePatternPathFromLuaPath(const std::wstring& strLuaPath, const std::wstring& strVersion)
//{
//    std::wstring strReturn;
//    std::wstring strPathFind = strLuaPath;
//    if (strPathFind.empty())
//    {
//        LOGW_WARN(L"Lua path empty!");
//        goto _exit;
//    }
//    if (!IsDirExist(strPathFind.c_str()))
//    {
//        LOGW_WARN(L"Path not exists! %s", strPathFind.c_str());
//        goto _exit;
//    }
//
//    for (int i = 0; i < FIND_PATTERN_PATH_COUNT; ++i)
//    {
//        wchar_t szPatternFileFind[MAX_PATH] = {0};
//        _snwprintf_s(szPatternFileFind, MAX_PATH, L"%s\\%s$%s", strPathFind.c_str(),
//                     UtilsStringToUnicode(UtilsGetBaselineTypePattenName()).c_str(), strVersion.c_str());
//        if (UtilsIsFileExist(szPatternFileFind))
//        {
//            strReturn = strPathFind;
//            goto _exit;
//        }
//
//        //找这个json文件主要是为了hra_test.exe使用
//        _snwprintf_s(szPatternFileFind, MAX_PATH, L"%s\\%s.json", strPathFind.c_str(),
//                     UtilsStringToUnicode(UtilsGetBaselineTypePattenName()).c_str());
//        if (UtilsIsFileExist(szPatternFileFind))
//        {
//            strReturn = strPathFind;
//            goto _exit;
//        }
//
//        strPathFind += L"\\..";
//    }
//
//_exit:
//    if (!strReturn.empty())
//    {//转换成全路径
//        wchar_t szFullPath[MAX_PATH] = {0};
//        DWORD dwPathLen              = GetFullPathName(strReturn.c_str(), MAX_PATH - 1, szFullPath, NULL);
//        if (dwPathLen > 0)
//        {
//            strReturn = szFullPath;
//        }
//    }
//    LOGW_DEBUG(L"FindBaseLinePatternPathFromLuaPath %s", strReturn.c_str());
//    return strReturn;
//}

/// <summary>
/// 搜索所有子目录，组装require路径
/// </summary>
/// <param name="strFindPath"></param>
/// <returns></returns>
//std::wstring FindRequirePath(const std::wstring& strFindPath, const std::wstring& strVersion)
//{
//    // 判断路径是否存在
//    if (!IsDirExist(strFindPath.c_str()))
//    {
//        LOGW_WARN(L"Path not exist! %s", strFindPath.c_str());
//        return L"";
//    }
//
//    wchar_t szFullPath[MAX_PATH] = {0};
//    DWORD dwPathLen              = GetFullPathName(strFindPath.c_str(), MAX_PATH - 1, szFullPath, NULL);
//    if (dwPathLen == 0)
//    {
//        LOGW_WARN(L"GetFullPathName error! code:%lu, path:%s", GetLastError(), strFindPath.c_str());
//        return L"";
//    }
//    //LOGW_DEBUG(L"------Full path:%s", szFullPath);
//
//    wchar_t szPathAddTmp[MAX_PATH] = {0};
//    _snwprintf_s(szPathAddTmp, MAX_PATH, L"%s\\?$%s", szFullPath, strVersion.c_str());
//    std::wstring strPathAdd = szPathAddTmp;
//    _snwprintf_s(szPathAddTmp, MAX_PATH, L";%s\\?.lua", szFullPath);
//    strPathAdd += szPathAddTmp;
//
//    // 将pszPath及下面子目录添加入包含路径
//    std::wstring strFileFilter = szFullPath;
//    strFileFilter += L"\\*";
//    WIN32_FIND_DATA FindFileData;
//    ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATAA));
//    HANDLE hFind = FindFirstFile(strFileFilter.c_str(), &FindFileData);
//    if (INVALID_HANDLE_VALUE == hFind)
//    {
//        LOGW_ERROR(L"hFind INVALID! Path:%s", strFileFilter.c_str());
//        return strPathAdd;
//    }
//    do
//    {
//        if (!(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
//        {
//            continue;
//        }
//
//        if ((wcscmp(FindFileData.cFileName, L".") == 0) ||
//            (wcscmp(FindFileData.cFileName, L"..") == 0)) // 如果不是"." ".."目录
//        {
//            continue;
//        }
//
//         //搜索子目录
//        wchar_t szSubTmp[MAX_PATH] = {0};
//        _snwprintf_s(szSubTmp, MAX_PATH, L"%s\\%s", szFullPath, FindFileData.cFileName);
//        std::wstring strFindSub = FindRequirePath(szSubTmp, strVersion);
//        if (strFindSub.empty())
//        {
//            continue;
//        }
//
//        if (!strPathAdd.empty())
//        {
//            strPathAdd += L";";
//        }
//        strPathAdd += strFindSub;
//    } while (FindNextFile(hFind, &FindFileData) != 0);
//    FindClose(hFind);
//    //LOGW_DEBUG(L"------strPathAdd:%s", strPathAdd.c_str());
//    return strPathAdd;
//}
