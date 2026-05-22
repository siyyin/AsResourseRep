#include "AssetEngineWrapper.h"
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "json/json.h"
#include <Windows.h>

#define ASSET_PATTERN_ENGINE_DLL    "AssetEngine.dll"
#define HRA_ENGINE_LOG_FUN_ENTRY    "EngineRegistLogFun"
#define HRA_ENGINE_SCAN_ENTRY       "EngineScanEntry"
#define HRA_ENGINE_CANCEL_ENTRY     "EngineCancelEntry"
#define HRA_ENGINE_FREE_ENTRY       "EngineFreeEntry"
typedef DWORD (*EngineScanEntry)(char** ppszResult, const char* pszCmdParam);
typedef DWORD (*EngineCancelEntry)(char** ppszResult, const char* pszCmdParam);
typedef void (*EngineFreeEntry)(void** ppszResult);
typedef void (*EngineRegistLogFun)(EngineLogFun pFun);

AssetEngineWrapper::AssetEngineWrapper()
{
    m_nDllLoadCount = 0;
}

AssetEngineWrapper ::~AssetEngineWrapper()
{

}

AssetEngineWrapper& AssetEngineWrapper::getInstance()
{
    static AssetEngineWrapper instance;
    return instance;
}

/// <summary>
/// dll是否被加载
/// </summary>
/// <returns></returns>
int AssetEngineWrapper::GetDllLoadCount()
{
    return m_nDllLoadCount;
}

/// <summary>
/// 扫描执行函数
/// </summary>
/// <param name="strResult"></param>
/// <param name="strCmdParam"></param>
/// <returns></returns>
bool AssetEngineWrapper::EngineScan(std::string& strResult, const std::string& strCmdParam)
{
    char szPatternEnginePath[MAX_PATH]        = {0};
    HMODULE hAssetEngineModule                = NULL;
    EngineScanEntry pAssetEngineScanEntry     = NULL;
    EngineFreeEntry pAssetEngineFreeEntry     = NULL;
    EngineRegistLogFun pEngineRegistLogFun    = NULL;
    char* pszScanResult                       = NULL;
    bool bRet                                 = false;

#ifdef _WIN64
    _snprintf_s(szPatternEnginePath, sizeof(szPatternEnginePath), "%s%s\\%s\\%s", ASSET_PATTERN_DIR, "data\\engine",
                "x64", ASSET_PATTERN_ENGINE_DLL);
#else
    _snprintf_s(szPatternEnginePath, sizeof(szPatternEnginePath), "%s%s\\%s\\%s", ASSET_PATTERN_DIR, "data\\engine",
                "Win32", ASSET_PATTERN_ENGINE_DLL);
#endif // _WIN64

    // 加载资产引擎
    hAssetEngineModule = LoadLibrary(UtilsStringToUnicode(szPatternEnginePath).c_str());
    if (!hAssetEngineModule)
    {
        LOG_ERROR("LoadLibrary:%s error! %lu", szPatternEnginePath, GetLastError());
        goto _exit;
    }
    ++m_nDllLoadCount;
    LOG_INFO("LoadLibrary:%s succeed! Load count:%d", szPatternEnginePath, m_nDllLoadCount);

    // 注册日志函数
    pEngineRegistLogFun = (EngineRegistLogFun)GetProcAddress(hAssetEngineModule, HRA_ENGINE_LOG_FUN_ENTRY);
    if (!pEngineRegistLogFun)
    {
        LOG_ERROR("GetProcAddress:%s error! %lu", HRA_ENGINE_LOG_FUN_ENTRY, GetLastError());
        goto _exit;
    }
    LOG_INFO("GetProcAddress:%s succeed!", HRA_ENGINE_LOG_FUN_ENTRY);
    pEngineRegistLogFun(&EngineLogFunEntry);
    LOG_INFO("Regist engine log function succeed!");

    /// 获取释放函数指针
    pAssetEngineScanEntry = (EngineScanEntry)GetProcAddress(hAssetEngineModule, HRA_ENGINE_SCAN_ENTRY);
    if (!pAssetEngineScanEntry)
    {
        LOG_ERROR("GetProcAddress:%s error! %lu", HRA_ENGINE_SCAN_ENTRY, GetLastError());
        goto _exit;
    }
    LOG_INFO("GetProcAddress:%s succeed!", HRA_ENGINE_SCAN_ENTRY);

    pAssetEngineFreeEntry = (EngineFreeEntry)GetProcAddress(hAssetEngineModule, HRA_ENGINE_FREE_ENTRY);
    if (!pAssetEngineFreeEntry)
    {
        LOG_ERROR("GetProcAddress:%s error! %lu", HRA_ENGINE_FREE_ENTRY, GetLastError());
        goto _exit;
    }
    LOG_INFO("GetProcAddress:%s succeed!", HRA_ENGINE_FREE_ENTRY);

    // 执行扫描
    if (pAssetEngineScanEntry(&pszScanResult, strCmdParam.c_str()) != 0)
    {
        LOG_ERROR("%s excute error!", HRA_ENGINE_SCAN_ENTRY);
        goto _exit;
    }

    if (!pszScanResult)
    {
        LOG_ERROR("pszScanResult NULL!");
        goto _exit;
    }

    strResult = pszScanResult;
    bRet      = true;
    LOG_INFO("AssetEngineWrapper ExcuteCmd succeed!");

_exit:
    // 释放result结果
    if (pAssetEngineFreeEntry)
    {
        if (pszScanResult)
        {
            pAssetEngineFreeEntry((void**)&pszScanResult);
            pszScanResult = NULL;
        }
    }
    // 释放dll
    if (hAssetEngineModule)
    {
        FreeLibrary(hAssetEngineModule);
        hAssetEngineModule = NULL;
        --m_nDllLoadCount;
        LOG_INFO("FreeLibrary:%s succeed! Load count:%d", szPatternEnginePath, m_nDllLoadCount);
    }

    return bRet;
}

bool AssetEngineWrapper::EngineCancel(std::string& strResult, const std::string& strCmdParam)
{
    char szPatternEnginePath[MAX_PATH]        = {0};
    HMODULE hAssetEngineModule                = NULL;
    EngineCancelEntry pAssetEngineCancelEntry = NULL;
    EngineFreeEntry pAssetEngineFreeEntry     = NULL;
    EngineRegistLogFun pEngineRegistLogFun    = NULL;
    char* pszScanResult                       = NULL;
    bool bRet                                 = false;

    if (m_nDllLoadCount <= 0)
    {
        bRet = true;
        LOG_INFO("Dll not loaded, no need to cancel! %d", m_nDllLoadCount);
        goto _exit;
    }

#ifdef _WIN64
    _snprintf_s(szPatternEnginePath, sizeof(szPatternEnginePath), "%s%s\\%s\\%s", ASSET_PATTERN_DIR, "data\\Engine",
                "x64", ASSET_PATTERN_ENGINE_DLL);
#else
    _snprintf_s(szPatternEnginePath, sizeof(szPatternEnginePath), "%s%s\\%s\\%s", ASSET_PATTERN_DIR, "data\\Engine",
                "Win32", ASSET_PATTERN_ENGINE_DLL);
#endif // _WIN64

    // 加载资产引擎
    hAssetEngineModule = LoadLibrary(UtilsStringToUnicode(szPatternEnginePath).c_str());
    if (!hAssetEngineModule)
    {
        LOG_ERROR("LoadLibrary:%s error! %lu", szPatternEnginePath, GetLastError());
        goto _exit;
    }
    ++m_nDllLoadCount;
    LOG_INFO("LoadLibrary:%s succeed! Load count:%d", szPatternEnginePath, m_nDllLoadCount);

    // 注册日志函数
    pEngineRegistLogFun = (EngineRegistLogFun)GetProcAddress(hAssetEngineModule, HRA_ENGINE_LOG_FUN_ENTRY);
    if (!pEngineRegistLogFun)
    {
        LOG_ERROR("GetProcAddress:%s error! %lu", HRA_ENGINE_LOG_FUN_ENTRY, GetLastError());
        goto _exit;
    }
    LOG_INFO("GetProcAddress:%s succeed!", HRA_ENGINE_LOG_FUN_ENTRY);
    pEngineRegistLogFun(&EngineLogFunEntry);
    LOG_INFO("Regist engine log function succeed!");

    /// 获取释放函数指针
    pAssetEngineCancelEntry = (EngineCancelEntry)GetProcAddress(hAssetEngineModule, HRA_ENGINE_CANCEL_ENTRY);
    if (!pAssetEngineCancelEntry)
    {
        LOG_ERROR("GetProcAddress:%s error! %lu", HRA_ENGINE_CANCEL_ENTRY, GetLastError());
        goto _exit;
    }
    LOG_INFO("GetProcAddress:%s succeed!", HRA_ENGINE_CANCEL_ENTRY);

    pAssetEngineFreeEntry = (EngineFreeEntry)GetProcAddress(hAssetEngineModule, HRA_ENGINE_FREE_ENTRY);
    if (!pAssetEngineFreeEntry)
    {
        LOG_ERROR("GetProcAddress:%s error! %lu", HRA_ENGINE_FREE_ENTRY, GetLastError());
        goto _exit;
    }
    LOG_INFO("GetProcAddress:%s succeed!", HRA_ENGINE_FREE_ENTRY);

    // 执行扫描
    if (pAssetEngineCancelEntry(&pszScanResult, strCmdParam.c_str()) != 0)
    {
        LOG_ERROR("%s excute error!", HRA_ENGINE_CANCEL_ENTRY);
        goto _exit;
    }

    if (!pszScanResult)
    {
        LOG_ERROR("pszScanResult NULL!");
        goto _exit;
    }

    strResult = pszScanResult;
    bRet      = true;
    LOG_INFO("AssetEngineWrapper ExcuteCmd succeed!");

_exit:
    // 释放result结果
    if (pAssetEngineFreeEntry)
    {
        if (pszScanResult)
        {
            pAssetEngineFreeEntry((void**)&pszScanResult);
            pszScanResult = NULL;
        }
    }
    // 释放dll
    if (hAssetEngineModule)
    {
        FreeLibrary(hAssetEngineModule);
        hAssetEngineModule = NULL;
        --m_nDllLoadCount;
        LOG_INFO("FreeLibrary:%s succeed! Load count:%d", szPatternEnginePath, m_nDllLoadCount);
    }

    return bRet;
}
