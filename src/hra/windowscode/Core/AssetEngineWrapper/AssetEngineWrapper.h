#pragma once
#include <atomic>
#include <string>

#ifdef ASSET_ENGINE_WRAPPER_API_COMPILED
#define ASSET_ENGINE_WRAPPER_API __declspec(dllexport)
#else
#define ASSET_ENGINE_WRAPPER_API __declspec(dllimport)
#endif

class ASSET_ENGINE_WRAPPER_API AssetEngineWrapper
{
public:
    static AssetEngineWrapper& getInstance();

    int GetDllLoadCount();
    bool EngineScan(std::string& strResult, const std::string& strCmdParam);
    bool EngineCancel(std::string& strResult, const std::string& strCmdParam);

private:
    std::atomic<int> m_nDllLoadCount;

private:
    AssetEngineWrapper();
    virtual ~AssetEngineWrapper();
};
