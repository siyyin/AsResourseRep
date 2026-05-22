#include "LogMgr.h"
#include "utility/comm.h"
#include "utility/Logger.h"
#include "utility/HraAppDef.h"
#include "utility/HraUtils.h"
#include "utility/ConfigSave.h"

struct LogMgrWorkEntry
{
    int iLogLevel;//日志等级
    int iLogAge;//日志时效

    LogMgrWorkEntry()
    {
        clear();
    }

    void clear()
    {
        iLogLevel = (int)LOG_LEVEL_INFO;
        iLogAge   = HRA_LOG_AGE_ONCE;
    }
};

int LogMgrCfgParse(LogMgrWorkEntry& stEntry, const Json::Value& jsContect)
{
    stEntry.clear();

    //log_level
    if (!jsContect.isMember(HRA_PARAM_LOG_LEVEL) || !jsContect[HRA_PARAM_LOG_LEVEL].isInt())
    {
        LOG_ERROR("Parse json log_level error!");
        return HRA_NOT_FOUND;
    }
    stEntry.iLogLevel = jsContect[HRA_PARAM_LOG_LEVEL].asInt();
    if (stEntry.iLogLevel > (int)LOG_LEVEL_ERROR)
    {
        LOG_WARN("Parse json log_level:%d error!", stEntry.iLogLevel);
        stEntry.iLogLevel = LOG_LEVEL_ERROR;
    }
    else if (stEntry.iLogLevel < (int)LOG_LEVEL_DEBUG)
    {
        LOG_WARN("Parse json log_level:%d error!", stEntry.iLogLevel);
        stEntry.iLogLevel = LOG_LEVEL_DEBUG;
    }
    LOG_INFO("Parse log_level:%d", stEntry.iLogLevel);

    //log_age
    if (!jsContect.isMember(HRA_PARAM_LOG_AGE) || !jsContect[HRA_PARAM_LOG_AGE].isInt())
    {
        stEntry.iLogAge = HRA_LOG_AGE_ONCE;
        LOG_INFO("Parse json log_age not found! use default!");
    }
    else
    {
        stEntry.iLogAge = jsContect[HRA_PARAM_LOG_AGE].asInt();
        if (stEntry.iLogAge != HRA_LOG_AGE_ONCE && stEntry.iLogAge != HRA_LOG_AGE_LONG)
        {
            LOG_WARN("Parse json log_age:%d error!", stEntry.iLogAge);
            stEntry.iLogAge = HRA_LOG_AGE_ONCE;
        }
        LOG_INFO("Parse json log_age:%d", stEntry.iLogAge);
    }
    

    return HRA_OK;
}

int LogMgrInit()
{
    return HRA_OK;
}

int LogMgrDestroy()
{
    return HRA_OK;
}

int LogMgrCfgHandle(const Json::Value& jsContect)
{
    LogMgrWorkEntry stEntry;
    int ret = LogMgrCfgParse(stEntry, jsContect);
    if (ret != HRA_OK)
    {
        return ret;
    }

    CLoger::SetLogLevel((LOG_LEVEL)stEntry.iLogLevel);
    LOG_INFO("Set log level:%d", stEntry.iLogLevel);

    g_ConfigSave.ConfigSaveSetIntegerValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_LOG_LEVEL, stEntry.iLogLevel);
    g_ConfigSave.ConfigSaveSetIntegerValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_LOG_AGE, stEntry.iLogAge);

    return HRA_OK;
}