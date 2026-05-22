#include "RegReport.h"
#include "utility/comm.h"
#include "utility/Logger.h"
#include "utility/HraJson.h"
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
//#include "HraIpcInterface/HraIpcCommDef.h"

struct RegReportWorkEntry
{
    //预留，暂无任何作用
    RegReportWorkEntry()
    {
        clear();
    }

    void clear()
    {
    }
};

int RegReportCfgParse(RegReportWorkEntry& stEntry, const Json::Value& jsContect)
{
    stEntry.clear();
    return HRA_OK;
}

int RegReportInit()
{
    return HRA_OK;
}

int RegReportDestroy()
{
    return HRA_OK;
}

int RegReportCfgHandle(const Json::Value& jsContect)
{
    RegReportWorkEntry stEntry;
    int ret = RegReportCfgParse(stEntry, jsContect);
    if (ret != HRA_OK)
    {
        return ret;
    }

    /* 获取注册信息 */
    std::string strRegsterInfo = GetRegsterInfo();
    LOG_DEBUG("Registration information len:%u, str:%s", (unsigned int)(strRegsterInfo.length()), strRegsterInfo.c_str());

    CReportInfo cReportInfo;    /* 生成上报对象*/
    ret = cReportInfo.Request(HraMsgHead::MsgType::REGISTER, RspMsgType::AGENT_REG_INFO, strRegsterInfo.c_str(),
                              strRegsterInfo.size());
    if (ret != HRA_OK)
    {
        LOG_ERROR("Hra regster info report failed");
        return ret;
    }

    LOG_INFO("Hra regster info end.");

    return HRA_OK;
}