#pragma once
#ifndef _BASELINE_H_
#define _BASELINE_H_
#include "utility/HraPatternUpdateUtils.h"
#include "json/json.h"
#include "utility/comm.h"
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
#include "HRATaskScheduler/HRATaskScheduler.h"

#include "BaseLineDef.h"

#include <set>
#include <string>

//#define BASELINE_BLP_PATTERN_NAME "blp$"
//#ifndef BASELINE_TASK_ID
//#define BASELINE_TASK_ID 128
//#endif

#ifndef BASELINE_POLICY_LEN
#define BASELINE_POLICY_LEN 64
#endif

extern CPatternUpdateUtils g_BaselinePatternUpdateUtils;

struct HRA_BASELINE_EXPORT BaseLineParam
{
    std::vector<std::string> param;

    void clear()
    {
        param.clear();
    }

    BaseLineParam()
    {
        clear();
    }
};

struct HRA_BASELINE_EXPORT BaseLineScanItem
{
    int scan_id;
    int template_type;
    std::string scan_shell;
    std::string pre_shell;
    std::string pst_shell;
    std::vector<BaseLineParam> params;

    void clear()
    {
        scan_id = 0;
        template_type = 0;
        scan_shell.clear();
        pre_shell.clear();
        pst_shell.clear();
        params.clear();
    }

    BaseLineScanItem()
    {
        clear();
    }
};

struct HRA_BASELINE_EXPORT BaseLineWorkEntry
{
    std::string task_id;
    //std::string cmd_src;
    std::vector<BaseLineScanItem> scan_items;

    void clear()
    {
        task_id.clear();
        //cmd_src.clear();
        scan_items.clear();
    }

    BaseLineWorkEntry()
    {
        clear();
    }
};

HRA_BASELINE_EXPORT int BaseLineInit(void);
HRA_BASELINE_EXPORT int BaseLineDestroy(void);
HRA_BASELINE_EXPORT int BaseLineCfgParse(BaseLineWorkEntry *pstBaseLineWorkEntry, const Json::Value& jsContect);
HRA_BASELINE_EXPORT int BaseLineCfgApply(const BaseLineWorkEntry& stBaseLineWorkEntry, const Json::Value& jsContect);
HRA_BASELINE_EXPORT int BaseLineCfgHandle(const Json::Value& jsContect);
HRA_BASELINE_EXPORT int BaseLinePatternUpdate(const std::string& strPatternFile, const std::string& strTempDir);
HRA_BASELINE_EXPORT int BaseLineCopyPattPack(std::string& strTempDir, const std::string& strPatternFile);

HRA_BASELINE_EXPORT int BaseLineCancelInit(void);
HRA_BASELINE_EXPORT int BaseLineCancelDestroy(void);
HRA_BASELINE_EXPORT int BaseLineCancelHandle(const Json::Value& jsContect);

#endif /* _BASELINE_H_ */
