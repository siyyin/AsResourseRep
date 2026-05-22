#pragma once
#include <string>
#include <Windows.h>

#define HRA_PATTERN_PATH 256
#define HRA_PATTERN_TYPE_NAME_SIZE 256

enum PatternUpdateType
{
    OSSCAN_PATTERN_UPDATE   = 1,
    APPSCAN_PATTERN_UPDATE  = 2,
    BASELINE_PATTERN_UPDATE = 3,
    DOLPHIN_PATTERN_UPDATE  = 4,
    VULN_POC_PATTERN_UPDATE = 5,
    ASSET_PATTERN_UPDATE    = 6
};

struct PatternUpdateInfo
{
    char szTempZipPath[MAX_PATH];
    char szTempDir[MAX_PATH];
};

struct PatternTypeInfo
{
    PatternUpdateType emPatternType;                // pattern枚举
    char szMoudleType[HRA_PATTERN_TYPE_NAME_SIZE];  // 总包类型
    char szPatternType[HRA_PATTERN_TYPE_NAME_SIZE]; // 单包类型
    char szPatternPath[HRA_PATTERN_PATH];           // pattern路径
};

//查找PatternTypeInfo
bool FindPatternTypeInfo(PatternTypeInfo& sTypeInfo, PatternUpdateType emType);

// 从pattern保重提取meta_info.json文件字符串
std::string GetMetaInfoFromZip(const std::string& strZipPath);

//检查拷贝的包，如果是大包则获得小包
int CheckPatternPackageGetSingle(PatternUpdateInfo& sSmallPatternInfo, const PatternUpdateInfo& sPatternTemp,
                                 PatternUpdateType emPatternType);
