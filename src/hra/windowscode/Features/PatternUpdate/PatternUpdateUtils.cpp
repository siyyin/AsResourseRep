#include "PatternUpdateUtils.h"
#include "utility/HraUtils.h"
#include "utility/Logger.h"
#include "utility/HraJson.h"
#include "utility/HraPatternUpdateUtils.h"
#include "zlib/unzip.h"
#include "json/json.h"
#include <shlwapi.h>
#include <algorithm>

//各模块pattern信息定义
const PatternTypeInfo c_pattern_type_info[] = {
    {OSSCAN_PATTERN_UPDATE, "vuln-os", "win-vuln-os", OSSACN_PATTERN_DIR},
    {VULN_POC_PATTERN_UPDATE, "vuln-os", "win-vuln-os", VULNPOC_PATTERN_DIR},
    {BASELINE_PATTERN_UPDATE, "baseline", "windows-baseline", BASELINE_PATTERN_DIR},
    {ASSET_PATTERN_UPDATE, "asset", "windows-asset", ASSET_PATTERN_DIR},
    {DOLPHIN_PATTERN_UPDATE, "", "weakpwd", DOLPHIN_PATTERN_DIR},
    {APPSCAN_PATTERN_UPDATE, "", "", ""}};

/// <summary>
/// 查找PatternTypeInfo
/// </summary>
/// <param name="sTypeInfo"></param>
/// <param name="emType"></param>
/// <returns></returns>
bool FindPatternTypeInfo(PatternTypeInfo& sTypeInfo, PatternUpdateType emType)
{
    for (int i = 0; i < (sizeof(c_pattern_type_info) / sizeof(PatternTypeInfo)); ++i)
    {
        if (emType != c_pattern_type_info[i].emPatternType)
        {
            continue;
        }
        memset(&sTypeInfo, 0, sizeof(sTypeInfo));
        sTypeInfo = c_pattern_type_info[i];
        return true;
    }
    return false;
}

/// <summary>
/// 从pattern保重提取meta_info.json文件字符串
/// </summary>
/// <param name="strZipPath"></param>
/// <returns></returns>
std::string GetMetaInfoFromZip(const std::string& strZipPath)
{
    std::string strReturn;
    int nRet          = 0;
    unzFile pvZipFile = NULL;
    std::string strFileCont;
    unz_file_info zFileInfo;
    memset(&zFileInfo, 0, sizeof(zFileInfo));
    char szSubFileName[MAX_PATH];
    memset(szSubFileName, 0, sizeof(szSubFileName));
    char* pscFileData = NULL;

    // 文件是否存在
    if (!PathFileExistsA(strZipPath.c_str()))
    {
        LOG_ERROR("File not exists! %s", strZipPath.c_str());
        goto _exit;
    }

    // 打开zip文件
    pvZipFile = unzOpen(strZipPath.c_str());
    if (NULL == pvZipFile)
    {
        LOG_ERROR("Open file error! %s", strZipPath.c_str());
        goto _exit;
    }

    // 获取压缩文件的全局信息
    unz_global_info zGlobalInfo;
    nRet = unzGetGlobalInfo(pvZipFile, &zGlobalInfo);
    if (nRet != UNZ_OK)
    {
        LOG_ERROR("unzGetGlobalInfo file error! code:%d, %s", nRet, strZipPath.c_str());
        goto _exit;
    }

    // 寻找文件
    for (size_t i = 0; i < zGlobalInfo.number_entry; ++i)
    {
        // 从压缩包循环获得子文件信息：文件名， 文件大小
        nRet = unzGetCurrentFileInfo(pvZipFile, &zFileInfo, szSubFileName, sizeof(szSubFileName), NULL, 0, NULL, 0);
        if (UNZ_OK != nRet)
        {
            LOG_ERROR("unzGetCurrentFileInfo file error! code:%d, %s", nRet, strZipPath.c_str());
            goto _exit;
        }

        std::string strSubFileName = szSubFileName;
        std::replace(strSubFileName.begin(), strSubFileName.end(), '/', '\\');
        if (strSubFileName != PATTERN_INFORMATION)
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }

        nRet = unzOpenCurrentFile(pvZipFile);
        if (UNZ_OK != nRet)
        {
            LOG_ERROR("unzOpenCurrentFile file error! code:%d, %s", nRet, strZipPath.c_str());
            goto _exit;
        }

        if (pscFileData)
        {
            free(pscFileData);
            pscFileData = NULL;
        }
        size_t lFileLength = zFileInfo.uncompressed_size; // 子文件长度
        pscFileData        = (char*)malloc(lFileLength + 1);
        memset(pscFileData, 0, lFileLength + 1);
        // 解压子文件
        int lUnzSubfileLen          = unzReadCurrentFile(pvZipFile, (voidp)pscFileData, (unsigned int)lFileLength);
        pscFileData[lUnzSubfileLen] = '\0';
        unzCloseCurrentFile(pvZipFile);

        strReturn = pscFileData;
        LOG_INFO("GetMetaInfoFromZip from zip succeed! %s", strZipPath.c_str());
        goto _exit;
    }

_exit:
    if (pvZipFile)
    {
        unzClose(pvZipFile);
        pvZipFile = NULL;
    }

    if (pscFileData)
    {
        free(pscFileData);
        pscFileData = NULL;
    }

    return strReturn;
}

/// <summary>
/// 检查拷贝的包，如果是大包则获得小包
/// </summary>
/// <param name="sSmallPatternInfo"></param>
/// <param name="sPatternTemp"></param>
/// <returns></returns>
int CheckPatternPackageGetSingle(PatternUpdateInfo& sSinglePatternInfo, const PatternUpdateInfo& sPatternTemp,
                                  PatternUpdateType emPatternType)
{
    int nRet = HRA_FAILED;
    bool bNeedDeleteTmp = true;
    bool bFindSignle    = false;
    std::string strMetaInfo;
    std::string strPatternType;
    std::string strMoudleType;
    Json::Value jsMetaInfo;
    PatternTypeInfo sTypeInfo;
    std::vector<std::string> vctZipFiles;
    std::string strNewZipFile;
    char szNewTmpDir[MAX_PATH] = {0};
    std::string strZipFileName = sPatternTemp.szTempZipPath;//szTempZipPath有可能传的是产品侧的路径
    size_t nIndex              = strZipFileName.rfind("\\");
    if (nIndex != std::string::npos)
    {
        strZipFileName = strZipFileName.substr(nIndex + 1);
    }
    else
    {
        strZipFileName = strZipFileName;
    }
    char szZipFilePath[MAX_PATH] = {0};
    _snprintf_s(szZipFilePath, sizeof(szZipFilePath), "%s%s", sPatternTemp.szTempDir, strZipFileName.c_str());

    if (!FindPatternTypeInfo(sTypeInfo, emPatternType))
    {
        LOG_ERROR("FindPatternTypeInfo error! %d", (int)emPatternType);
        goto _exit;
    }

    //判断是大包小包
    strMetaInfo = GetMetaInfoFromZip(szZipFilePath);
    if (strMetaInfo.empty())
    {
        LOG_ERROR("strPatternType empty!");
        goto _exit;
    }

    jsMetaInfo = StringToJson(strMetaInfo.c_str(), strMetaInfo.length());
    if (jsMetaInfo.isMember("pattern_type") && jsMetaInfo["pattern_type"].isString())
    {
        strPatternType = jsMetaInfo["pattern_type"].asString();
    }
    if (jsMetaInfo.isMember("module_type") && jsMetaInfo["module_type"].isString())
    {
        strMoudleType = jsMetaInfo["module_type"].asString();
    }

    //单包
    if (_stricmp(strPatternType.c_str(), sTypeInfo.szPatternType) == 0)
    {
        LOG_INFO("Single pattern type! %s", strPatternType.c_str());
        bNeedDeleteTmp = false;
        memcpy(&sSinglePatternInfo, &sPatternTemp, sizeof(PatternUpdateInfo));
        nRet = HRA_OK;
        goto _exit;
    }
    //大包
    else if (_stricmp(strMoudleType.c_str(), sTypeInfo.szMoudleType) == 0)
    {
        LOG_INFO("All pattern type! %s", strMoudleType.c_str());
        bNeedDeleteTmp = true;
        if (UtilsUnzip(szZipFilePath) != HRA_OK)
        {
            LOG_ERROR("UtilsUnzip error! %s", szZipFilePath);
            goto _exit;
        }

        vctZipFiles.clear();
        UtilsGetAllMatchFileInDir(sPatternTemp.szTempDir, ".zip", vctZipFiles);
        for (std::vector<std::string>::const_iterator it = vctZipFiles.begin(); vctZipFiles.end() != it; ++it)
        {
            LOG_DEBUG(" Check zip pattern type! %s", it->c_str());

            // 判断是大包小包
            strMetaInfo = GetMetaInfoFromZip(*it);
            if (strMetaInfo.empty())
            {
                LOG_ERROR("strPatternType empty!");
                goto _exit;
            }

            jsMetaInfo = StringToJson(strMetaInfo.c_str(), strMetaInfo.length());
            if (jsMetaInfo.isMember("pattern_type") && jsMetaInfo["pattern_type"].isString())
            {
                strPatternType = jsMetaInfo["pattern_type"].asString();
            }
            LOG_DEBUG("PatternType:%s", strPatternType.c_str());

            //只获取小包
            if (_stricmp(strPatternType.c_str(), sTypeInfo.szPatternType) != 0)
            {
                LOG_DEBUG("PatternType not match! %s");
                continue;
            }

            _snprintf_s(szNewTmpDir, sizeof(szNewTmpDir), "%s..\\%s-%s\\", sPatternTemp.szTempDir, PACKAGE_TEMP_DIR,
                        UtilsGetNanoTimestamp().c_str());
            memset(sSinglePatternInfo.szTempDir, 0, sizeof(sSinglePatternInfo.szTempDir));
            if (GetFullPathNameA(szNewTmpDir, sizeof(sSinglePatternInfo.szTempDir) - 1, sSinglePatternInfo.szTempDir,
                                 NULL) == 0)
            {
                LOG_ERROR("GetFullPathNameA error! code:%lu, path:%s", GetLastError(), szNewTmpDir);
                goto _exit;
            }
            strNewZipFile = UtilsCopyFileToDir(*it, sSinglePatternInfo.szTempDir);
            if (strNewZipFile.empty())
            {
                LOG_ERROR("UtilsCopyFileToDir error!");
                goto _exit;
            }
            _snprintf_s(sSinglePatternInfo.szTempZipPath, sizeof(sSinglePatternInfo.szTempZipPath), "%s",
                        strNewZipFile.c_str());
            nRet = HRA_OK;
            LOG_INFO("Get signle pattern succeed!");
            goto _exit;
        }
    }
    //类型错误
    else
    {
        bNeedDeleteTmp = true;
        LOG_ERROR("pattern type not match! %d:%s", (int)emPatternType, strPatternType.c_str());
        goto _exit;
    }

_exit:
    if (bNeedDeleteTmp && IsDirExist(UtilsStringToUnicode(sPatternTemp.szTempDir).c_str()))
    {
        if (!UtilsRemoveDirectory(UtilsStringToUnicode(sPatternTemp.szTempDir).c_str()))
        {
            LOG_ERROR("UtilsRemoveDirectory[%s] error!", sPatternTemp.szTempDir);
        }
        LOG_INFO("UtilsRemoveDirectory[%s] succeed!", sPatternTemp.szTempDir);
    }
    return nRet;
}
