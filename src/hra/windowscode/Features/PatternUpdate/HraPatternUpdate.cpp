#include "HraPatternUpdate.h"
#include "PatternUpdateUtils.h"
#include "HraIpcInterface/HraIpcCommDef.h"
#include "utility/Logger.h"
#include "json/json.h"
#include "utility/comm.h"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
#include "../AppScan/AppScan.h"
#include "../BaseLine/BaseLine.h"
#include "../OsScan/OsScan.h"
#include "../Dolphin/Dolphin.h"
#include "../VulnPoc/VulnPoc.h"
#include "../AssetScan/AssetScan.h"
#include "utility/HraReport.h"
#include "utility/HraTaskType.h"
//#include "utility/HraCmdPkg.h"
#include "HRATaskScheduler/HRATaskScheduler.h"

static void *patternUpdateOsscan(void *pArg);
static void* patternUpdateBaseLine(void *pArg);
static void* patternUpdateDolphin(void* pArg);
static void* VulnPocPatternUpdateWorker(void* pArg);
static void* patternUpdateAsset(void* pArg);
static int patternUpdateSelectType(const Json::Value& jsArrayCmdObj);

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	调用OsScan的内部实现接口. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pArg">	[in,out] If non-null, the argument. </param>
///
/// <returns>	Null if it fails, else a pointer to a void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
static void *patternUpdateOsscan(void *pArg)
{
	struct PatternUpdateInfo *pstOneWorkerArg = NULL;
	//std::string strPatternFile;
	CReportInfo cReportOsInfo;
	int lRet = HRA_OK;

	LOG_INFO("Osscan pattern update start.");
	if (NULL == pArg)
	{
		LOG_ERROR("Parameter is null.");
		return NULL;
	}

	pstOneWorkerArg = (struct PatternUpdateInfo*)pArg;
    //strPatternFile  = pstOneWorkerArg->szTempZipPath;
	//strPatternFile.assign(pstOneWorkerArg->pscJsonCmdData, pstOneWorkerArg->lDataLen);

	//free(pstOneWorkerArg->pscJsonCmdData);
	//pstOneWorkerArg->pscJsonCmdData = NULL;

	lRet = OsScanPatternUpdate(pstOneWorkerArg->szTempZipPath, pstOneWorkerArg->szTempDir);

	//结果上报
	std::string strPattVersion = UtilsGetOSscanPatternVersion();
	std::string strRePort = GetReportPatternUpdateResult(lRet, HRA_PATTERN_UPDATE_CMD, "vuln_os_pattern", strPattVersion);

	cReportOsInfo.SetCompress(NO_COMPRESSION);
	cReportOsInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, CONFIG_RESULT, strRePort.c_str(), strRePort.size());

	return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	调用BaseLine的内部实现接口. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pArg">	[in,out] If non-null, the argument. </param>
///
/// <returns>	Null if it fails, else a pointer to a void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
static void* patternUpdateBaseLine(void *pArg)
{
	struct PatternUpdateInfo *pstOneWorkerArg = NULL;
	//std::string strPatternFile;
	CReportInfo cReportBaselineInfo;
	int lRet = HRA_OK;

    LOG_INFO("BaseLine pattern update start.");
	if (NULL == pArg)
	{
		LOG_ERROR("Parameter is null.");
		return NULL;
	}

	pstOneWorkerArg = (struct PatternUpdateInfo*)pArg;
    //strPatternFile  = pstOneWorkerArg->szTempZipPath;
	//strPatternFile.assign(pstOneWorkerArg->pscJsonCmdData, pstOneWorkerArg->lDataLen);
	//free(pstOneWorkerArg->pscJsonCmdData);
	//pstOneWorkerArg->pscJsonCmdData = NULL;

	lRet = BaseLinePatternUpdate(pstOneWorkerArg->szTempZipPath, pstOneWorkerArg->szTempDir);

	/* 结果上报 */
	std::string strPattVersion = UtilsGetBaselinePatternVersion();
	std::string strRePort = GetReportPatternUpdateResult(lRet, HRA_PATTERN_UPDATE_CMD, "baseline_pattern", strPattVersion);

	cReportBaselineInfo.SetCompress(NO_COMPRESSION);
	cReportBaselineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, CONFIG_RESULT, strRePort.c_str(), strRePort.size());
	return NULL;
}

/// <summary>
/// 弱口令pattern更新线程函数入口
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
static void* patternUpdateDolphin(void* pArg)
{
    struct PatternUpdateInfo* pstOneWorkerArg = NULL;
    //std::string strPatternFile;
    CReportInfo cReportBaselineInfo;
    int lRet = HRA_OK;

    LOG_INFO("Dolphin pattern update start.");
    if (NULL == pArg)
    {
        LOG_ERROR("Parameter is null.");
        return NULL;
    }

    pstOneWorkerArg = (struct PatternUpdateInfo*)pArg;
    //strPatternFile  = pstOneWorkerArg->szTempZipPath;
    //strPatternFile.assign(pstOneWorkerArg->pscJsonCmdData, pstOneWorkerArg->lDataLen);
    //free(pstOneWorkerArg->pscJsonCmdData);
    //pstOneWorkerArg->pscJsonCmdData = NULL;

    lRet = DolphinPatternUpdate(pstOneWorkerArg->szTempZipPath, pstOneWorkerArg->szTempDir);

    /* 结果上报 */
    std::string strPattVersion = UtilsGetDolphinPatternVersion();
    std::string strRePort = GetReportPatternUpdateResult(lRet, HRA_PATTERN_UPDATE_CMD, "wpscan_pattern", strPattVersion);

    cReportBaselineInfo.SetCompress(NO_COMPRESSION);
    cReportBaselineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, CONFIG_RESULT, strRePort.c_str(),
                                strRePort.size());

    return NULL;
}

/// <summary>
/// pattern更新线程函数入口
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
void* VulnPocPatternUpdateWorker(void* pArg)
{
    struct PatternUpdateInfo* pstOneWorkerArg = NULL;
    // std::string strPatternFile;
    CReportInfo cReportBaselineInfo;
    int lRet = HRA_OK;

    LOG_INFO("VulnPoc pattern update start.");
    if (NULL == pArg)
    {
        LOG_ERROR("Parameter is null.");
        return NULL;
    }

    pstOneWorkerArg = (struct PatternUpdateInfo*)pArg;
    // strPatternFile  = pstOneWorkerArg->szTempZipPath;
    // strPatternFile.assign(pstOneWorkerArg->pscJsonCmdData, pstOneWorkerArg->lDataLen);
    // free(pstOneWorkerArg->pscJsonCmdData);
    // pstOneWorkerArg->pscJsonCmdData = NULL;

    lRet = VulnPocPatternUpdate(pstOneWorkerArg->szTempZipPath, pstOneWorkerArg->szTempDir);

    /* 结果上报 */
    std::string strPattVersion = UtilsGetVulnPocPatternVersion();
    std::string strRePort =
        GetReportPatternUpdateResult(lRet, HRA_PATTERN_UPDATE_CMD, "vulnpoc_pattern", strPattVersion);

    cReportBaselineInfo.SetCompress(NO_COMPRESSION);
    cReportBaselineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, CONFIG_RESULT, strRePort.c_str(),
                                strRePort.size());
    return NULL;
}

/// <summary>
/// 资产模块pattern更新线程入口
/// </summary>
/// <param name="pArg"></param>
/// <returns></returns>
static void* patternUpdateAsset(void* pArg)
{
    int lRet                                  = HRA_FAILED;
    struct PatternUpdateInfo* pstOneWorkerArg = NULL;
    PatternUpdateInfo sSignlePatternInfo;
    memset(&sSignlePatternInfo, 0, sizeof(sSignlePatternInfo));

    LOG_INFO("Asset pattern update start.");
    if (NULL == pArg)
    {
        LOG_ERROR("Parameter is null.");
        goto _exit;
    }
    pstOneWorkerArg = (struct PatternUpdateInfo*)pArg;

    lRet = CheckPatternPackageGetSingle(sSignlePatternInfo, *pstOneWorkerArg, ASSET_PATTERN_UPDATE);
    if (lRet != HRA_OK)
    {
        LOG_ERROR("CheckPatternPackageGetSingle error!");
        goto _exit;
    }

    lRet = AssetPatternUpdate(sSignlePatternInfo.szTempZipPath, sSignlePatternInfo.szTempDir);

_exit:
    /* 结果上报 */
    std::string strPattVersion = UtilsGetAssetPatternVersion();
    std::string strRePort =
        GetReportPatternUpdateResult(lRet, HRA_PATTERN_UPDATE_CMD, "asset_pattern", strPattVersion);
    CReportInfo cReportBaselineInfo;
    cReportBaselineInfo.SetCompress(NO_COMPRESSION);
    cReportBaselineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, CONFIG_RESULT, strRePort.c_str(),
                                strRePort.size());
    return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	解析数据包中的pattern_type回调对应的pattern更新函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="jsArrayCmdObj">	The js array command object. </param>
///
/// <returns>	An int. </returns>
///    
///    {
///     "pattern_update_item":[{
///	            "pattern_type":1/2/3,  // 1:osScan 2.appScan 3.baseline
///		            "pattern_files":["/var/pattern1","/var/pattern1_information.json"],
///		            "pattern_version":"3.2.1"
///		       },{
///			            "pattern_type":1/2/3,  // 1:osScan 2.appScan 3.baseline
///				            "pattern_files":["/var/pattern1","/var/pattern1_information.json"],
///				            "pattern_version":"3.2.1"
///				         }
///	       ]
///    }
////////////////////////////////////////////////////////////////////////////////////////////////////
static int patternUpdateSelectType(const Json::Value& jsArrayCmdObj)
{
    int lRet          = HRA_OK;
    uint64_t nTaskSeq = 0;
    std::string strFile;
    std::string strTempDir;
    std::string strZipTemp;
    Json::Value jsFilePathArrary;

    if (jsArrayCmdObj == "" || !jsArrayCmdObj["pattern_type"].isInt() || !jsArrayCmdObj["pattern_files"].isString())
    {
        LOG_ERROR("Pattern update: Command error");
        return HRA_BAD_PARAM;
    }
    strFile = jsArrayCmdObj["pattern_files"].asString();
    if ((strFile.size() <= 4) || (strFile.substr(strFile.size() - 4) != ".zip"))
    {
        LOG_ERROR("Pattern update: pattern_files is error:%s.", strFile.c_str());
        return HRA_BAD_PARAM;
    }

    if ((jsArrayCmdObj["pattern_type"].asInt() == OSSCAN_PATTERN_UPDATE ||
         jsArrayCmdObj["pattern_type"].asInt() == VULN_POC_PATTERN_UPDATE))
    {   // 首先解压查看meta_info.json
        std::string strPatternPath = UtilsGetMetaInfoDir(PATTERN_DIR);
        if (strPatternPath.empty())
        {
            LOG_ERROR("Pattern update: Failed to get pattern path.");
            return HRA_FAILED;
        }

        //strZipTemp = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetTimestamp() + "\\";
        strZipTemp = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetNanoTimestamp() + "-" +
                     std::to_string(jsArrayCmdObj["pattern_type"].asInt()) + "\\";
        strFile    = UtilsCopyFileToDir(strFile, strZipTemp);
        if (strFile == "")
        {
            LOG_ERROR("Pattern update: The path of the currently obtained zip package file is incorrect.");
            lRet = HRA_FAILED;
            goto _exit;
        }
        if (HRA_OK != UtilsUnzip(strFile))
        {
            LOG_ERROR("Pattern update: Failed to extract zip file[%s].", strFile.c_str());
            lRet = HRA_FAILED;
            goto _exit;
        }

        std::string strMetaInfo = UtilsPathAppend(strZipTemp, PATTERN_INFORMATION);
        Json::Value jsRoot      = FileToJson(strMetaInfo.c_str());
        if (jsRoot.isMember("module_type") && jsRoot["module_type"].isString() &&
            _stricmp(jsRoot["module_type"].asString().c_str(), "vuln") == 0)
        {
            //strFile = UtilsGetFileFromDir(strZipTemp, "win_vuln_os_p-b"); // 不保险,Zip包的名称可能会被产品篡改
            std::vector<std::string> vecFiles;
            UtilsGetAllMatchFileInDir(strZipTemp, ".zip", vecFiles);
            std::string strTmp = UtilsGetVulnZipPathFromZips(vecFiles, strFile);
            if (_stricmp(strTmp.c_str(), "") == 0)
            {
                LOG_ERROR("Pattern update: Find win_vuln_os from the Zip list failed.");
                lRet = HRA_FAILED;
                goto _exit;
            }
            strFile = strTmp;
        }
        else if (jsRoot.isMember("pattern_type") && jsRoot["pattern_type"].isString() &&
                 _stricmp(jsRoot["pattern_type"].asString().c_str(), "win-vuln-os") == 0)
        {
            strFile = jsArrayCmdObj["pattern_files"].asString();
        }
        else
        {
            LOG_ERROR("Pattern update: The information in meta_info.json is incorrect, and the zip package[%s] is not "
                      "delivered correctly.", jsArrayCmdObj["pattern_files"].asString().c_str());
            lRet = HRA_FAILED;
            goto _exit;
        }
    }

    /* 根据模块开始pattern更新 */
    switch (jsArrayCmdObj["pattern_type"].asInt())
    {
    case OSSCAN_PATTERN_UPDATE: {
        LOG_INFO("===The OSSCAN module Pattern is ready to be updated.===");
        lRet = OsScanCopyPattPack(strTempDir, strFile); // 先将pattern拷贝到HRA目录

        PatternUpdateInfo stPattInfo;
        memset(&stPattInfo, 0, sizeof(stPattInfo));
        _snprintf_s(stPattInfo.szTempDir, sizeof(stPattInfo.szTempDir), "%s", strTempDir.c_str());
        _snprintf_s(stPattInfo.szTempZipPath, sizeof(stPattInfo.szTempZipPath), "%s", strFile.c_str());
        if (lRet == HRA_OK)
        {
            LOG_INFO("The OsScan pattern update was added to the thread pool.");

            //添加到工作队列
            nTaskSeq = HraTask_AddWorker("", HRA_ELMT_OS_SCAN_CFG, ProMsgHead::MsgType::PATTERN_UPDATE,
                                         patternUpdateOsscan, (void*)&stPattInfo, sizeof(stPattInfo));
            if (nTaskSeq <= 0)
            {
                lRet = HRA_FAILED;
                LOG_ERROR("Hra Task pool add worker failed.");
            }
        }
    }
    //break; //vulnpoc pattern合并入osscan，所以下发osscan pattern会触发vulnpoc pattern更新，去掉此break；
    case VULN_POC_PATTERN_UPDATE: {
        LOG_INFO("===The VulnPoc module Pattern is ready to be updated.===");
        lRet = VulnPocCopyPattPack(strTempDir, strFile);

        PatternUpdateInfo stPattInfo;
        memset(&stPattInfo, 0, sizeof(stPattInfo));
        _snprintf_s(stPattInfo.szTempDir, sizeof(stPattInfo.szTempDir), "%s", strTempDir.c_str());
        _snprintf_s(stPattInfo.szTempZipPath, sizeof(stPattInfo.szTempZipPath), "%s", strFile.c_str());

        if (lRet == HRA_OK)
        {
            LOG_INFO("The VulnPoc pattern update was added to the thread pool.");
            //添加到工作队列
            nTaskSeq = HraTask_AddWorker("", HRA_ELMT_VULN_POC_CFG, ProMsgHead::MsgType::PATTERN_UPDATE,
                                         VulnPocPatternUpdateWorker, (void*)&stPattInfo, sizeof(stPattInfo));
            if (nTaskSeq <= 0)
            {
                lRet = HRA_FAILED;
                LOG_ERROR("Hra Task pool add worker failed.");
            }
        }
    }
    break;
    case APPSCAN_PATTERN_UPDATE:
        LOG_INFO("===windows has no APPSCAN module pattern.===");
        break;
    case BASELINE_PATTERN_UPDATE: {
        LOG_INFO("===The BASELINE module Pattern is ready to be updated.===");
        lRet = BaseLineCopyPattPack(strTempDir, strFile); // 先将pattern拷贝到HRA目录

        PatternUpdateInfo stPattInfo;
        memset(&stPattInfo, 0, sizeof(stPattInfo));
        _snprintf_s(stPattInfo.szTempDir, sizeof(stPattInfo.szTempDir), "%s", strTempDir.c_str());
        _snprintf_s(stPattInfo.szTempZipPath, sizeof(stPattInfo.szTempZipPath), "%s", strFile.c_str());
        
        if (lRet == HRA_OK)
        {
            LOG_INFO("The BaseLine pattern update was added to the thread pool.");
            //添加到工作队列
            nTaskSeq = HraTask_AddWorker("", HRA_ELMT_BASE_LINE_CFG, ProMsgHead::MsgType::PATTERN_UPDATE,
                                         patternUpdateBaseLine, (void*)&stPattInfo, sizeof(stPattInfo));
            if (nTaskSeq <= 0)
            {
                lRet = HRA_FAILED;
                LOG_ERROR("Hra Task pool add worker failed.");
            }
        }
    }
    break;
    case DOLPHIN_PATTERN_UPDATE: 
    {
        LOG_INFO("===The Dolphin module Pattern is ready to be updated.===");
        lRet = DolphinCopyPattPack(strTempDir, strFile);

        PatternUpdateInfo stPattInfo;
        memset(&stPattInfo, 0, sizeof(stPattInfo));
        _snprintf_s(stPattInfo.szTempDir, sizeof(stPattInfo.szTempDir), "%s", strTempDir.c_str());
        _snprintf_s(stPattInfo.szTempZipPath, sizeof(stPattInfo.szTempZipPath), "%s", strFile.c_str());
        
        if (lRet == HRA_OK)
        {
            LOG_INFO("The Dolphin pattern update was added to the thread pool.");
            //添加到工作队列
            nTaskSeq = HraTask_AddWorker("", HRA_ELMT_WP_SACN_CFG, ProMsgHead::MsgType::PATTERN_UPDATE,
                                         patternUpdateDolphin, (void*)&stPattInfo, sizeof(stPattInfo));
            if (nTaskSeq <= 0)
            {
                lRet = HRA_FAILED;
                LOG_ERROR("Hra Task pool add worker failed.");
            }
        }
    }
    break;
    case ASSET_PATTERN_UPDATE:
    {
        LOG_INFO("===The Asset module Pattern is ready to be updated.===");
        lRet = AssetCopyPattPack(strTempDir, strFile);

        PatternUpdateInfo stPattInfo;
        memset(&stPattInfo, 0, sizeof(stPattInfo));
        _snprintf_s(stPattInfo.szTempDir, sizeof(stPattInfo.szTempDir), "%s", strTempDir.c_str());
        _snprintf_s(stPattInfo.szTempZipPath, sizeof(stPattInfo.szTempZipPath), "%s%s", strTempDir.c_str(),
                    strFile.c_str());
        
        if (lRet == HRA_OK)
        {
            LOG_INFO("The Asset pattern update was added to the thread pool.");
            // 添加到工作队列
            nTaskSeq = HraTask_AddWorker("", HRA_ELMT_ASSETS_SCAN_CFG, ProMsgHead::MsgType::PATTERN_UPDATE,
                                         patternUpdateAsset, (void*)&stPattInfo, sizeof(stPattInfo));
            if (nTaskSeq <= 0)
            {
                lRet = HRA_FAILED;
                LOG_ERROR("Hra Task pool add worker failed.");
            }
        }
    }
    break;
    default:
        LOG_INFO("===Unknown pattern_type:%d .===", jsArrayCmdObj["pattern_type"].asInt());
        break;
    }

_exit:
    if (IsDirExist(UtilsStringToUnicode(strZipTemp).c_str()))
    {
        if (!UtilsRemoveDirectory(UtilsStringToUnicode(strZipTemp).c_str()))
        {
            LOG_ERROR("Pattern update: UtilsRemoveDirectory[%s] error!", strZipTemp.c_str());
        }
        LOG_INFO("Pattern update: UtilsRemoveDirectory[%s] succeed!", strZipTemp.c_str());
    }

    return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	处理json 数据. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pscJsonData">  	[in,out] If non-null, information describing the psc JSON. </param>
/// <param name="ulJsonDataLen">	Length of the ul JSON data. </param>
///
/// <returns>	A std::string. </returns>
///      {
///     "pattern_update_item":[{
///	            "pattern_type":1/2/3,  // 1:osScan 2.appScan 3.baseline
///		            "pattern_files":"/var/pattern1"
///		       },{
///			            "pattern_type":1/2/3,  // 1:osScan 2.appScan 3.baseline
///				            "pattern_files":"/var/pattern1"
///				         }
///	       ]
///    }
////////////////////////////////////////////////////////////////////////////////////////////////////
std::string PatternUpdateHandleJsonData(char *pscJsonData, unsigned int ulJsonDataLen)
{
	Json::Reader reader;
	Json::Value jsRoot;
	Json::Value jsItemObj;
	Json::Value jsBodyObj;
	Json::Value jsResultArrayObj;


	if (pscJsonData == NULL || 0 == ulJsonDataLen)
	{
		LOG_ERROR("Json data is null.\n");
		return "";
	}

    LOG_INFO(">>>>>>>>>>>>>request:\n%s", pscJsonData);
	jsRoot = StringToJson(pscJsonData, ulJsonDataLen);
	if ((jsRoot.isMember("pattern_update_item")) && (jsRoot["pattern_update_item"].isArray()))
	{
		const Json::Value jsArrayObj = jsRoot["pattern_update_item"];
		for (int i = 0; i < jsArrayObj.size(); i++)
		{
			if (jsArrayObj[i].isMember("pattern_type"))
			{
				int lHandleCommandRet = HRA_FAILED;

				lHandleCommandRet = patternUpdateSelectType(jsArrayObj[i]);

				// 记录处理数据
				jsItemObj["pattern_type"] = jsArrayObj[i]["pattern_type"];
				jsItemObj["error_code"] = lHandleCommandRet;
				jsItemObj["error_info"] = (lHandleCommandRet==HRA_OK) ? "succeeded" : "command parse failed";
				jsResultArrayObj.append(jsItemObj);
			}
			else
			{
				// 本地记录异常
				LOG_ERROR("There is not command_type Json data.");
			}
		}

		/* json header */
		jsBodyObj.clear();
		jsBodyObj["device_id"] = UtilsGetUUID();
		jsBodyObj["time_stamp"] = UtilsGetRunTime();
		jsBodyObj["results"] = jsResultArrayObj;
	}
	else
	{
		// 记录异常
		LOG_ERROR("There is not data param array object in Json data.");
	}
    LOG_INFO("feadback>>>>>>>>>>>>:\n%s", jsBodyObj.toStyledString().c_str());

	return JsonToString(jsBodyObj);
}

