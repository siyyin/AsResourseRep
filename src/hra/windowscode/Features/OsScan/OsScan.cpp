#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <list>

#include "OsScan.h"
#include "OsScanEngineApi.h"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
#include "utility/Logger.h"
#include "utility/HraCtrlCmd.h"
#include "utility/ConfigSave.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraTaskType.h"
#include "HraIpcInterface/HraIpcCommDef.h"

#pragma comment(lib, "libvaeng.lib")

CPatternUpdateUtils g_OsScanPatternUpdateUtils;

// struct OsScanEngineApi *g_pstOsScanEngineApi = NULL;
char g_scOsScanModuleWork = 1;

static char OsScanGetModuleWorkStatus(void)
{
	return g_scOsScanModuleWork;
}

static void OsScanSetModuleWorkStatus(char scOsScanModuleWork)
{
	g_scOsScanModuleWork = scOsScanModuleWork;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	从pattern目录解压最新的pattern压缩包. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
static int osScanPreparePattern()
{
	std::string strPatternDir = UtilsGetMetaInfoDir(OSSACN_PATTERN_DIR);

	//pattern压缩包已经解压，进程重启的情况
	struct stat stFileStat;
	std::string strPattInfoFile = strPatternDir + PATTERN_INFORMATION;
	std::string strPattDataDir = strPatternDir + PATTERN_DATA_DIR;
	if (stat(strPattInfoFile.c_str(), &stFileStat) == 0 && stat(strPattDataDir.c_str(), &stFileStat) == 0)
	{
        LOG_INFO("The pattern file already exists.");
		return HRA_OK;
	}

	std::string strPackageName = UtilsFindNewestPattPack(strPatternDir);
	if (strPackageName.size() == 0)
	{
		LOG_ERROR("Failed to find the latest pattern compression package.");
		return HRA_FAILED;
	}

	//解压
    LOG_INFO("Find the latest Pattern package and start unpacking.");
	int lRet = UtilsUnzip(strPatternDir + strPackageName);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("Unpack the failure.");
	}

    std::string strLocalTime = UtilsGetLocalTime();
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "OsscanPatternUpdateTime", strLocalTime);

	return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描结果上报. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="pscTaskId">		[in,out] If non-null, identifier for the psc task. </param>
/// <param name="lRet">				The ret. </param>
/// <param name="strScanResult">	The scan result. </param>
/// <param name="lScanType">		The scan type. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanReport(const char *pscTaskId, int lRet, const std::string& strScanResult/*, int lScanType*/)
{
	//if (!pscTaskId)
	//{
	//	return HRA_NULL_PTR;
	//}

	std::string strResultInfo = GetReportResultInfo(pscTaskId, lRet, strScanResult.c_str(), LOG_LEVEL_INFO);

	//结果上报
	CReportInfo cReportOsInfo;
	cReportOsInfo.SetCompress(NEED_COMPRESSION);
	cReportOsInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT,OS_SCAN_RESULT,strResultInfo.c_str(), strResultInfo.size());
	cReportOsInfo.ShowRspHdr();

	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Operating system scan engine destroy. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="pstOsScanEngineApi">	[in,out] If non-null, the pst operating system scan
/// 									engine API. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanEngineDestroy(struct OsScanEngineApi *pstOsScanEngineApi)
{
	if (pstOsScanEngineApi != NULL)
	{
		OsScanEngineUnInit(pstOsScanEngineApi);
		free(pstOsScanEngineApi);
	}
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描引擎初始化函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////
struct OsScanEngineApi *OsScanEnginePatternInit(const std::string& strPatternPath)
{
	int lEngineRet = 0;
	struct OsScanEngineApi *pstOsScanEngineApi = NULL;
	//std::string strPatternPath;

	pstOsScanEngineApi = (struct OsScanEngineApi *)malloc(sizeof(struct OsScanEngineApi));
	if (!pstOsScanEngineApi)
	{
		LOG_ERROR("Malloc buffer for Os scan engine manager failed.");
		goto _err;
	}

	memset(pstOsScanEngineApi, 0, sizeof(struct OsScanEngineApi));
	lEngineRet = OsScanEngineInit(pstOsScanEngineApi, strPatternPath);
	if (lEngineRet != HRA_OK)
	{
		LOG_ERROR("Os scan engine init failed.");
		goto _err;
	}

	//加载pattern
	//strPatternPath = UtilsGetOSscanPatternVersionPath();
	//if (strPatternPath.size() == 0)
	//{
	//	LOG_ERROR("[HRA] Os scan get pattern file failed.");
	//	goto _err;
	//}
	//lEngineRet = OsScanPatternLoad(strPatternPath.c_str(), pstOsScanEngineApi);
	//if (lEngineRet != HRA_OK)
	//{
	//	LOG_ERROR("Os scan engine load pattern failed.");
	//	goto _err;
	//}

	return pstOsScanEngineApi;

_err:
	if (pstOsScanEngineApi != NULL)
	{
		free(pstOsScanEngineApi);
		pstOsScanEngineApi = NULL;
	}

	LOG_ERROR("Os scan engine load failed.");
	return NULL;
}

// new pattern for kb cve method
int OsScanWithKbCvePattern(struct OsScanEngineApi* pstOsScanEngineApi, std::string& strScanResult)
{
	int lRet = HRA_OK;
	std::string strPatternPath = UtilsGetKbCveOsScanPatternVerisionPath();
	LOG_INFO("Kb to cve pattern path %s", strPatternPath.c_str());
	pstOsScanEngineApi = OsScanEnginePatternInit(strPatternPath);	
	if (pstOsScanEngineApi == NULL)
	{
		LOG_ERROR("The Kb to Cve OSScan failed to load engine or pattern.");
		lRet = HRA_Code::HRA_OPEN_FAIL;
	}
	else
	{
		lRet = OsScanEngineDoScan(pstOsScanEngineApi, strScanResult);
	}
	return lRet;
}

int OsScanWithOldPattern(struct OsScanEngineApi* pstOsScanEngineApi, std::string& strScanResult)
{
	int lRet = HRA_OK;
	std::string strPatternPath = UtilsGetOSscanPatternVersionPath();
	pstOsScanEngineApi = OsScanEnginePatternInit(strPatternPath);
	if (pstOsScanEngineApi == NULL)
	{
		LOG_ERROR("The OSScan failed to load engine or pattern.");
		lRet = HRA_Code::HRA_OPEN_FAIL;
	}
	else
	{
		lRet = OsScanEngineDoScan(pstOsScanEngineApi, strScanResult, true);
	}
	return lRet;
}

std::string handleMultiScanResult(std::list<std::string>& listScanResults)
{
	//先取第一个元素作为基础
	std::string strRes = listScanResults.front();
	listScanResults.pop_front();
	if (!listScanResults.empty())
	{
		Json::Value root = StringToJson(strRes.c_str(), strRes.size());
		Json::Value arrayResult = root["result"];
		if (arrayResult.isNull() || !arrayResult.isArray())
		{
			LOG_ERROR("handleMultiScanResult failed: invalid result!");
			LOG_DEBUG("strRes: %s", strRes.c_str());
			return strRes;
		}
		//拼接结果
		for (std::string strScanResult : listScanResults)
		{
			Json::Value tempRoot = StringToJson(strScanResult.c_str(), strScanResult.size());
			Json::Value tempArrayResult = tempRoot["result"];
			if (tempArrayResult.isNull() || !tempArrayResult.isArray())
			{
				LOG_ERROR("handleMultiScanResult failed: invalid result!");
				LOG_DEBUG("tempRoot: %s", strScanResult.c_str());
				return strRes;
			}
			for (const Json::Value data: tempArrayResult)
			{
				arrayResult.append(data);
			}
			Sleep(5000);
		}
		//重新组装Json
		root["result"] = arrayResult;
		strRes = JsonToString(root);
	}
	return strRes;
}

int OsScanWithMultiPattern(std::string& strScanResult)
{
	int lRet = HRA_OK;
	std::list<std::string> listScanResults;
	std::wstring strPatternPath = UtilsStringToUnicode(UtilsGetMultiOsScanPatternVersionPath());
	
	if (IsDirExist(strPatternPath.c_str()))
	{
		std::list<std::wstring> listSubFiles;
		UtilsGetSubFileInDir(strPatternPath, listSubFiles);
		if (listSubFiles.empty())
		{
			LOG_ERROR("The OsScan failed: empty pattern file!");
			lRet = HRA_Code::HRA_OPEN_FAIL;
		} 
		else
		{
			for (std::wstring wstrPatternFile : listSubFiles)
			{
				LOGW_INFO(L"excute pattern: %s", wstrPatternFile.c_str());
				std::string strTempResult;
				//初始化引擎
				struct OsScanEngineApi* pstOsScanEngineApi = OsScanEnginePatternInit(UtilsUnicodeToString(wstrPatternFile));
				if (pstOsScanEngineApi == NULL)
				{
					LOG_ERROR("The OSScan failed to load engine or pattern.");
					lRet = HRA_Code::HRA_OPEN_FAIL;
					//释放引擎资源
					OsScanEngineDestroy(pstOsScanEngineApi);
					break;
				}
				else
				{
					lRet = OsScanEngineDoScan(pstOsScanEngineApi, strTempResult, true);
					if (lRet != HRA_Code::HRA_OK)
					{
						LOG_ERROR("The OsScan excute failed!");
						//释放引擎资源
						OsScanEngineDestroy(pstOsScanEngineApi);
						break;
					}
					else
					{
						LOG_DEBUG("strTempResult: %s", strTempResult.c_str());
						listScanResults.push_back(strTempResult);
					}
					//释放引擎资源
					OsScanEngineDestroy(pstOsScanEngineApi);
				}
				Sleep(5000);
			}
		}
	}
	else
	{
		LOGW_ERROR(L"invalid pattern path: %s", strPatternPath.c_str());
		lRet = HRA_Code::HRA_OPEN_FAIL;
	}
	if (!listScanResults.empty())
	{
		strScanResult = handleMultiScanResult(listScanResults);
		LOG_INFO("strScanResult: %s", strScanResult.c_str());
	}
	return lRet;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描工作函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="pArg">	[in] 配置存储结构体. </param>
///
/// <returns>	Null if it fails, else a pointer to a void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void *OsScanWorker(void *pArg)
{
    int lRet                                   = HRA_OK;
    struct OsScanWorkEntry* pstOsScanWorkEntry = (struct OsScanWorkEntry*)pArg;
    
    std::string strScanResult;
    int iCtrlCmd = (int)HraCtrlCmd::CmdDef::cmd_init;

    LOG_INFO("OS Scan Worker(%d) start.", HRA_ELMT_OS_SCAN_CFG);
    do
    {
        if (!pArg)
        {
            LOG_ERROR("Scan work input paramater is null.");
            lRet = HRA_NULL_PTR;
            break;
        }

        if (OsScanGetModuleWorkStatus() == 0)
        {
            LOG_ERROR("Os scan is not init, can not work.");
            lRet = HRA_NOT_SUPPORTED;
            break;
        }

        //埋点
        iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
        if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
        {
            lRet = HRA_Code::HRA_USER_CANCEL;
        }
		else
		{
			g_OsScanPatternUpdateUtils.PatternLock(); //加锁

			struct OsScanEngineApi* pstOsScanEngineApi = NULL;
			
			//获取产品管道名，目前仅区分TrustOne及非TrustOne
			std::string strIpcName = UtilsGetHraIpcName();
			bool bIsTOEnviorment = true;
			if (strIpcName != TRUST_ONE_IPC_NAME)
			{
				LOG_INFO("Not trust one enviorment, scan with all cve method , ipc_name : %s", strIpcName.c_str());
				bIsTOEnviorment = false;
			}
			 
			//判断是否为TO产品，若不是TO则跨过补丁扫描直接采用老方案进行扫描
			if (bIsTOEnviorment)
			{
				lRet = OsScanWithKbCvePattern(pstOsScanEngineApi, strScanResult);
			}
			else
			{
				lRet = HRA_Code::HRA_NOT_SUPPORTED;
			}

			if (lRet != HRA_Code::HRA_OK)
			{
				LOG_WARN("Kb_cve method failed, starting to execute separated oval method");
				//补丁扫描失败，使用分割后得全量pattern进行扫描
				OsScanEngineDestroy(pstOsScanEngineApi);
				lRet = OsScanWithMultiPattern(strScanResult);
				if (lRet != HRA_Code::HRA_OK)
				{
					//分割后的全量pattern扫描不成功，使用旧版扫描
					LOG_WARN("Separated oval method failed, starting to execute original os scan method");
					struct OsScanEngineApi* pstOsScanEngineApi = NULL;
					lRet = OsScanWithOldPattern(pstOsScanEngineApi, strScanResult);
					if (lRet != HRA_Code::HRA_OK)
					{
						LOG_ERROR("The original os scan executing failed");
					}

					OsScanEngineDestroy(pstOsScanEngineApi);
				}
			}
			else
			{
				LOG_INFO("Scanning with the Kb Cve method success, return scan result");
				OsScanEngineDestroy(pstOsScanEngineApi);
			}
            g_OsScanPatternUpdateUtils.PatternUnLock(); //解锁
        }

        //埋点
        iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
        if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
        {
            lRet = HRA_Code::HRA_USER_CANCEL;
        }
    } while (false);

    OsScanReport(pstOsScanWorkEntry->ascTaskId, lRet, strScanResult /*, pstOsScanWorkEntry->lScanType*/);
    LOG_INFO("OS Scan Worker(%d) end.", HRA_ELMT_OS_SCAN_CFG);
    return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描配置解析函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="pstOsScanWorkEntry">	[out] 配置存储结构体 </param>
/// <param name="jsContect">		 	json数据. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanCfgParse(struct OsScanWorkEntry *pstOsScanWorkEntry, const Json::Value& jsContect)
{
	if (!pstOsScanWorkEntry)
	{
		LOG_ERROR("Work entry is null.");
		return HRA_NULL_PTR;
	}

	if (jsContect.isMember("pre_task_seq") && jsContect["pre_task_seq"].isUInt64())
	{
		pstOsScanWorkEntry->pre_task_seq = jsContect["pre_task_seq"].asUInt64();
		LOG_INFO("Get pre_task_seq:%llu", pstOsScanWorkEntry->pre_task_seq);
	}

	if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        //return HRA_BAD_PARAM;
    }
    else
    {
        _snprintf_s(pstOsScanWorkEntry->ascTaskId, sizeof(pstOsScanWorkEntry->ascTaskId), "%s",
                    jsContect["task_id"].asString().c_str());
    }


	//std::string stTaskid = jsContect["task_id"].asCString();
	//unsigned int ulCopyLen = stTaskid.size();
	//if (ulCopyLen > OS_SCAN_TASK_ID_MAX_LEN - 1)
	//{
	//	LOG_ERROR("Support task id max len %d, current len is %d.", OS_SCAN_TASK_ID_MAX_LEN - 1, ulCopyLen);
	//	return HRA_BAD_PARAM;
	//}

	//memcpy(pstOsScanWorkEntry->ascTaskId, stTaskid.c_str(), ulCopyLen);

	//if (jsContect.isMember("scan_type"))
	//{
 //       int lScanType = jsContect["scan_type"].asInt();
 //       pstOsScanWorkEntry->lScanType = lScanType;
	//}
	

    LOG_INFO("Parse json parameter finish.");
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描配置应用函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="pstOsScanWork">	[in] 配置存储结构体. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanCfgApply(struct OsScanWorkEntry *pstOsScanWork)
{
	if (!pstOsScanWork)
	{
		LOG_ERROR("Os scan work entry is null.");
		return HRA_NULL_PTR;
	}

	LOG_INFO("Thread add OsScan Worker start.");

	//添加到工作队列
    uint64_t nTaskSeq =
        HraTask_AddWorker(pstOsScanWork->ascTaskId, HRA_ELMT_OS_SCAN_CFG, ProMsgHead::MsgType::NOTIFIER, OsScanWorker,
                          pstOsScanWork, sizeof(struct OsScanWorkEntry), pstOsScanWork->pre_task_seq);
    LOG_INFO("Hra Task add OsScan Worker end.");
    if (nTaskSeq <= 0)
	{
		LOG_ERROR("Hra Task pool add worker failed.");
		return HRA_FAILED;
	}

	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描初始化函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanInit(void)
{
	int lEngineRet = 0;
	struct OsScanEngineApi *pstOsScanEngineApi = NULL;

	//解压最新的pattern压缩包
    LOG_INFO("The OSScan module starts to prepare the Pattern file.");
	lEngineRet = osScanPreparePattern();
	if (lEngineRet != HRA_OK)
	{
		LOG_ERROR("The OSScan failed to decompress the Pattern package.");
		goto _err;
	}

	UtilsStoreOSscanPatternVersionFromFile();

	//测试引擎加载情况
	pstOsScanEngineApi = OsScanEnginePatternInit(UtilsGetOSscanPatternVersionPath());
	if (pstOsScanEngineApi == NULL)
	{
		LOG_ERROR("Os scan engine init failed.");
		goto _err;
	}

	OsScanSetModuleWorkStatus(1);
	OsScanEngineDestroy(pstOsScanEngineApi);
	return HRA_OK;
_err:
	OsScanSetModuleWorkStatus(0);
	return HRA_FAILED;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描去初始化函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanDestroy(void)
{
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	对外暴露的配置处理函数. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="jsContect">	The json数据 . </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanCfgHandle(const Json::Value& jsContect)
{
	int lRet = HRA_OK;
	struct OsScanWorkEntry stOsScanWorkEntry;

	//if (OsScanGetModuleWorkStatus() == 0)
	//{
	//	LOG_ERROR("Os scan is not init, can not work.");
	//	return HRA_NOT_SUPPORTED;
	//}

	//解析
	memset(&stOsScanWorkEntry, 0, sizeof(struct OsScanWorkEntry));
    //stOsScanWorkEntry.lScanType = -1;

	lRet = OsScanCfgParse(&stOsScanWorkEntry, jsContect);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("OsScanCfgParse Failed.");
		goto _out;
	}
	//应用
	lRet = OsScanCfgApply(&stOsScanWorkEntry);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("OsScanCfgApply Failed.");
		goto _out;
	}

_out:
	return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Operating system scan pattern update. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="strPatternFile">	The pattern file. </param>
/// <param name="strTempDir">	 	The temporary dir. </param>
///
/// <returns>	HRA_OK：成功   HRA_NULL_PTR：参数为空   HRA_FAILED：执行失败. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanPatternUpdate(const std::string& strPatternFile, const std::string& strTempDir)
{
	int lRet = HRA_OK;
	std::string strPatternPath;     // pattern文件夹路径
	std::string strTemp;
	//std::string strCmd;
    char szCmd[MAX_COMD_BUFF_LEN] = {0};
	int lIndex = 0;
	bool bRet = FALSE;
	struct OsScanEngineApi *pstOsScanEngineApi = NULL;

	if(strPatternFile.size() == 0 || strTempDir.size() == 0)
	{
		LOG_ERROR("Parameter is null");
		lRet = HRA_NULL_PTR;
		goto _out;
	}

	//获取Pattern所在的文件夹路径
	strPatternPath = UtilsGetMetaInfoDir(OSSACN_PATTERN_DIR);
	if(strPatternPath.size() == 0)
	{
		LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
		lRet = HRA_FAILED;
		goto _out;
	}

	//在临时文件夹里解压
	lIndex = strPatternFile.rfind("\\");

	if (lIndex != std::string::npos)
	{
		strTemp = strPatternFile.substr(lIndex + 1);
	}
	else
	{
		strTemp = strPatternFile;
	}

	strTemp = strTempDir + strTemp;
    LOG_INFO(" The decompressed file is: %s .", strTemp.c_str());
	lRet = UtilsUnzip(strTemp);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("Failed to decompress the Pattern package.");
		goto _out;
	}
    LOG_INFO("Decompressed file %s succeed.", strTemp.c_str());

	//在临时文件夹中校验sha256值
	bRet = g_OsScanPatternUpdateUtils.VerifyPackageSha256(strTempDir);
	if (bRet != TRUE)
	{
		LOG_ERROR("The file has been modified or corrupted.");
		lRet = HRA_FAILED;
		goto _out;
	}

	//	校验成功，将pattern拷到工作目录
	g_OsScanPatternUpdateUtils.PatternLock(); //	加锁

	g_OsScanPatternUpdateUtils.DeleteFileExceptPatternZIP(strPatternPath);
	//strCmd = "xcopy /q /e /y /h " + strTempDir + "*  " + strPatternPath;
    //ExecuteCmd(strCmd.c_str(), NULL);
    //_snprintf_s(szCmd, sizeof(szCmd), "xcopy /q /e /y /h \"%s*\" \"%s\"", strTempDir.c_str(), strPatternPath.c_str());
    //system(szCmd);
    UtilsCopyDirFiles(UtilsStringToUnicode(strTempDir).c_str(), UtilsStringToUnicode(strPatternPath).c_str());

	//	更新版本信息
    UtilsStoreOSscanPatternVersionFromFile(true);
	//	测试引擎加载情况
	pstOsScanEngineApi = OsScanEnginePatternInit(UtilsGetOSscanPatternVersionPath());
	if (pstOsScanEngineApi == NULL)
	{
		OsScanSetModuleWorkStatus(0);
        g_OsScanPatternUpdateUtils.PatternUnLock(); //	解锁
		goto _out;
	}
	else
	{
		OsScanSetModuleWorkStatus(1);
		OsScanEngineDestroy(pstOsScanEngineApi);
	}

	g_OsScanPatternUpdateUtils.PatternUnLock(); //	解锁


_out:
	//	该函数退出时，删除pattern更新的临时目录
	//strCmd = "rmdir /q /s " + strTempDir;
    if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
    {
        LOG_ERROR("RemoveDirectory:%s error!", strTempDir.c_str());
    }
    LOG_INFO("RemoveDirectory:%s succeed!", strTempDir.c_str());

    //删除遗留pattern
    UtilsRemoveOldPattPack(strPatternPath);
	return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Operating system scan copy pattern pack. </summary>
///
/// <remarks>	, 2021/12/29. </remarks>
///
/// <param name="strPatternFile">	The pattern file. </param>
///
/// <returns>	A std::string. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int OsScanCopyPattPack(std::string& strTempDir, const std::string& strPatternFile)
{
	//	获取Pattern所在的文件夹路径
	std::string strPatternPath = UtilsGetMetaInfoDir(OSSACN_PATTERN_DIR);
	if(strPatternPath.size() == 0)
	{
		LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
		return HRA_FAILED;
	}

	//	创建临时文件夹用于保存patten，验证通过后再拷贝到对应目录
	/*std::string strTimeStamp = UtilsGetTimestamp();*/
    //strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetTimestamp() + "\\";
    strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetNanoTimestamp() + "\\";
	//std::string strCmd = "mkdir " + strTempDir;
	//ExecuteCmd(NULL, "mkdir \"%s\"", strTempDir.c_str());
    if (!CreateDirectoryA(strTempDir.c_str(), NULL))
    {
        LOG_ERROR("CreateDirectory:%s error!", strTempDir.c_str());
        return HRA_FAILED;
    }
    LOG_INFO("CreateDirectory:%s succeed!", strTempDir.c_str());

	int lRet = g_OsScanPatternUpdateUtils.CopyPatternFromDSA(strTempDir, strPatternFile);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("Failed to copy pattern package.");
        //ExecuteCmd(NULL, "rmdir /q /s \"%s\"", strTempDir.c_str());
        if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
        {
            LOG_ERROR("RemoveDirectory:%s error!", strTempDir.c_str());
        }
        LOG_INFO("RemoveDirectory:%s succeed!", strTempDir.c_str());
	}

	return lRet;
}


int OsScanCancelInit(void)
{
    return HRA_OK;
}

int OsScanCancelDestroy(void)
{
    return HRA_OK;
}

int OsScanCancelHandle(const Json::Value& jsContect)
{
    std::string task_id;
    if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
    {
        LOG_WARN("task_id not found!");
        //return HRA_BAD_PARAM;
    }
    else
    {
        task_id = jsContect["task_id"].asString();
    }

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_OS_SCAN_CFG, ProMsgHead::MsgType::NOTIFIER);
    return HRA_OK;
}
