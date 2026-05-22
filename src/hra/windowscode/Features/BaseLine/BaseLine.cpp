#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <fstream>
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "BaseLine.h"
#include "BaseLineEngine.h"
#include "utility/version.hpp"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
#include "utility/Logger.h"
#include "utility/HraPatternUpdateUtils.h"
#include "utility/HraCtrlCmd.h"
#include "utility/ConfigSave.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraTaskType.h"
#include "HraIpcInterface/HraIpcCommDef.h"

#include <NTSecAPI.h>
#include <map>

//json串返回值
const int JSON_RET_PASS       = 0;
const int JSON_RET_UNPASS     = 1;
const int JSON_RET_UNINVOLVED = 2;
const int JSON_RET_ERROR      = 4;

//扫描依赖
struct ScanDepend
{
    std::string pre_shell; // lua脚本路径
    std::string pst_shell; // lua脚本路径

    void clear()
    {
        pre_shell.clear();
        pre_shell.clear();
    }

    ScanDepend()
    {
        clear();
    }

    ScanDepend operator=(const ScanDepend b)
    {
        this->pre_shell = b.pre_shell;
        this->pst_shell = b.pst_shell;
        return *this;
    }

    bool operator==(const ScanDepend b) const
    {
        if (0 == strcmp(this->pre_shell.c_str(), b.pre_shell.c_str()) &&
            0 == strcmp(this->pst_shell.c_str(), b.pst_shell.c_str()))
        {
            return true;
        }
        return false;
    }

    bool operator!=(const ScanDepend b) const
    {
        if (0 != strcmp(this->pre_shell.c_str(), b.pre_shell.c_str()) ||
            0 != strcmp(this->pst_shell.c_str(), b.pst_shell.c_str()))
        {
            return true;
        }
        return false;
    }

    bool operator<(const ScanDepend b) const
    {
        if (strcmp(this->pre_shell.c_str(), b.pre_shell.c_str()) < 0 ||
            strcmp(this->pst_shell.c_str(), b.pst_shell.c_str()) < 0)
        {
            return true;
        }
        return false;
    }
};

////cust_blp.json中需要的结构
//struct JsonPattern
//{
//    std::string scan_id;
//    std::string scan_shell;// lua脚本路径
//    std::string pre_shell; // lua脚本路径
//    std::string pst_shell; // lua脚本路径
//
//    void clear()
//    {
//        scan_id.clear();
//        scan_shell.clear();
//        pre_shell.clear();
//        pst_shell.clear();
//    }
//
//    JsonPattern()
//    {
//        clear();
//    }
//};

////执行计划
//struct ScanPlan
//{
//    JsonPattern json_pattern;
//    BaseLineScanItem scan_item;
//
//    void clear()
//    {
//        json_pattern.clear();
//        scan_item.clear();
//    }
//
//    ScanPlan()
//    {
//        clear();
//    }
//};

CPatternUpdateUtils g_BaselinePatternUpdateUtils;
char g_scBaseLineModuleWork = 1;

std::map<int, int> g_mapJsonRetPriority;
void InitJsonRetPriority()
{
    g_mapJsonRetPriority.insert(std::map<int, int>::value_type(JSON_RET_ERROR,3));
    g_mapJsonRetPriority.insert(std::map<int, int>::value_type(JSON_RET_UNPASS, 2));
    g_mapJsonRetPriority.insert(std::map<int, int>::value_type(JSON_RET_PASS, 1));
    g_mapJsonRetPriority.insert(std::map<int, int>::value_type(JSON_RET_UNINVOLVED, 0));
}

//struct BaseLineEngineApi *BaseLineEnginePatternInit(const char* pszSecTempName);
//int BaseLineEngineDestroy(struct BaseLineEngineApi *pstBaseLineEngineApi);
//static int baseLinePreparePattern(void);
//Json::Value BaseLineResultHandle(const std::vector<std::string>& vctPatternScanIds, const std::string& strScanResult);
//std::string BaseLineJsonParam(const char* strScanIds, const char* pszSecTempName);

/// <summary>
/// 解析cust_blp.json
/// </summary>
/// <param name="mapJsonPattern"></param>
/// <returns></returns>
int BaseLineParseJsonPattern(BaseLineWorkEntry& entry)
{
    //std::string strWorkPath    = UtilsGetWorkPath();
    std::string strPatternPath = UtilsGetBaselinePatternVersionPath();
    if (strPatternPath.empty())
    {
        LOG_ERROR("Baseline pattern path empty!");
        return HRA_FAILED;
    }
    std::string strBLVersion = UtilsGetBaselinePatternVersion();
    if (strBLVersion.empty())
    {
        LOG_ERROR("Baseline pattern version empty!");
        return HRA_FAILED;
    }

    //读文件
    std::string strJsonPattern = UtilsFileDecryption(strPatternPath);
    if (strJsonPattern.empty())
    {
        LOG_ERROR("Read baseline pattern failed! file:%s", strPatternPath.c_str());
        return HRA_FAILED;
    }

    //解析json
    std::set<int> setScanIDs;//用于排重，防止重复配置
    Json::Value jsPattern = StringToJson(strJsonPattern.c_str(), (int)strJsonPattern.length());
    if (jsPattern.empty())
    {
        LOG_ERROR("StringToJson error! file:%s, content:%s", strPatternPath.c_str(), strJsonPattern.c_str());
        return HRA_FAILED;
    }

    if (!jsPattern.isMember("scan_items") || !jsPattern["scan_items"].isArray())
    {
        LOG_ERROR("There is no scan_items array in json! file:%s", strPatternPath.c_str());
        return HRA_FAILED;
    }
    for (int i = 0; i < (int)jsPattern["scan_items"].size(); ++i)
    {
        //JsonPattern sJsonPatternTmp;
        Json::Value jsIterm = jsPattern["scan_items"][i];
        //scan_id
        if (!jsIterm.isMember("scan_id") || !jsIterm["scan_id"].isInt())
        {
            LOG_ERROR("There is no scan_id string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        int tmp_scan_id = jsIterm["scan_id"].asInt();

        // scan_shell
        if (!jsIterm.isMember("scan_shell") || !jsIterm["scan_shell"].isString())
        {
            LOG_ERROR("There is no scan_shell string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        std::string tmp_scan_shell = jsIterm["scan_shell"].asString();
        if (tmp_scan_shell.empty())
        {
            LOG_ERROR("scan_shell empty! scan_id:%d, file:%s", tmp_scan_id, strPatternPath.c_str());
            return HRA_FAILED;
        }
        std::replace(tmp_scan_shell.begin(), tmp_scan_shell.end(), '/', '\\');

        // pre_shell
        if (!jsIterm.isMember("pre_shell") || !jsIterm["pre_shell"].isString())
        {
            LOG_ERROR("There is no pre_shell string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        std::string tmp_pre_shell = jsIterm["pre_shell"].asString();
        std::replace(tmp_pre_shell.begin(), tmp_pre_shell.end(), '/', '\\');

        // pst_shell
        if (!jsIterm.isMember("pst_shell") || !jsIterm["pst_shell"].isString())
        {
            LOG_ERROR("There is no pst_shell string in json! file:%s", strPatternPath.c_str());
            return HRA_FAILED;
        }
        std::string tmp_pst_shell = jsIterm["pst_shell"].asString();
        std::replace(tmp_pst_shell.begin(), tmp_pst_shell.end(), '/', '\\');

        if (setScanIDs.end() != setScanIDs.find(tmp_scan_id))
        {
            LOG_ERROR("There is repeat scan_id:%d in json! file:%s", tmp_scan_id, strPatternPath.c_str());
            return HRA_FAILED;
        }
        setScanIDs.insert(tmp_scan_id);

        //填充entry
        for (std::vector<BaseLineScanItem>::iterator it = entry.scan_items.begin(); entry.scan_items.end() != it; ++it)
        {
            if (it->scan_id == tmp_scan_id)
            {
                it->scan_shell = tmp_scan_shell + "$" + strBLVersion;
                it->pre_shell  = tmp_pre_shell.empty() ? "" : tmp_pre_shell + "$" + strBLVersion;
                it->pst_shell  = tmp_pst_shell.empty() ? "" : tmp_pst_shell + "$" + strBLVersion;
            }
        }
    }

    return HRA_OK;
}

static char BaseLineGetModuleWorkStatus(void)
{
	return g_scBaseLineModuleWork;
}

static void BaseLineSetModuleWorkStatus(char scBaseLineModuleWork)
{
	g_scBaseLineModuleWork = scBaseLineModuleWork;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	从pattern目录解压最新的pattern压缩包. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <returns>	A int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
static int baseLinePreparePattern(void)
{
	std::string strPatternDir = UtilsGetMetaInfoDir(BASELINE_PATTERN_DIR);

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
    g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, "BaselinePatternUpdateTime", strLocalTime);

    return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	基线核查配置解析函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pstBaseLineWorkEntry">	[in,out] If non-null, the pst base line work entry. </param>
/// <param name="jsContect">		   	The js contect. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineCfgParse(BaseLineWorkEntry *pstBaseLineWorkEntry, const Json::Value& jsContect)
{
	if (!pstBaseLineWorkEntry)
	{
		LOG_ERROR("BaseLine work entry is null.");
		return HRA_NULL_PTR;
	}
    pstBaseLineWorkEntry->clear();

    //task_id
	if (!jsContect.isMember("task_id") || !jsContect["task_id"].isString())
	{
		LOG_WARN("There is no task_id string object in Json data.");
		//return HRA_NOT_FOUND;
	}
    else
    {
        pstBaseLineWorkEntry->task_id = jsContect["task_id"].asString();
    }

    //cmd_src
    //if (!jsContect.isMember("cmd_src") || !jsContect["cmd_src"].isString())
    //{
    //    LOG_ERROR("There is no cmd_src string object in Json data.");
    //    return HRA_NOT_FOUND;
    //}
    //pstBaseLineWorkEntry->cmd_src = jsContect["cmd_src"].asString();

    //scan_items
    if (!jsContect.isMember("scan_items") || !jsContect["scan_items"].isArray())
    {
        LOG_ERROR("There is no scan_items array object in Json data.");
        return HRA_NOT_FOUND;
    }
    const Json::Value jsArrayObj = jsContect["scan_items"];
    for (int i = 0; i < (int)jsArrayObj.size(); ++i)
    {
        BaseLineScanItem sScanItem;
        //scan_id
        if (!jsArrayObj[i].isMember("scan_id") || !jsArrayObj[i]["scan_id"].isInt())
        {
            LOG_ERROR("There is no scan_id string object in Json data.");
            return HRA_NOT_FOUND;
        }
        sScanItem.scan_id = jsArrayObj[i]["scan_id"].asInt();

        // template_type
        if (!jsArrayObj[i].isMember("template_type") || !jsArrayObj[i]["template_type"].isInt())
        {
            LOG_ERROR("There is no template_type string object in Json data.");
            return HRA_NOT_FOUND;
        }
        sScanItem.template_type = jsArrayObj[i]["template_type"].asInt();

        //params
        if (!jsArrayObj[i].isMember("params"))
        {
            LOG_ERROR("There is no params arrary object in Json data.");
            return HRA_NOT_FOUND;
        }

        if (jsArrayObj[i]["params"].isNull())
        {
            pstBaseLineWorkEntry->scan_items.push_back(sScanItem);
            continue;
        }

        if (!jsArrayObj[i]["params"].isArray())
        {
            LOG_ERROR("There is no params arrary object in Json data.");
            return HRA_NOT_FOUND;
        }

        const Json::Value jsArrayParams = jsArrayObj[i]["params"];
        for (int j = 0; j < (int)jsArrayParams.size(); ++j)
        {
            //param
            BaseLineParam sParam;
            if (!jsArrayParams[j].isMember("param"))
            {
                LOG_ERROR("There is no param object in Json data.");
                return HRA_NOT_FOUND;
            }

            if (jsArrayParams[j]["param"].isNull())
            {
                sScanItem.params.push_back(sParam);
                continue;
            }

            if (!jsArrayParams[j]["param"].isArray())
            {
                LOG_ERROR("There is no param arrary object in Json data.");
                return HRA_NOT_FOUND;
            }
            
            const Json::Value jsArrayParam = jsArrayParams[j]["param"];
            for (int k = 0; k < (int)jsArrayParam.size(); ++k)
            {
                if (!jsArrayParam[k].isString())
                {
                    LOG_ERROR("There is no param string object in Json data.");
                    return HRA_NOT_FOUND;
                }
                sParam.param.push_back(jsArrayParam[k].asString());
            }
            sScanItem.params.push_back(sParam);
        }
        pstBaseLineWorkEntry->scan_items.push_back(sScanItem);
    }
    if (pstBaseLineWorkEntry->scan_items.empty())
    {
        LOG_ERROR("Param error! scan_items empty!");
        return HRA_BAD_PARAM;
    }

    LOG_INFO("Parse json parameter finish.");
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	baseline扫描结果处理函数. </summary>
///
/// <remarks>	, 2022/1/25. </remarks>
///
/// <param name="strGradeType"> 	Type of the grade. </param>
/// <param name="pscPolicy">		[in] the psc policy. </param>
/// <param name="strScanResult">	The scan result. </param>
///
/// <returns>	A Json::Value. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
Json::Value BaseLineResultHandle(const std::vector<std::string>& vctPatternScanIds, const std::string& strScanResult)
{
	//Json::Value root;
	Json::Value arrayObj;
	Json::Value item;
	//Json::Value jsPattern;
	//Json::Value jsPatternScanItem;
	Json::Value jsScanResult;
	Json::Value jsResultScanItem;
	//std::vector<std::string> v_ScanItemInPattern;
	std::vector<std::string> v_ScanItemInResult;
	int lIndex = 0;

    //转换扫描结果为json格式
    jsScanResult = StringToJson(strScanResult.c_str(), (unsigned int)strScanResult.size());
    if (jsScanResult.size() == 0 || !jsScanResult.isMember("result"))
    {
        LOG_ERROR("the pattern has no member result.");
        return arrayObj;
    }

    jsResultScanItem = jsScanResult["result"];
    for (int j = 0; j < (int)jsResultScanItem.size(); ++j)
    {
        std::string strScanItem = jsResultScanItem[j]["scan_id"].asCString();
        v_ScanItemInResult.push_back(strScanItem);
    }
	
	//重新组装扫描结果
	for(auto iter = vctPatternScanIds.begin(); iter!= vctPatternScanIds.end(); ++iter)
	{
		if(std::find(v_ScanItemInResult.begin(), v_ScanItemInResult.end(), *iter) != v_ScanItemInResult.end())
		{
			item["scan_id"] = *iter;
			item["status"] = "0";
		}
		else
		{
			item["scan_id"] = *iter;
			item["status"] = "1";
		}
		arrayObj.append(item);
	}

	return arrayObj;
}
////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	Operating system scan report. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pscTaskId">		[in,out] If non-null, identifier for the psc task. </param>
/// <param name="lRet">				The ret. </param>
/// <param name="strScanResult">	The scan result. </param>
/// <param name="lScanType">		The scan type. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineReport(const char* pscTaskId, /*const char* pszCmdSrc,*/ int lRet, const std::string& strScanResult)
{
    std::string strResultInfo = GetReportResultInfo(pscTaskId, lRet, strScanResult.c_str(), LOG_LEVEL_INFO);

	//结果上报
	CReportInfo cReportBaseLineInfo;
	cReportBaseLineInfo.SetCompress(NEED_COMPRESSION);
	cReportBaseLineInfo.Request(HraMsgHead::MsgType::FEATURE_RESULT, BASELINE_RESULT, strResultInfo.c_str(), strResultInfo.size());
	cReportBaseLineInfo.ShowRspHdr();

	return HRA_OK;
}

/// <summary>
/// lua扫描结果转换json串返回结果
/// </summary>
/// <param name="nLuaRet"></param>
/// <returns></returns>
int LuaRetToJsonRet(int nLuaRet)
{
    int nJsonRet = JSON_RET_ERROR;
    if (nLuaRet == BASE_LINE_LUA_RET_PASS)
    {
        nJsonRet = JSON_RET_PASS; //通过
    }
    else if (nLuaRet == BASE_LINE_LUA_RET_UNINVOLVED)
    {
        nJsonRet = JSON_RET_UNINVOLVED; //不涉及
    }
    else if (nLuaRet == BASE_LINE_LUA_RET_UNPASS)
    {
        nJsonRet = JSON_RET_UNPASS; //不通过
    }
    else if (nLuaRet <= BASE_LINE_LUA_RET_ERROR)
    {
        nJsonRet = JSON_RET_ERROR; //出错
    }
    else
    {
        nJsonRet = JSON_RET_ERROR; //出错
    }

    return nJsonRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	系统扫描工作函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pArg">	[in,out] If non-null, the argument. </param>
///
/// <returns>	Null if it fails, else a pointer to a void. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
void *BaseLineWorker(void *pArg)
{
    int lRet = HRA_OK;
    int iCtrlCmd = HraCtrlCmd::CmdDef::cmd_init;
    Json::Value jsScanResults;
    BaseLineWorkEntry workEntry;
    LOG_INFO("Baseline Worker(%d) start.", HRA_ELMT_BASE_LINE_CFG);

    //加锁
    g_BaselinePatternUpdateUtils.PatternLock(); 

    //do while(false)代码段
    do
    {
        if (!pArg)
        {
            LOG_ERROR("Baseline work input paramater is null.");
            lRet = HRA_Code::HRA_NULL_PTR;
            break;
        }

        std::string strContect = (char*)pArg;
        Json::Value jsValue    = StringToJson(strContect.c_str(), (unsigned int)strContect.length());
        lRet                   = BaseLineCfgParse(&workEntry, jsValue);
        if (lRet != HRA_OK)
        {
            break;
        }

        if (BaseLineGetModuleWorkStatus() == 0)
        {
            LOG_ERROR("Baseline is not init, can not work.");
            lRet = HRA_NOT_SUPPORTED;
            break;
        }

        //埋点
        iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
        if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
        {
            lRet = HRA_Code::HRA_USER_CANCEL;
            break;
        }

        //加载json
        lRet = BaseLineParseJsonPattern(workEntry);
        if (lRet != HRA_OK)
        {
            LOG_ERROR("The Baseline failed to parse the Pattern file.");
            break;
        }

        //组织执行计划
        std::map<ScanDepend, std::vector<BaseLineScanItem>> mapScanPlan;
        for (std::vector<BaseLineScanItem>::const_iterator it = workEntry.scan_items.begin(); 
             workEntry.scan_items.end() != it; ++it)
        {
            ScanDepend tmp_dep;
            tmp_dep.pre_shell = it->pre_shell;
            tmp_dep.pst_shell = it->pst_shell;

            std::map<ScanDepend, std::vector<BaseLineScanItem>>::iterator itFind = mapScanPlan.find(tmp_dep);
            if (mapScanPlan.end() == itFind)
            {
                std::vector<BaseLineScanItem> vctPlan;
                vctPlan.push_back(*it);
                mapScanPlan.insert(std::map<ScanDepend, std::vector<BaseLineScanItem>>::value_type(tmp_dep, vctPlan));
            }
            else
            {
                itFind->second.push_back(*it);
            }
        }

        //逐个扫描
        for (std::map<ScanDepend, std::vector<BaseLineScanItem>>::const_iterator it = mapScanPlan.begin(); 
             mapScanPlan.end() != it; ++it)
        {
            //埋点
            iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
            if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
            {
                lRet = HRA_Code::HRA_USER_CANCEL;
                break;
            }

            //前置任务执行
            std::vector<std::string> tmp_param;
            int nPreRet = BASE_LINE_LUA_RET_PASS;
            if (!it->first.pre_shell.empty())
            {
                lRet = BaseLineExcuteScan(nPreRet, it->first.pre_shell, tmp_param);
                if (lRet != HRA_OK)
                {
                    //后置任务执行
                    tmp_param.clear();
                    int nPstRet = BASE_LINE_LUA_RET_PASS;
                    if (!it->first.pst_shell.empty())
                    {
                        BaseLineExcuteScan(nPstRet, it->first.pst_shell, tmp_param);
                    }
                    break;
                }
            }

            //扫描项
            for (std::vector<BaseLineScanItem>::const_iterator itVct = it->second.begin(); it->second.end() != itVct;
                 ++itVct)
            {
                //埋点
                iCtrlCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
                if (iCtrlCmd == HraCtrlCmd::CmdDef::cmd_cancel)
                {
                    lRet = HRA_Code::HRA_USER_CANCEL;
                    break;
                }

                LOG_INFO("scan_id:%d", itVct->scan_id);
                //管理端有可能params参数直接给空数组，无param参数
                //此时也需要执行一次扫描
                if (itVct->params.empty())
                {
                    int nJsonStatusTmp = BASE_LINE_LUA_RET_UNINVOLVED;
                    //只有前置通过的才会继续扫描
                    if (nPreRet == BASE_LINE_LUA_RET_PASS)
                    {
                        int nScanRet = BASE_LINE_LUA_RET_ERROR;
                        if (!itVct->scan_shell.empty())
                        {
                            std::vector<std::string> vctParamTmp;
                            lRet = BaseLineExcuteScan(nScanRet, itVct->scan_shell, vctParamTmp);
                            if (lRet != HRA_OK)
                            {
                                lRet = HRA_FAILED;
                                LOG_ERROR("BaseLineExcuteScan error:%d, %s", lRet, itVct->scan_shell.c_str());
                                break;
                            }
                        }
                        else
                        {
                            nScanRet = BASE_LINE_LUA_RET_UNINVOLVED;
                        }

                        //转换结果
                        nJsonStatusTmp = LuaRetToJsonRet(nScanRet);
                    }
                    //前置不通过或者是报错，扫描项全都不通过
                    //前置依赖不涉及，扫描项全都不涉及
                    //其他返回值则为出错
                    else
                    {
                        nJsonStatusTmp = LuaRetToJsonRet(nPreRet);
                    }

                    Json::Value jsResultContent;
                    jsResultContent.resize(0);
                    Json::Value jsScanItem;
                    jsScanItem["scan_id"]        = itVct->scan_id;
                    jsScanItem["template_type"]  = itVct->template_type;
                    jsScanItem["status"]         = nJsonStatusTmp;
                    jsScanItem["result_content"] = jsResultContent;
                    jsScanResults.append(jsScanItem);
                }
                else
                {
                    Json::Value jsResultContent;
                    for (std::vector<BaseLineParam>::const_iterator itParam = itVct->params.begin();
                         itVct->params.end() != itParam; ++itParam)
                    {
                        Json::Value jsResult;
                        jsResult["param"].resize(0);
                        //参数列表
                        for (std::vector<std::string>::const_iterator itParamList = itParam->param.begin();
                             itParam->param.end() != itParamList; ++itParamList)
                        {
                            jsResult["param"].append(*itParamList);
                        }

                        //只有前置通过的才会继续扫描
                        if (nPreRet == BASE_LINE_LUA_RET_PASS)
                        {
                            int nScanRet = BASE_LINE_LUA_RET_ERROR;
                            if (!itVct->scan_shell.empty())
                            {
                                lRet = BaseLineExcuteScan(nScanRet, itVct->scan_shell, itParam->param);
                                if (lRet != HRA_OK)
                                {
                                    lRet = HRA_FAILED;
                                    LOG_ERROR("BaseLineExcuteScan error:%d, %s", lRet, itVct->scan_shell.c_str());
                                    break;
                                }
                            }
                            else
                            {
                                nScanRet = BASE_LINE_LUA_RET_UNINVOLVED;
                            }

                            //转换结果
                            jsResult["result"] = LuaRetToJsonRet(nScanRet);
                        }
                        else
                        {
                            jsResult["result"] = LuaRetToJsonRet(nPreRet);
                        }
                        jsResultContent.append(jsResult);
                    }

                    //依据所有扫描结果判断此scan_id的status，依据优先级判断
                    int nJsonStatusTmp = JSON_RET_UNINVOLVED; //初始化最低优先级
                    for (int i = 0; i < jsResultContent.size(); ++i)
                    {
                        //当前最新
                        std::map<int, int>::const_iterator itCurr = g_mapJsonRetPriority.find(nJsonStatusTmp);
                        if (itCurr == g_mapJsonRetPriority.end())
                        {
                            nJsonStatusTmp = JSON_RET_ERROR;
                            break;
                        }
                        //每个扫描结果
                        std::map<int, int>::const_iterator itFind =
                            g_mapJsonRetPriority.find(jsResultContent[i]["result"].asInt());
                        if (itFind == g_mapJsonRetPriority.end())
                        {
                            nJsonStatusTmp = JSON_RET_ERROR;
                            break;
                        }

                        if (itFind->second > itCurr->second)
                        {
                            nJsonStatusTmp = itFind->first; //取优先级最大的
                        }
                    }

                    Json::Value jsScanItem;
                    jsScanItem["scan_id"]        = itVct->scan_id;
                    jsScanItem["template_type"]  = itVct->template_type;
                    jsScanItem["status"]         = nJsonStatusTmp;
                    jsScanItem["result_content"] = jsResultContent;
                    jsScanResults.append(jsScanItem);
                }

                if (lRet != HRA_OK)
                {
                    break;
                }
            }
            
            //后置任务执行
            tmp_param.clear();
            int nPstRet = BASE_LINE_LUA_RET_PASS;
            if (!it->first.pst_shell.empty())
            {
                BaseLineExcuteScan(nPstRet, it->first.pst_shell, tmp_param);
            }

            if (lRet != HRA_OK)
            {
                break;
            }
        }
        if (lRet != HRA_OK)
        {
            break;
        }
    } while (false);

    g_BaselinePatternUpdateUtils.PatternUnLock(); //解锁

    std::string strScanResult = JsonToString(jsScanResults);
	LOG_DEBUG("BaseLine scan result:%s", strScanResult.c_str());
    BaseLineReport(workEntry.task_id.c_str(), /*workEntry.cmd_src.c_str(), */lRet, strScanResult);
    LOG_INFO("Baseline Worker(%d) end.", HRA_ELMT_BASE_LINE_CFG);

    return NULL;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	 基线核查应用函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="pstBaseLineWorkEntry">	[in,out] If non-null, the pst base line work entry. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineCfgApply(const BaseLineWorkEntry& stBaseLineWorkEntry, const Json::Value& jsContect)
{
    LOG_INFO("[HRA] Thread add BaseLine Worker start.");

    std::string strContect = jsContect.toStyledString();
    int iSize = (int)strContect.length() + 1;
    char* pszParam = (char*)malloc(iSize);
    if (!pszParam)
    {
        LOG_ERROR("malloc error!");
        return HRA_MALLOC_FAIL;
    }
    memset(pszParam, 0, iSize);
    strncpy_s(pszParam, iSize, strContect.c_str(), strContect.length());

	//添加到工作队列
    uint64_t nTaskSeq = HraTask_AddWorker(stBaseLineWorkEntry.task_id.c_str(), HRA_ELMT_BASE_LINE_CFG,
                             ProMsgHead::MsgType::NOTIFIER, BaseLineWorker, pszParam, iSize);
    LOG_INFO("Hra Task add BaseLine Worker end.");
    if (pszParam)
    {
        free(pszParam);
        pszParam = NULL;
    }

	if (nTaskSeq <= 0)
	{
		LOG_ERROR("Hra Task pool add worker failed.");
		return HRA_FAILED;
	}

	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	基线核查初始化函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineInit(void)
{
    //初始化优先级
    InitJsonRetPriority();

    //注册日志函数
    //BLRegistLogFun(ModuleLogFun);

	//解压最新的pattern压缩包
    LOG_INFO("The Baseline module starts to prepare the Pattern file.");
    int ret = baseLinePreparePattern();
    if (ret != HRA_OK)
	{
		LOG_ERROR("The Baseline failed to decompress the Pattern package.");
		goto _err;
	}

	UtilsStoreBaselinePatternVersionFromFile();

	//测试json文件加载情况
    //BaseLineWorkEntry entry;
    //ret = BaseLineParseJsonPattern(entry);
    //if (ret != HRA_OK)
    //{
    //    LOG_ERROR("The Baseline failed to parse the Pattern file.");
    //    goto _err;
    //}

	BaseLineSetModuleWorkStatus(1);
	return HRA_OK;
_err:
	BaseLineSetModuleWorkStatus(0);
	return HRA_FAILED;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	基线核查资源销毁函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineDestroy(void)
{
	return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	对外暴露的配置处理函数. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="jsContect">	The js contect. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineCfgHandle(const Json::Value& jsContect)
{
	int lRet = HRA_OK;
	BaseLineWorkEntry stBaseLineWorkEntry;

	//if (BaseLineGetModuleWorkStatus() == 0)
	//{
	//	LOG_ERROR("Baseline is not init, can not work.");
	//	return HRA_NOT_SUPPORTED;
	//}

	//解析
	lRet = BaseLineCfgParse(&stBaseLineWorkEntry, jsContect);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("BaseLineCfgParse Failed.");
		goto _out;
	}
	//应用
    lRet = BaseLineCfgApply(stBaseLineWorkEntry, jsContect);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("BaseLineCfgApply Failed.");
		goto _out;
	}

_out:
	return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	strPatternFile: Pattern在DSA的路径. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="strPatternFile">	The pattern file. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLinePatternUpdate(const std::string& strPatternFile, const std::string& strTempDir)
{
    int lRet = HRA_OK;
    std::string strPatternPath; // pattern文件夹路径
    std::string strTemp;
    // std::string strCmd;
    char szCmd[MAX_COMD_BUFF_LEN]                  = {0};
    int lIndex                                     = 0;
    bool bRet                                      = FALSE;
    BaseLineWorkEntry entry;

    if (strPatternFile.size() == 0 || strTempDir.size() == 0)
    {
        LOG_ERROR("Parameter is null");
        lRet = HRA_NULL_PTR;
        goto _out;
    }

    //获取Pattern所在的文件夹路径
    strPatternPath = UtilsGetMetaInfoDir(BASELINE_PATTERN_DIR);
    if (strPatternPath.size() == 0)
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
    bRet = g_BaselinePatternUpdateUtils.VerifyPackageSha256(strTempDir);
    if (bRet != TRUE)
    {
        LOG_ERROR("The file has been modified or corrupted.");
        lRet = HRA_FAILED;
        goto _out;
    }

    //	校验成功，将pattern拷到工作目录
    g_BaselinePatternUpdateUtils.PatternLock(); //	加锁

    g_BaselinePatternUpdateUtils.DeleteFileExceptPatternZIP(strPatternPath);
    // strCmd = "xcopy /q /e /y /h " + strTempDir + "*  " + strPatternPath;
    // ExecuteCmd(strCmd.c_str(), NULL);
    //_snprintf_s(szCmd, sizeof(szCmd), "xcopy /q /e /y /h \"%s*\" \"%s\"", strTempDir.c_str(), strPatternPath.c_str());
    //system(szCmd);
    UtilsCopyDirFiles(UtilsStringToUnicode(strTempDir).c_str(), UtilsStringToUnicode(strPatternPath).c_str());

    //	更新版本信息
    UtilsStoreBaselinePatternVersionFromFile(true);
    //	测试引擎加载情况
    lRet = BaseLineParseJsonPattern(entry);
    if (lRet != HRA_OK)
    {
        LOG_ERROR("The Baseline failed to parse the Pattern file.");
        BaseLineSetModuleWorkStatus(0);
        g_BaselinePatternUpdateUtils.PatternUnLock(); //	解锁
        goto _out;
    }
    else
    {
        BaseLineSetModuleWorkStatus(1);
    }

    g_BaselinePatternUpdateUtils.PatternUnLock(); //	解锁

_out:
    //	该函数退出时，删除pattern更新的临时目录
    if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
    {
        LOG_ERROR("Delete %s error!", strTempDir.c_str());
    }
    LOG_INFO("Delete %s succeed!", strTempDir.c_str());

    //删除遗留pattern
    UtilsRemoveOldPattPack(strPatternPath);
    return lRet;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	strPatternFile:pattern路径. </summary>
///
/// <remarks>	, 2022/1/12. </remarks>
///
/// <param name="strPatternFile">	The pattern file. </param>
///
/// <returns>	An int. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int BaseLineCopyPattPack(std::string& strTempDir, const std::string& strPatternFile)
{
	//	获取Pattern所在的文件夹路径
	std::string strPatternPath = UtilsGetMetaInfoDir(BASELINE_PATTERN_DIR);
	if(strPatternPath.size() == 0)
	{
		LOG_ERROR("Failed to obtain the pattern folder path.  Procedure");
		return HRA_FAILED;
	}

	//	创建临时文件夹用于保存patten，验证通过后再拷贝到对应目录
    //strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetTimestamp() + "\\";
    strTempDir = strPatternPath + PACKAGE_TEMP_DIR + "-" + UtilsGetNanoTimestamp() + "\\";
	//std::string strCmd = "mkdir " + strTempDir;
	//ExecuteCmd(NULL, "mkdir \"%s\"", strTempDir.c_str());
    if (!CreateDirectoryA(strTempDir.c_str(), NULL))
    {
        LOG_ERROR("CreateDirectory:%s error! Code:%lu", strTempDir.c_str(), GetLastError());
        return HRA_FAILED;
    }
    LOG_INFO("CreateDirectory:%s succeed!", strTempDir.c_str());

	int lRet = g_BaselinePatternUpdateUtils.CopyPatternFromDSA(strTempDir, strPatternFile);
	if (HRA_OK != lRet)
	{
		LOG_ERROR("Failed to copy pattern package.");
        //ExecuteCmd(NULL, "rmdir /q /s \"%s\"", strTempDir.c_str());
        if (!UtilsRemoveDirectory(UtilsStringToUnicode(strTempDir).c_str()))
        {
            LOG_ERROR("UtilsRemoveDirectory:%s error!", strTempDir.c_str());
        }
        LOG_INFO("UtilsRemoveDirectory:%s succeed!", strTempDir.c_str());
		return lRet;
	}

	return lRet;
}

int BaseLineCancelInit(void)
{
    return HRA_OK;
}

int BaseLineCancelDestroy(void)
{
    return HRA_OK;
}

int BaseLineCancelHandle(const Json::Value& jsContect)
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

    HraTask_CancelWorker(task_id.c_str(), HRA_ELMT_BASE_LINE_CFG, ProMsgHead::MsgType::NOTIFIER);
    return HRA_OK;
}