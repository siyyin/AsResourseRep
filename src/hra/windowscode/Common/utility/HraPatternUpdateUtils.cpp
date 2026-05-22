#include "HraPatternUpdateUtils.h"

CPatternUpdateUtils::CPatternUpdateUtils()
{
	InitializeCriticalSection(&m_Mute);
}

CPatternUpdateUtils::~CPatternUpdateUtils()
{
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	加锁，运用一个flag实现互斥. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////
void CPatternUpdateUtils::PatternLock(void)
{
    LOG_INFO("Pattern Lock......");
	EnterCriticalSection(&m_Mute);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	解锁，运用一个flag实现互斥. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
////////////////////////////////////////////////////////////////////////////////////////////////////
void CPatternUpdateUtils::PatternUnLock(void)
{
    LOG_INFO("Pattern UnLock......");
	LeaveCriticalSection(&m_Mute);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	将pattern从DSA的路径拷贝到HRA的路径. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strDirPath">	 	拷贝到的目录. </param>
/// <param name="strPatternFile">	需要更新的文件. </param>
///
/// <returns>	 HRA_OK：成功		HRA_NULL_PTR：参数为空		HRA_FAILED：执行失败. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int CPatternUpdateUtils::CopyPatternFromDSA(const std::string& strDirPath, const std::string& strPatternFile)
{
	//std::string strExecuteCmdRet;

	if(IsDir(strDirPath) == false || strPatternFile.size() == 0)
	{
		LOG_ERROR("The directory is invalid or the file list is empty! dir:%s, file:%s", strDirPath.c_str(), strPatternFile.c_str());
		return HRA_NULL_PTR;
	}

	//判断文件是否存在
	if (!FileIsExist(strPatternFile))
	{
		LOG_ERROR(" Pattern update: pattern file does not exist.%s", strPatternFile.c_str());
		return HRA_NOT_FOUND;
	}

    //char szCmd[MAX_COMD_BUFF_LEN];
    //memset(szCmd, 0, sizeof(szCmd));
    //_snprintf_s(szCmd, sizeof(szCmd), "copy /y \"%s\" \"%s\"", strPatternFile.c_str(), strDirPath.c_str());
	//ExecuteCmd(&strExecuteCmdRet, szCmd);
    //strExecuteCmdRet = AiiscToUtf8(strExecuteCmdRet.c_str());
    //LOG_INFO("update pattern cmd: %s. The execution result is %s", szCmd, strExecuteCmdRet.c_str());
    std::string strFileName = strPatternFile.substr(strPatternFile.find_last_of("\\") + 1, strPatternFile.length());
    char szFileDes[MAX_PATH];
    memset(szFileDes, 0, sizeof(szFileDes));
    _snprintf_s(szFileDes, sizeof(szFileDes), "%s\\%s", strDirPath.c_str(), strFileName.c_str());
    BOOL bRet = CopyFileA(strPatternFile.c_str(), szFileDes, FALSE);
    if (!bRet)
    {
        LOG_ERROR("CopyFile %s-->%s error! Code:%lu", strPatternFile.c_str(), szFileDes, GetLastError());
        return HRA_FAILED;
    }
    LOG_INFO("CopyFile %s-->%s succeed!", strPatternFile.c_str(), szFileDes);

    return HRA_OK;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	判断文件是否存在. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strFilePath">	文件路径. </param>
///
/// <returns>	True:存在, false:不存在. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CPatternUpdateUtils::FileIsExist(const std::string& strFilePath)
{
	struct stat stFileStat;
	if (stat(strFilePath.c_str(), &stFileStat) < 0)
	{
		return false;
	}
	else
	{
		return true;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	判断是否是文件夹. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strFilePath">	文件路径. </param>
///
/// <returns>	True:是文件夹, false:不是文件夹. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CPatternUpdateUtils::IsDir(const std::string& strFilePath)
{
    if (strFilePath.empty())
    {
        return false;
    }
    //去除末尾\\符号，否则stat会出错
    std::string strTmp = strFilePath;
    if (strTmp.at(strTmp.size()-1) == '\\')
    {
        strTmp.erase(strTmp.size()-1);
    }

	struct stat stFileStat;
    if (stat(strTmp.c_str(), &stFileStat) < 0)
	{
		return false;
	}

	if(S_IFDIR & stFileStat.st_mode)
	{
		return true;
	}
	else
	{
		return false;
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>	只保留压缩包，其他文件都删除. </summary>
///
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strPatternDir">	文件路径. </param>
///
/// <returns>	 HRA_OK：成功	HRA_NULL_PTR：参数为空	HRA_FAILED：执行失败. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
int CPatternUpdateUtils::DeleteFileExceptPatternZIP(const std::string& strPatternDir)
{
    if (strPatternDir.empty())
	{
		LOG_ERROR("Parameter is invalid");
		return HRA_BAD_PARAM;
	}

    BOOL bRet = TRUE;
    //删除meta_info.json
    std::string strPathDel = strPatternDir + PATTERN_INFORMATION;
    if (!DeleteFileA(strPathDel.c_str()))
    {
        LOG_ERROR("DeleteFile:%s error! Code:%lu", strPathDel.c_str(), GetLastError());
        bRet = FALSE;
    }
    else
    {
        LOG_INFO("DeleteFile:%s succeed!", strPathDel.c_str());
    }

    //删除data目录
    strPathDel = strPatternDir + PATTERN_DATA_DIR;
    if (!UtilsRemoveDirectory(UtilsStringToUnicode(strPathDel).c_str()))
    {
        LOG_ERROR("DeleteDir:%s error!", strPathDel.c_str());
        bRet = FALSE;
    }
    else
    {
        LOG_INFO("DeleteDir:%s succeed!", strPathDel.c_str());
    }

	return (bRet ? HRA_OK : HRA_FAILED);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
/// <summary>   验证pattern的sha256值，从strPatternDir目录下的PATTERN_INFORMATION
///				文件中获取pattern的文件信息，再计算PATTERN_DATA_DIR目录下文件的
///			    sha256值进行比对. </summary>
/// 
/// <remarks>	, 2021/12/23. </remarks>
///
/// <param name="strPatternDir">	pattern存放的路径. </param>
///
/// <returns>	True:sha256一致, false:sha256不一致. </returns>
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CPatternUpdateUtils::VerifyPackageSha256(const std::string& strPatternDir)
{
	Json::Value jsRoot;
	std::string strTemp = strPatternDir + PATTERN_INFORMATION;

	jsRoot = FileToJson(strTemp.c_str()); 
	if ( !(jsRoot.isMember("sha256") && jsRoot["sha256"].isArray()) )
	{
		LOG_ERROR("The file format does not meet expectations.");
		return false;
	}

	for (int i = 0; i < jsRoot["sha256"].size(); i++)
	{
		Json::Value jsOneFileInfo = jsRoot["sha256"][i];
		std::string strFileName = jsOneFileInfo["path"].asString();
		std::string strFileSha256 = jsOneFileInfo["sha256"].asString();

		strTemp = strPatternDir + PATTERN_DATA_DIR + '\\' + strFileName;
		std::string strSha256 = UtilsGetFileSHA256(strTemp);
		int lComareRet = strSha256.compare(strFileSha256);
		if (0 != lComareRet)
		{
            LOG_ERROR("File:%s, sha256 compare failed!", strFileName.c_str());
			return false;
		}
        LOG_DEBUG("File:%s, sha256 compare succeed!", strFileName.c_str());
	}

	return true;
}