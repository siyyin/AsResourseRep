#pragma once
#ifndef __HRA_PATTERN_UPDATE_UTILS_H__
#define __HRA_PATTERN_UPDATE_UTILS_H__
#include <fstream>
#include <sys/stat.h>
#include <errno.h>

#include "Logger.h"
#include "comm.h"
#include "json/json.h"
#include "HraJson.h"
#include "HraUtils.h"

#define PATTERN_VERSION_LEN 32
#define PATTERN_PATH_LEN 128

#define APPSACN_PATTERN_ZIP "vuln-soft_pattern_$$.zip"
#define OSSACN_PATTERN_ZIP "vuln-os_pattern_$$.zip"
#define BASELINE_PATTERN_ZIP "baseline_pattern_$$.zip"

#define PACKAGE_TEMP_DIR   "packagetmp"

class HRA_UTILITY_EXPORT CPatternUpdateUtils
{
private:
	CRITICAL_SECTION m_Mute;
public:
	CPatternUpdateUtils();
	~CPatternUpdateUtils();
	void PatternUnLock(void);
	void PatternLock(void);
	bool FileIsExist(const std::string& strFilePath);
	int CopyPatternFromDSA(const std::string& strDirPath, const std::string& strPatternFile);
	bool IsDir(const std::string& strFilePath);
	int DeleteFileExceptPatternZIP(const std::string& strPatternDir);
	bool VerifyPackageSha256(const std::string& strPatternInfoFile);
};

#endif