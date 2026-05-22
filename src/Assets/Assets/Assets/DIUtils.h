#pragma once
#include <Windows.h>
// should be after Windows.h
#include <IPHlpApi.h>
#include <string>
#include <vector>
#include <strstream>
#include <Psapi.h>

#ifdef _WIN32
#define PRODUCT_REGISTRY_SUBKEY L"Software\\asiainfo-sec\\diagent"
#define PRODUCT_REGISTRY_VERSION_KEY L"version"
#define PROFILE_LIST_SUBKEY L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
#define PROFILE_IMAGE_PATH_KEY L"ProfileImagePath"
#endif

namespace di_rest_client
{
#ifdef _WIN32
  enum WIN_ESM_MODULES
  {
    WIN_ESM_EDR = 1,
    WIN_ESM_ASSETS,
    WIN_ESM_IOA
  };
#endif

UINT16 hashMacAddress(PIP_ADAPTER_INFO info);
void getMacHash(UINT16& mac1, UINT16& mac2);
UINT16 getVolumeHash(void);
UINT16 getCpuHash(void);
static void smear(UINT16* id);
static void unsmear(UINT16* id);
static UINT16* computeSystemUniqueId(void);
std::string getSystemUniqueId(void);

std::string GetASCTime(void);
std::string GetLocalDateTime(void);
std::string GetLocalDateTime(time_t& time);

std::string GetFileName(std::string& filePath);
std::string GetNameFromPath(char* pFilePath);
std::string GetFileDir(std::string& filePath);
DWORD GetTimestamp();

bool CopyFileToDir(const std::string sSrcFile, const std::string sDesDir);

bool SafeCopyFile(const std::string sSrcFile, const std::string sDesFile);

int ExecuteShell(const char * fmt, ...);

void GetDirectoryFiles(std::string path, std::vector<std::string>& files);

bool GetVer4PartFromVer2Part(const std::string sVer2Part, std::string& sOut);

bool GetVer4PartFromVer3Part(const std::string sVer3Part, std::string& sOut);

std::string GetClientVersion(void);

std::string GetClientVersionNumber(void);

std::string GetProductVersionNumber(void);

std::string GetDeviceName(void);

DWORD CalcFileSize(std::string filePath);

// return if versionA is greater than versionB
bool IsClientVersionGreaterThan(std::string versionA, std::string versionB);

BOOL IsWinVerGreaterThan(DWORD dwMajorVersion, DWORD dwMinorVersion);

BOOL IsWinVerEqualTo(DWORD dwMajorVersion, DWORD dwMinorVersion);

BOOL IsProductType(BYTE wProductType);

bool IsDesktopSystem();

std::string GetOSVersion(void);
std::string GetOSVersionWMI(void);

BOOL Is64BitOS(void);

BOOL EnablePrivilege(LPTSTR lpszPrivilege, BOOL bEnable);

bool ExtractProcessMandatory(unsigned long processId, UINT64& Mandatory);

bool ExtractProcessOwner(unsigned long processId, std::wstring& owner);

bool ZlibCompressFile(std::string source, std::string dest);

void DeleteFolderRecursively(const wchar_t* szFolderPath);

BOOL DeleteDirectory(const wchar_t * DirName);

BOOL CreateFolder(const wchar_t* szFolderPath);

BOOL CleanFolderFile(const wchar_t * DirName);

BOOL ExtractFileFromResource(TCHAR* szFileName, TCHAR* szResourceType, DWORD dwResourceID);

HANDLE OpenShareRead(const wchar_t* szFilePath);

BOOL GetFileTime(const TCHAR* szFileName, FILETIME& created, FILETIME& accessed, FILETIME& modified);

BOOL GetFileTime(HANDLE hFile, FILETIME& created, FILETIME& accessed, FILETIME& modified);

time_t FileTimeToUnixTime(FILETIME& ft);

void ListFiles(const wchar_t* szPath, const wchar_t* szFileName, std::vector<std::wstring>& fileList);

int FindFilesWithPrefix(std::string root, std::string prefix,std::vector<std::string> &fileVec);

BOOL ExecuteCmd(LPCWSTR pFile, LPCWSTR pPara, LPCWSTR pDir);

std::vector<std::wstring> GetAllUserSids(void);
bool GetProfileImagePathBySid(const wchar_t* szSid, std::wstring& strProfileImagePath);

typedef struct _OS_VERSION_MAP {
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    BOOL bIsWorkstation;
    char* szName;
} OS_VERSION_MAP;

bool CalcFileSha1Entity(const char* pszFilePath, unsigned char* pFileSha1, DWORD& dwBufSize);

std::string GetProcessStartTime(DWORD &dwPid);
std::string GetProcessStartTime1(DWORD &dwPid);

std::string oleTime2Str(double time);
std::string oleTime2Str1(double time);
std::string systemTime2Str(const SYSTEMTIME& st);

std::string StringToDatetime(std::string& str);

template<class src_type>
std::string type2str(src_type src) {
    std::strstream ss;
    ss << src;
    std::string ret;
    ss >> ret;

    return ret;
}

BOOL CheckProcessExist(LPCTSTR lpProcessName, DWORD& dwPid, BOOL bService = false);
BOOL CheckProcessExist(LPCTSTR lpProcessName, LPCTSTR lpParam, DWORD& dwPid, LPCTSTR& lpCmd, BOOL bService = false);
BOOL CheckProcessExist(LPCTSTR lpProcessName);
std::vector<DWORD> GetPidListByProcessName(LPCTSTR lpProcessName, BOOL bService = false);
std::vector<DWORD> GetPidListByProcessName(LPCTSTR lpProcessName, LPCTSTR lpParam, BOOL bService = false);
BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath);
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH]);
void ConvertHexToString(unsigned char *hex_buffer, int hex_size, char * out_buffer, int out_size);
BOOL CheckFileExist(std::string &strFilePath);
DWORD FindProcessPIDByName(LPCTSTR szProcessName);
BOOL GetAccountSid(LPTSTR AccountName, PSID *Sid);
BOOL GetCurrentUserSid(LPWSTR *sid);
TCHAR* GetProcessCommandLine(DWORD dwPID);
BOOL CheckPIDIsServiceProcess(DWORD processId);
std::wstring GetFileVersion(std::wstring strExePath);
std::wstring GetLargerVerIOAPatternName(void);
std::wstring GetLargerVerIOAPatternName(std::wstring& sDir);
int GetPatternNumberFromPatternFile(std::wstring &fileName);
std::string GetStrFromRandom(int iLen = 8);
std::string GetStrFromInt(int iData);
std::string GetStrFromUInt(unsigned int iData);
BOOL GetCurrentUser(std::string &sUserName);
}  // namespace di_rest_client