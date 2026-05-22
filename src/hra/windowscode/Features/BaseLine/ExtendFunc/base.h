#ifdef _WIN32
#include <windows.h>
#include <vector>
#include <map>

#define MAX_LEN_512 512
#define MAX_LEN_256 256
#define MAX_LEN_32 32

LPWSTR ConverStringToUnicode(const char* Str);
LPSTR ConvertUnicodeString(WCHAR* Str);
void ConvertSlashSymbol(char* str);
void ConvertBackSlashSymbol(char* Str);

typedef struct _BASELINE_SOFTWARE
{
    char szRegFullPath[MAX_LEN_256];
    char szVendor[MAX_LEN_256];
    char szSoftName[MAX_LEN_256];
    char szSoftVersion[MAX_LEN_256];
    char szInstallLocation[MAX_LEN_256];
    char szInstallTime[MAX_LEN_32];
    //unsigned int nSize;
} BASELINE_SOFTWARE;

typedef struct _BASELINE_APPLICATION
{
    char szVendor[MAX_LEN_256];
    char szApplication[MAX_LEN_256];
    char szApplicationVersion[MAX_LEN_256];
    char szFileName[MAX_LEN_256];
    char szFileVersion[MAX_LEN_32];
    char szPath[MAX_LEN_256];
    unsigned char ucSha1[21];
    //unsigned int nUseTime;
} BASELINE_APPLICATION;

time_t FileTimeToUnixTime(FILETIME& ft);
void GetSoftWare(std::vector<BASELINE_SOFTWARE>& vctSoftware, HKEY RootKey, LPCTSTR lpSubKey);
void GeRegUserWare(std::vector<BASELINE_SOFTWARE>& vctSoftware, HKEY RootKey);

//DWORD GetFileInfo(unsigned char* pBuff, size_t nBuffSize, const wchar_t* pFileName);
//wchar_t* GetFileInfoSub(const wchar_t* pSubblock, DWORD dwLangCharset, const unsigned char* pBuff);
void EnrichApplication(BASELINE_APPLICATION& application, const wchar_t* pPath);
void GetApplicationInfo(std::map<std::string, BASELINE_APPLICATION>& mapApplication);

unsigned short aisntohs(unsigned short port);
std::string GetTcpIpv4Port();
std::string GetTcpIpv6Port();
std::string GetUdpIpv4Port();
std::string GetUdpIpv6Port();

#endif