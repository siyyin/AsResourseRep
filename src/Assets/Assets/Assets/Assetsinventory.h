#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <Windows.h>
#include <map>
#include <vector>
#include "DIAssetAutoRun.h"
#include "DIAssetDB.h"
#include "DIAssetPort.h"
#include "DIAssetTask.h"
#include "DIAssetWebService.h"

using namespace std;
using namespace di_rest_client;

#define FILE_INFO_SIZE 4096

#define MAX_LEN_512 512
#define MAX_LEN_256 256
#define MAX_LEN_128 128
#define MAX_LEN_21 21
#define MAX_LEN_32 32
#define MAX_LEN_IP 17
#define MAX_LEN_MAC 19
#define MAX_LEN_TIME 12
#define MAX_NET_NUM 15
#define MAX_DISK_NUM 20
#define MAX_CPU_NUM 8
#define MAX_USER_NUM 100

typedef struct _NETCARD_INFO {
    char strMac[MAX_LEN_MAC];
    char strip[MAX_LEN_IP * 10];
    char gateway[MAX_LEN_IP * 10];
    char strOutip[MAX_LEN_IP];
    char strNetCard[MAX_LEN_256];
    char dns[MAX_LEN_128];
    int inum;
} NETCARD_INFO;

typedef struct _DISK_INFO {
    char strDiskname[4];
    float ftotal;
    float fuse;
    char strencrypt[2];
    int inum;
    char filetype[20];
} DISK_INFO;

typedef struct _CPU_INFO {
    char strType[MAX_LEN_256];
    int icore;
    int inum;
} CPU_INFO;

typedef struct _ASSETS_HOSTINFO {
    char strHostName[MAX_LEN_256];
    char strDomain[MAX_LEN_256];
    NETCARD_INFO NetcardInfo[MAX_NET_NUM];
    char strMac[MAX_LEN_MAC];
    char strip[MAX_LEN_IP * 10];
    char strNetCard[MAX_LEN_256];
    char gateway[MAX_LEN_IP * 10];
    char dns[MAX_LEN_128];
    int iDeviceModel;  //0:"Windows桌面",1:"Windows服务器",2:"Linux服务器"
    unsigned int starttime;
    unsigned int installtime;
    char strSerialnumber[MAX_LEN_256];
    char strUuid[MAX_LEN_256];
    char strOs[MAX_LEN_256];
    char strSiteName[MAX_LEN_256];
    char strKernel[MAX_LEN_256];
    char strManufacturer[MAX_LEN_256];
    char strProduct_model[MAX_LEN_256];
    char strBios[MAX_LEN_256];
    char strAgent_version[MAX_LEN_32];
    char strAgent_id[MAX_LEN_256];
    CPU_INFO CpuInfo[MAX_CPU_NUM];
    char strCpu_usage[MAX_LEN_32];
    char strMemory[MAX_LEN_32];
    char strMemory_use[MAX_LEN_32];
    DISK_INFO DiskInfo[MAX_DISK_NUM];
} ASSETS_HOSTINFO;

typedef struct _ASSETS_USER {
    char strUser[MAX_LEN_512];
    char strUserName[MAX_LEN_256];
    char strGroup[MAX_LEN_256];
    char strType[2];
    unsigned int uLogonType;
    unsigned int uStatus;
    char strLocalAdmin[2];
    ;
    char strChpswtime[MAX_LEN_TIME];
    char strHostName[MAX_LEN_256];
    char strDomain[MAX_LEN_256];
    unsigned long lSessionID;
    unsigned __int64 uLoginTime;
    unsigned __int64 uLoginOutTime;
} ASSETS_USER;

typedef struct _ASSETS_APPLICATION {
    char vendor[MAX_LEN_256];
    char strApplication[MAX_LEN_256];
    char strApplicationversion[MAX_LEN_256];
    char strFilename[MAX_LEN_256];
    char strFileversion[MAX_LEN_32];
    char strPath[MAX_LEN_256];
    unsigned char sha1[21];
    UINT32 uUseTime;
    bool bdelete;
    bool bupload;
} ASSETS_APPLICATION;

typedef struct _ASSETS_SOFTWARE {
    char vendor[MAX_LEN_256];
    char strSoftname[MAX_LEN_256];
    char strSoftversion[MAX_LEN_256];
    char strInstalllocation[MAX_LEN_256];
    char strInstallTime[MAX_LEN_32];
    unsigned int uSize;
} ASSETS_SOFTWARE;

typedef DWORD(__stdcall *GetFileVersionInfoSizeWfun)(
    LPCWSTR lptstrFilename,
    LPDWORD lpdwHandle);

typedef DWORD(__stdcall *GetFileVersionInfoWfun)(
    LPCWSTR lptstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData);

typedef DWORD(__stdcall *GetFileVersionInfoSizeExWfun)(
    DWORD dwFlags,
    LPCWSTR lpwstrFilename,
    LPDWORD lpdwHandle);

typedef DWORD(__stdcall *GetFileVersionInfoExWfun)(
    DWORD dwFlags,
    LPCWSTR lpwstrFilename,
    DWORD dwHandle,
    DWORD dwLen,
    LPVOID lpData);

class Assetsinventory
{
  public:
    explicit Assetsinventory(char* pServerIp,char* pDeviceId,char* pAgentVersion);
    virtual ~Assetsinventory(void);

  public:
    void GetAssetInfor(void);
    std::string ConvertToJson(void);
    void UpdateApplicationinfo(bool bCreate, UINT64 pid, UINT64 uUseTime, wchar_t *pPath);
    void ResetUpLoadAsserts(){m_bFirstUpLoadAsserts = true;}
    void GetApplicationinfo(void);
    BOOL m_bFirstUpLoadAsserts;
    char m_szSystemRootPath[MAX_PATH];

  private:
    void GetDiskCapacity();
    void GetCpuInfo();
    void GetDomain();
    void GetHostinfo(void);
    void GetMemoryInfo(void);
    void GetUser(void);
    void GetSoftware(void);
    void GetHostInfoInit();
    
    std::string GetAdapter(void);
    char *GetFileInfoSub(const wchar_t *pSubblock, DWORD dwLangCharset);
    DWORD GetFileInfo(const char *pFileName);
    void EnrichApplication(ASSETS_APPLICATION &application, DWORD dLangCharset, const char *pPath);
    BOOL CheckProcessUserIsDomain(DWORD &dwPID);
    DWORD FindProcessPIDByName(LPCTSTR szProcessName);
    bool LoadLibraryVersion();

    std::vector<ASSETS_USER> m_Userinfo;
    std::map<std::string, ASSETS_APPLICATION> m_Application;
    std::map<std::string, std::vector<UINT64>> m_ProcPathPid;
    ASSETS_HOSTINFO m_HostInfo;

    unsigned int m_uLastTime;
    std::string m_ServerIp;
    std::string m_DeviceId;
    std::map<std::string, ASSETS_SOFTWARE> m_mapLastSoftInfo;
    std::map<std::string, ASSETS_SOFTWARE> m_mapLastSoftInfoAdd;
    std::map<std::string, ASSETS_SOFTWARE> m_mapLastSoftInfoDel;
    std::vector<std::wstring> m_strDomainUserName;
    char *m_pBuff;
    CRITICAL_SECTION m_cs;

    GetFileVersionInfoSizeWfun m_pGetFileVersionInfoSizeWfun;
    GetFileVersionInfoWfun m_pGetFileVersionInfoWfun;
    GetFileVersionInfoSizeExWfun m_pGetFileVersionInfoSizeExWfun;
    GetFileVersionInfoExWfun m_pGetFileVersionInfoExWfun;
    HMODULE m_hdll;
    bool m_bxp;

	DIAssetAutoRun *m_pDIAssetAutoRun;
	DIAssetDB*m_pDIAssetDB;
	DIAssetPort *m_pDIAssetPort;
	DIAssetTask *m_pDIAssetTask;
	DIAssetWebService *m_pDIAssetWebService;

	std::map<std::string, DIAssetWebServiceItem> m_list_webservice_table_pre;
	std::map<std::string, DIAssetWebServiceItem> m_list_webservice_table_add;
	std::map<std::string, DIAssetWebServiceItem> m_list_webservice_table_del;

	std::map<std::string, DIAssetDBItem> m_map_database_table_pre;
	std::map<std::string, DIAssetDBItem> m_map_database_table_add;
	std::map<std::string, DIAssetDBItem> m_map_database_table_del;

	std::map<std::string, DIAssetAutoRunItem> m_map_autorun_table_pre;
	std::map<std::string, DIAssetAutoRunItem> m_map_autorun_table_add;
	std::map<std::string, DIAssetAutoRunItem> m_map_autorun_table_del;

	std::map<std::string, DIAssetPortItem> m_map_all_ports_table_pre;
	std::map<std::string, DIAssetPortItem> m_map_all_ports_table_add;
	std::map<std::string, DIAssetPortItem> m_map_all_ports_table_del;

	std::map<std::string, DIAssetTaskItem> m_map_tasks_table_pre;
	std::map<std::string, DIAssetTaskItem> m_map_tasks_table_add;
	std::map<std::string, DIAssetTaskItem> m_map_tasks_table_del;
};

extern Assetsinventory *gpAssetsinventory;
