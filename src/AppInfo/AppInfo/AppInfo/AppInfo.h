#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <map>
#include <vector>

using namespace std;


#define FILE_INFO_SIZE 4096

#define MAX_LEN_512 512
#define MAX_LEN_256 256

typedef struct _APPINFO_APPLICATION {
    char vendor[MAX_LEN_256];
    char strApplication[MAX_LEN_256];
    char strApplicationversion[MAX_LEN_256];
    char strFilename[MAX_LEN_256];
} APPINFO_APPLICATION;

typedef struct _APPINFO_SOFTWARE {
    char vendor[MAX_LEN_256];
    char strSoftname[MAX_LEN_256];
    char strSoftversion[MAX_LEN_256];
    char strInstalllocation[MAX_LEN_256];
} APPINFO_SOFTWARE;

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

class AppInfo
{
  public:
    explicit AppInfo( );
    virtual ~AppInfo(void);

  public:
    std::string GetAppInfo(void);

  private:
    void GetSoftware(void);
    void GetApplicationinfo(void);
    
    

    char *GetFileInfoSub(const wchar_t *pSubblock, DWORD dwLangCharset);
    DWORD GetFileInfo(const char *pFileName);
    void EnrichApplication(APPINFO_APPLICATION &application, DWORD dLangCharset, const char *pPath);

    bool LoadLibraryVersion();


    std::map<std::string, APPINFO_APPLICATION> m_Application;
    char m_szSystemRootPath[MAX_PATH];
    char *m_pBuff;

    GetFileVersionInfoSizeWfun m_pGetFileVersionInfoSizeWfun;
    GetFileVersionInfoWfun m_pGetFileVersionInfoWfun;
    GetFileVersionInfoSizeExWfun m_pGetFileVersionInfoSizeExWfun;
    GetFileVersionInfoExWfun m_pGetFileVersionInfoExWfun;
    HMODULE m_hdll;
    bool m_bxp;

};

extern AppInfo *gpAppInfo;
