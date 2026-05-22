#include "ExtendFunc.h"


FILE *g_fp = NULL;

#ifdef _WIN32
#include <string>
#include <atlenc.h>
#include "base.h"
#include <windows.h>
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include <WinBase.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Version.lib")

#define MAX_BUFSIZE 1 * 1024 *1024
#define FILE_INFO_SIZE 4096

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

GetFileVersionInfoSizeWfun g_pGetFileVersionInfoSizeWfun;
GetFileVersionInfoWfun g_pGetFileVersionInfoWfun;
GetFileVersionInfoSizeExWfun g_pGetFileVersionInfoSizeExWfun;
GetFileVersionInfoExWfun g_pGetFileVersionInfoExWfun;
bool g_bxp;
HMODULE g_hdll =  NULL;

#else
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <regex.h>
using namespace std;
typedef unsigned char			byte;
typedef unsigned long			DWORD;
typedef int						BOOL;
typedef unsigned char			BYTE;
typedef unsigned short			WORD;
typedef float					FLOAT;

bool IsRpmOs(void)
{
    char line[256] = {0};
    FILE *fp = popen("dpkg -s dpkg &>/dev/null && echo dpkg; rpm -q rpm &>/dev/null && echo rpm;", "r");
    if (NULL == fp){
      return false;
    }

    fgets(line, sizeof(line), fp);
    pclose(fp);
    return (strncmp(line, "rpm", 3) == 0);
}

bool g_RpmOS = IsRpmOs();

void _itoa_s(int value, char* buffer, size_t sizeInCharacters, int radix)
{
	if (16 == radix)
		snprintf(buffer, sizeInCharacters, "%x", value);
}
#endif

#define BUFFER_READ_SIZE 0x40000
#define MAX_LEN_1024       1024
#define MAX_LEN_512         512
#define MAX_LEN_256         256



void ConvertHexToString(byte * hex_buffer, int hex_size, char * out_buffer, int out_size)
{
	if (hex_size * 2 + 2 > out_size)return;
	memset(out_buffer, 0, out_size);
	for (int count = 0; count < hex_size; count++) {
		//snprintf(out_buffer, out_size, "%s%02x", out_buffer, hex_buffer[count] & 0xff);
	}
}
 

#ifdef _WIN32
BOOL CheckFileExists(const char * FilePath) {

	LPWSTR FilePath_Unicode = ConverStringToUnicode(FilePath);
	BOOL Status = FALSE;
	do {
		if (FilePath_Unicode == NULL)
			break;

		WIN32_FIND_DATAW  FindData = { 0 };
		HANDLE hFile = FindFirstFileW(FilePath_Unicode, &FindData);
		if (hFile == INVALID_HANDLE_VALUE) {
			break;
		}
		FindClose(hFile);

		Status = TRUE;
	
	} while (false);

	if (FilePath_Unicode != NULL)
		VirtualFree(FilePath_Unicode, 0, MEM_RELEASE);

	return Status;
}

#endif

int PrintDbgMsgA(lua_State *L)
{
	int iParaCount = lua_gettop(L);
	if (1 == iParaCount)
	{
		const char* pszDbgMsg = (const char*)lua_tostring(L, 1);
		if (strlen(pszDbgMsg) > 0)
		{
#ifdef _WIN32
			OutputDebugStringA(pszDbgMsg);
#else 
			printf(pszDbgMsg);
#endif // _WIN32
		}
	}
	return 0;
}

int PrintDbgMsgW(lua_State *L)
{
#ifdef _WIN32
int iParaCount = lua_gettop(L);
	if (1 == iParaCount)
	{
		const char* pszDbgMsg = (const char*)lua_tostring(L, 1);
		DWORD dwDbgMsgLen = (DWORD)strlen(pszDbgMsg);
	    wchar_t* pwcsDbgMsg = new wchar_t[dwDbgMsgLen+1];
		memset(pwcsDbgMsg, 0, sizeof(wchar_t)*(dwDbgMsgLen+1));
		MultiByteToWideChar(CP_ACP, 0, pszDbgMsg, dwDbgMsgLen, pwcsDbgMsg, dwDbgMsgLen+1);
		if (wcslen(pwcsDbgMsg) > 0)
		{
			OutputDebugStringW(pwcsDbgMsg);
		}
		if (pwcsDbgMsg)
			delete[] pwcsDbgMsg;
	}

#endif // _WIN32
	return 0;
}


void RemoveSpecialLetter(std::string& raw)
{
  for (size_t i = 0; i < raw.size();) {
    if (raw[i] == '\"') {
      raw.erase(i, 1);
    }else if (raw[i] == '(') {
      raw.erase(i, 1);
    }if (raw[i] == ')') {
      raw.erase(i, 1);
    }else {
      i++;
    }
  }
}

#ifndef _WIN32
int GetLinuxBuild(char *pOstype)
{
  FILE *fp;
  std::string linuxbuild;
  char line[256] = {0};
  char *pline = line;
  size_t lineSize = 256;
  int lineLen = 0;
  int ret = 0;
  fp = fopen("/etc/os-release", "r");
  if (NULL == fp) {
    fp = fopen("/etc/redhat-release", "r");
    if (NULL == fp) {
      return ret;
    }
    else
    {
      while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
        pline[lineLen] = 0;
        linuxbuild = pline;
      }
      fclose(fp);

      RemoveSpecialLetter(linuxbuild);
      strcat(pOstype,linuxbuild.c_str());
    }
  }
  else
  {
    while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
      pline[lineLen] = 0;
      linuxbuild = pline;
      if (linuxbuild.find("PRETTY_NAME") != std::string::npos) {
        linuxbuild = linuxbuild.substr(linuxbuild.find_first_of("=") + 1);
        ret = 1;
        break;
      }
    }
    fclose(fp);

    RemoveSpecialLetter(linuxbuild);
    strcpy(pOstype,linuxbuild.c_str());
  }
  
  return ret;
}


int LinuxVersion(char *version)
{
  FILE *fp;
  std::string linux_version;
  char line[256] = {0};
  char *pline = line;
  size_t lineSize = 256;
  int lineLen = 0;
  int ret = 0;
  fp = fopen("/etc/os-release", "r");
  if (NULL == fp) {
    fp = popen("cat /etc/redhat-release|grep -Po \"\\d+\\.\\d+\"", "r");
    if (NULL == fp) {
      return ret;
    }
    else
    {
      while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
        pline[lineLen] = 0;
        linux_version = pline;
      }
      pclose(fp);

      RemoveSpecialLetter(linux_version);
      strcpy(version,linux_version.c_str());
    }
  }
  else
  {
    while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
      pline[lineLen] = 0;
      linux_version = pline;
      if (linux_version.find("VERSION_ID") != std::string::npos) {
        linux_version = linux_version.substr(linux_version.find_first_of("=") + 1);
        ret = 1;
        break;
      }
    }
    fclose(fp);

    RemoveSpecialLetter(linux_version);
    strcpy(version,linux_version.c_str());
  }
  
  return ret;
}

int GetFileVersion(char *filename,char *version)
{
  std::string file_version;
  char line[256] = {0};
  char *pline = line;
  size_t lineSize = 256;
  int lineLen = 0;
  int ret = 0;

  if (g_fp == NULL)
  {
    return ret;
  }

  fseek(g_fp,0,SEEK_SET);
  lineLen = getline(&pline, &lineSize, g_fp);
  while (lineLen > 0) {
    pline[lineLen] = 0;
    file_version = pline;
    if (file_version.find(filename) != std::string::npos) {
      file_version = file_version.substr(strlen(filename));
      file_version = file_version.substr(file_version.find_first_of("-") + 1);
      // printf("filename:%s\n",filename);
      // printf("package:%s",line);
      if (file_version.length()>0)
      {
        if (file_version[0]>=48 && file_version[0]<=57)//第一个字符必须是数字
        {
          ret = 1;
          strcpy(version,file_version.c_str());
          // printf("version:%s",version);
          break;
        }
      }
    }

    lineLen = getline(&pline, &lineSize, g_fp);
  }

  return ret;
}


int GetKernelRuning(char *pOstype)
{
  FILE *fp;
  std::string linuxbuild;
  char line[256] = {0};
  char *pline = line;
  size_t lineSize = 256;
  int lineLen = 0;
  int ret = 0;
  fp = popen("uname -r", "r");
  if (NULL == fp) {
    return ret;
  }
  while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
    pline[lineLen] = 0;
    linuxbuild = pline;
    break;
  }
  pclose(fp);

  RemoveSpecialLetter(linuxbuild);
  strcpy(pOstype,linuxbuild.c_str());
  return ret;
}


int GetKernelBoot(char *pOstype)
{
  FILE *fp;
  std::string linuxbuild;
  char line[256] = {0};
  char *pline = line;
  size_t lineSize = 256;
  int lineLen = 0;
  int ret = 0;
  fp = popen("grub2-editenv list", "r");
  if (NULL != fp) 
  {
    while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
      pline[lineLen] = 0;
      linuxbuild = pline;
      if (linuxbuild.find("saved_entry=") != std::string::npos) {
        linuxbuild = linuxbuild.substr(linuxbuild.find_first_of("(") + 1);
        ret = 1;
        break;
      }
    }
    pclose(fp);

    RemoveSpecialLetter(linuxbuild);

    if (linuxbuild.length()==0)
    {
      fp = fopen("/etc/grub.conf", "r");
      if (NULL == fp) {
        return ret;
      }
      else
      {
        while ((lineLen = getline(&pline, &lineSize, fp)) > 0) {
          pline[lineLen] = 0;
          linuxbuild = pline;
          if (linuxbuild.find("title ") != std::string::npos) {
            linuxbuild = linuxbuild.substr(linuxbuild.find_first_of("(") + 1);
            ret = 1;
            break;
          }
        }
        fclose(fp);

        RemoveSpecialLetter(linuxbuild);
      }
    }
    strcpy(pOstype,linuxbuild.c_str());
  }

  return ret;
}

#endif

int FunGetLinuxBuild(lua_State *L)
{
  char linuxbuild[256] = {0};

#ifndef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetLinuxBuild(linuxbuild);
#endif
  lua_pushstring(L, (const char*)linuxbuild);
  return 1;
}

int FunLinuxVersion(lua_State *L)
{
  char linuxversion[256] = {0};

#ifndef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  LinuxVersion(linuxversion);
#endif

  lua_pushstring(L, (const char*)linuxversion);
  return 1;
}

int FunGetKernelRuning(lua_State *L)
{
  char linuxversion[256] = {0};
#ifndef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetKernelRuning(linuxversion);
#endif

  lua_pushstring(L, (const char*)linuxversion);
  return 1;
}

int FunGetKernelBoot(lua_State *L)
{
  char linuxversion[256] = {0};
#ifndef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetKernelBoot(linuxversion);
#endif

  lua_pushstring(L, (const char*)linuxversion);
  return 1;
}

#ifndef _WIN32
int MatchRegex(const char *rx, char *string, int n_sub, /* char **substrings */...)
{
    int r = -1, n;
    regex_t crx;
    va_list va;
    char **substring;
    regmatch_t *sub_offsets;
    sub_offsets = (regmatch_t *)malloc(sizeof(regmatch_t) * (n_sub + 1));
    if (sub_offsets == NULL)
        return -1;

    memset(sub_offsets, 0, sizeof(regmatch_t) * (n_sub + 1));

    r = regcomp(&crx, rx, REG_EXTENDED);
    if (r != 0) {
        goto out;
    }

    r = regexec(&crx, string, n_sub + 1, sub_offsets, 0);
    if (r != 0 && r != REG_NOMATCH) {
        goto out;
    }
    regfree(&crx);
    if (r == REG_NOMATCH) {
        goto out;
    }

    va_start(va, n_sub);
    n = 1;
    while (n <= n_sub) {
        substring = va_arg(va, char **);
        if (substring != NULL) {
            if (sub_offsets[n].rm_so == -1) {
                va_end(va);
                free(sub_offsets);
                return -1;
            }
            *substring = string + sub_offsets[n].rm_so;
            *(string + sub_offsets[n].rm_eo) = 0;
        }
        n++;
    }
    va_end(va);
out:
    free(sub_offsets);
    return r;
}
#endif

#ifndef _WIN32
int VersionMatch(char *pscVerString, char *pscVerion, int size)
{
  /* 
  * pscVersion = "0:1.2.32ubuntu0.1" pscTemp = "1.2.32"
  * pscVersion = "3.10.0-1062.12.1.el7" pscTemp = "3.10.0-1062.12.1"
  * pscVersion = "4_12_14-150_41-default-8-2.2" pscTemp = "4_12_14-150_41"
  * pscVersion = "20080701-26.el7.noarch" pscTemp = "20080701-26"
  */
  char *pscTemp = NULL;

  if (NULL == pscVerString || NULL == pscVerion) {
    return 0;
  }

  MatchRegex("([0-9]+((\\.|_)[0-9]+)+(-[0-9]+((\\.|_)[0-9]+)*)*)|([0-9]+-([0-9]+(\\.[0-9])*)+)", pscVerString, 1, &pscTemp);
  if (pscTemp !=NULL)
    strncpy(pscVerion, pscTemp, size);
  
  return 1;
}
#endif

#ifndef _WIN32
int FunMatchRegex(lua_State *L)
{
  char scVersion[256] = {0};
  char scVerString[256] = {0};
  int iParaCount = lua_gettop(L);
  if (iParaCount != 1){
    return 0;
  }

  if (0 == lua_isstring(L, 1)) {
    return 0;
  }

  strncpy(scVerString, lua_tostring(L, 1), 256);
  int iRet = VersionMatch(scVerString, scVersion, sizeof(scVersion));
  
  lua_pushstring(L, (const char*)scVersion);
  return 1;
}
#endif

#ifdef _WIN32
int InitWmi(HRESULT &hres, IWbemLocator **pLoc, IWbemServices **pSvc)
{

  hres = CoInitializeEx(0, COINIT_MULTITHREADED);
  if (FAILED(hres)) {
    return -1;
  }

  hres = CoInitializeSecurity(
    NULL,
    -1,                           // COM authentication
    NULL,                         // Authentication services
    NULL,                         // Reserved
    RPC_C_AUTHN_LEVEL_DEFAULT,    // Default authentication
    RPC_C_IMP_LEVEL_IMPERSONATE,  // Default Impersonation
    NULL,                         // Authentication info
    EOAC_NONE,                    // Additional capabilities
    NULL                          // Reserved
    );

  if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
    CoUninitialize();
    return -1;  // Program has failed.
  }

  hres = CoCreateInstance(
    CLSID_WbemLocator,
    0,
    CLSCTX_INPROC_SERVER,
    IID_IWbemLocator, (LPVOID *)&(*pLoc));

  if (FAILED(hres)) {
    CoUninitialize();
    return -1;  // Program has failed.
  }

  hres = (*pLoc)->ConnectServer(
    _bstr_t(L"ROOT\\CIMV2"),  // Object path of WMI namespace
    NULL,                     // User name. NULL = current user
    NULL,                     // User password. NULL = current
    0,                        // Locale. NULL indicates current
    NULL,                     // Security flags.
    0,                        // Authority (for example, Kerberos)
    0,                        // Context object
    &(*pSvc)                  // pointer to IWbemServices proxy
    );

  if (FAILED(hres)) {
    (*pLoc)->Release();
    CoUninitialize();
    return -1;  // Program has failed.
  }

  hres = CoSetProxyBlanket(
    *pSvc,                        // Indicates the proxy to set
    RPC_C_AUTHN_WINNT,            // RPC_C_AUTHN_xxx
    RPC_C_AUTHZ_NONE,             // RPC_C_AUTHZ_xxx
    NULL,                         // Server principal name
    RPC_C_AUTHN_LEVEL_CALL,       // RPC_C_AUTHN_LEVEL_xxx
    RPC_C_IMP_LEVEL_IMPERSONATE,  // RPC_C_IMP_LEVEL_xxx
    NULL,                         // client identity
    EOAC_NONE                     // proxy capabilities
    );

  if (FAILED(hres)) {
    (*pSvc)->Release();
    (*pLoc)->Release();
    CoUninitialize();
    return -1;  // Program has failed.
  }

  return 0;
}

std::string WcharToString(const wchar_t* src)
{
  int iTextLen = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
  if (iTextLen + 1 >= MAX_BUFSIZE){
  }
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_UTF8, 0, src, -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
}


std::string GetWMIInfo(HRESULT hres, IWbemLocator *pLoc, IWbemServices *pSvc, std::string wql, std::wstring field, const std::string& dataType)
{

  std::string info;
  IEnumWbemClassObject *pEnumerator = NULL;

  hres = pSvc->ExecQuery(
    bstr_t("WQL"),
    bstr_t(wql.c_str()),
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
    NULL,
    &pEnumerator);

  if (FAILED(hres)) {
    return "";
  }

  IWbemClassObject *pclsObj = NULL;
  ULONG uReturn = 0;
  while (pEnumerator) {
    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
      &pclsObj, &uReturn);
    if (0 == uReturn) {
      break;
    }

    VARIANT vtProp;
    hr = pclsObj->Get(field.c_str(), 0, &vtProp, 0, 0);
    if (dataType == "string") {
      info = WcharToString(vtProp.bstrVal);//UnicodeToUtf8String(vtProp.bstrVal);
    } else if (dataType == "int") {
      info = std::to_string(vtProp.intVal);
    } else if (dataType == "bool") {
      if (vtProp.boolVal) {
        info = "true";
      } else {
        info = "false";
      }
    }
    VariantClear(&vtProp);
    pclsObj->Release();
  }

  pEnumerator->Release();
  return info;
}

std::string GetWMIInfoAll(HRESULT hres, IWbemLocator *pLoc, IWbemServices *pSvc, std::string wql, std::wstring field, const std::string& dataType)
{

  std::string info;
  IEnumWbemClassObject *pEnumerator = NULL;

  hres = pSvc->ExecQuery(
    bstr_t("WQL"),
    bstr_t(wql.c_str()),
    WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
    NULL,
    &pEnumerator);

  if (FAILED(hres)) {
    return "";
  }

  IWbemClassObject *pclsObj = NULL;
  ULONG uReturn = 0;
  while (pEnumerator) {
    HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
      &pclsObj, &uReturn);
    if (0 == uReturn) {
      break;
    }

    VARIANT vtProp;
    hr = pclsObj->Get(field.c_str(), 0, &vtProp, 0, 0);
    if (dataType == "string") {
      info = info+WcharToString(vtProp.bstrVal)+";";
    } else if (dataType == "int") {
      info = info+std::to_string(vtProp.intVal)+";";
    } else if (dataType == "bool") {
      if (vtProp.boolVal) {
        info = info+"true"+";";
      } else {
        info = info+"false"+";";
      }
    }
    VariantClear(&vtProp);
    pclsObj->Release();
  }

  pEnumerator->Release();
  return info;
}

void GetInstallKb(char *pinfo)
{
  HRESULT hres;
  IWbemLocator *pLoc;
  IWbemServices *pSvc;
  std::string data;
  int i = 0;

  if (pinfo==NULL)
  {
    return;
  }

  while (InitWmi(hres, &pLoc, &pSvc) != 0) {
    if (i < 3) {
      i++;
      continue;
    } else {
      return;
    }
  }

  //查询域

  data = GetWMIInfoAll(hres, pLoc, pSvc, "SELECT HotFixID FROM Win32_QuickFixEngineering", L"HotFixID", "string");
  memcpy(pinfo, data.c_str(), data.length());

  pSvc->Release();
  pLoc->Release();
  CoUninitialize();  //关闭该线程的COM库
}

void GetWindowsVersion(char *pVersion)
{
  HKEY hkRKey;
  DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_ALL_ACCESS, &hkRKey) == ERROR_SUCCESS) {
    WCHAR szValue[MAX_LEN_256] = {0};
    DWORD dwszValueLen = MAX_LEN_256;
    RegQueryValueEx(hkRKey, L"DisplayVersion", 0, &dwType, (LPBYTE)szValue, &dwszValueLen);
    if (szValue[0] == 0) {
      RegQueryValueEx(hkRKey, L"CurrentVersion", 0, &dwType, (LPBYTE)szValue, &dwszValueLen);
    }

    if (szValue[0] != 0)
    {
      std::string version = WcharToString(szValue).c_str();
      strncpy_s(pVersion, MAX_LEN_256, version.c_str(), -1);
    }

    RegCloseKey(hkRKey);
  }
}

void GetWindowsBuild(char *pVersion)
{
  HRESULT hres;
  IWbemLocator *pLoc;
  IWbemServices *pSvc;
  std::string data;
  int i = 0;

  if (pVersion==NULL)
  {
    return;
  }

  while (InitWmi(hres, &pLoc, &pSvc) != 0) {
    if (i < 3) {
      i++;
      continue;
    } else {
      return;
    }
  }

  //查询域

  data = GetWMIInfo(hres, pLoc, pSvc, "SELECT BuildNumber FROM Win32_OperatingSystem", L"BuildNumber", "string");
  memcpy(pVersion, data.c_str(), data.length());

  pSvc->Release();
  pLoc->Release();
  CoUninitialize();  //关闭该线程的COM库
}

void GetWindowsRevisonNumber(char *pVersion)
{
  HKEY hkRKey;
  DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_ALL_ACCESS, &hkRKey) == ERROR_SUCCESS) {
    WCHAR szValue[MAX_LEN_256] = {0};
    DWORD dwszValueLen = MAX_LEN_256;
    RegQueryValueEx(hkRKey, L"UBR", 0, &dwType, (LPBYTE)szValue, &dwszValueLen);
    if (szValue[0] == 0) {
      RegQueryValueEx(hkRKey, L"CSDVersion", 0, &dwType, (LPBYTE)szValue, &dwszValueLen);
      if (szValue[0] != 0)
      {
        std::string version = WcharToString(szValue).c_str();
        strncpy_s(pVersion, MAX_LEN_256, version.c_str(), -1);
      }
    }
    else
    {
      DWORD version = *(unsigned int *)szValue;
      sprintf_s(pVersion, MAX_LEN_256, "%d", version);
    }

    RegCloseKey(hkRKey);
  }
}

void GetWindowsName(char *pName)
{
  HRESULT hres;
  IWbemLocator *pLoc;
  IWbemServices *pSvc;
  std::string data;
  int i = 0;

  if (pName==NULL)
  {
    return;
  }

  while (InitWmi(hres, &pLoc, &pSvc) != 0) {
    if (i < 3) {
      i++;
      continue;
    } else {
      return;
    }
  }

  //查询域

  data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Caption FROM Win32_OperatingSystem", L"Caption", "string");
  memcpy(pName, data.c_str(), data.length());

  pSvc->Release();
  pLoc->Release();
  CoUninitialize();  //关闭该线程的COM库
}

std::wstring StringToWchar(const char* src)
{
  int unicodeLen = ::MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
  wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
  memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
  ::MultiByteToWideChar(CP_UTF8, 0, src, -1, (LPWSTR)pUnicode, unicodeLen);
  std::wstring rt(pUnicode);
  delete[] pUnicode;
  return rt;
}

bool StrEndWith(const char* pszText, const char* pszPostfix)
{
  if (pszText == NULL || pszPostfix == NULL) return false;
  size_t nTextLen = strlen(pszText);
  size_t nSuffixLen = strlen(pszPostfix);
  return nTextLen >= nSuffixLen && strcmp(pszText + nTextLen - nSuffixLen, pszPostfix) == 0;
}

int UnicodeToUtf8(char *pSrc, UINT32 uCodepage, char *pOut, int Outlen)
{
  int length = 0;
  if (pSrc == NULL || pOut == NULL) {
    return -1;
  }

  if (65001 == uCodepage) {
    length = (int)(strlen(pSrc));
    if (length >= Outlen - 1) {
      return -1;
    } else {
      strncpy_s(pOut, Outlen - 1, pSrc, length);
    }
  } else {
    length = WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)pSrc, -1, NULL, 0, NULL, NULL);
    if (length >= Outlen - 1) {
      return -1;
    }
    WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)pSrc, -1, pOut, length, NULL, NULL);
  }

  return length;
}


int GetFileVersion(char *filename,char *version)
{
  DWORD dwHandle;
  DWORD *pTransTable;
  UINT nQuerySize;
  DWORD dwDataSize;
  char buff[FILE_INFO_SIZE] = {0};
  char fullname[MAX_LEN_256]={0};

  DWORD dwRet = GetEnvironmentVariableA("SystemRoot", fullname, MAX_PATH - 1);
  if (dwRet == 0 || dwRet == MAX_PATH - 1) {
    strncpy_s(fullname, "C:\\windows", MAX_PATH - 1);
  }

  if (StrEndWith(filename,".exe")||StrEndWith(filename,".dll"))
  {
    strncat_s(fullname, "\\System32\\", MAX_PATH - 1);
    strncat_s(fullname, filename, MAX_PATH - 1);
  }
  else if(StrEndWith(filename,".sys"))
  {
    strncat_s(fullname, "\\System32\\drivers\\", MAX_PATH - 1);
    strncat_s(fullname, filename, MAX_PATH - 1);
  }

  std::wstring filepath = StringToWchar(fullname);

  if (g_bxp) {
    dwDataSize = g_pGetFileVersionInfoSizeWfun(filepath.c_str(), &dwHandle);
    if (dwDataSize == 0 || dwDataSize > FILE_INFO_SIZE) {
      return 0;
    }

    if (!g_pGetFileVersionInfoWfun(filepath.c_str(), dwHandle, dwDataSize,
      (void *)buff)) {
        return 0;
    }
  } else {
    dwDataSize = g_pGetFileVersionInfoSizeExWfun(FILE_VER_GET_NEUTRAL, filepath.c_str(), &dwHandle);
    if (dwDataSize == 0 || dwDataSize > FILE_INFO_SIZE) {
      return 0;
    }
    if (!g_pGetFileVersionInfoExWfun(FILE_VER_GET_NEUTRAL, filepath.c_str(), dwHandle, dwDataSize,
      (void *)buff)) {
        return 0;
    }
  }

  if (!::VerQueryValueW(buff, L"\\VarFileInfo\\Translation", (void **)&pTransTable, &nQuerySize)) {
    return 0;
  }

  DWORD uCodepage = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));

  wchar_t tmpstr[MAX_PATH] = {0};
  LPVOID lpData = NULL;
  swprintf_s(tmpstr, MAX_PATH, L"\\StringFileInfo\\%08lx\\ProductVersion", uCodepage);
  if (::VerQueryValueW((void *)buff, tmpstr, &lpData, &nQuerySize))
  {
    UnicodeToUtf8((char*)lpData, uCodepage, version, 255);
    std::string ver  = version;
    RemoveSpecialLetter(ver);
    strncpy_s(version,255,ver.c_str(),-1);
  }
  

  return 1;
}

#endif

int FunGetWindowsVersion(lua_State *L)
{
  char version[256] = {0};

#ifdef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetWindowsVersion(version);
#endif
  lua_pushstring(L, (const char*)version);
  return 1;
}

int FunGetWindowsBuild(lua_State *L)
{
  char version[256] = {0};

#ifdef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetWindowsBuild(version);
#endif
  lua_pushstring(L, (const char*)version);
  return 1;
}

int FunGetWindowsRevisonNumber(lua_State *L)
{
  char version[256] = {0};

#ifdef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetWindowsRevisonNumber(version);
#endif
  lua_pushstring(L, (const char*)version);
  return 1;
}

int FunGetInstallKB(lua_State *L)
{
  char instllkb[2048] = {0};

#ifdef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetInstallKb(instllkb);
#endif
  lua_pushstring(L, (const char*)instllkb);
  return 1;
}

int FunGetWindowsOs(lua_State *L)
{
  char version[256] = {0};

#ifdef _WIN32
  int iParaCount = lua_gettop(L);
  if (iParaCount != 0){
    return 0;
  }

  GetWindowsName(version);
#endif
  lua_pushstring(L, (const char*)version);
  return 1;
}


int FunGetFileVersion(lua_State *L)
{
  char fileversion[256] = "0";

  int iParaCount = lua_gettop(L);
  if (iParaCount != 1){
    return 0;
  }

  if (0 == lua_isstring(L, 1)) {
    return 0;
  }

  char* pszFilePath = (char*)lua_tostring(L, 1);
  GetFileVersion(pszFilePath,fileversion);

  lua_pushstring(L, (const char*)fileversion);
  return 1;
}

int initExtend()
{
#ifndef _WIN32
#else
  g_bxp = true;
  OSVERSIONINFO osvi;
  ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
  GetVersionEx(&osvi);
  if (osvi.dwMajorVersion > 5) {
    g_bxp = false;
  }

  if (g_bxp) {
    g_hdll = LoadLibraryA("version.dll");
    if (g_hdll == NULL)
      return 0;

    g_pGetFileVersionInfoSizeWfun = (GetFileVersionInfoSizeWfun)GetProcAddress(g_hdll,
      "GetFileVersionInfoSizeW");
    if (g_pGetFileVersionInfoSizeWfun == NULL) {
      FreeLibrary(g_hdll);
      g_hdll = NULL;
      return 0;
    }

    g_pGetFileVersionInfoWfun = (GetFileVersionInfoWfun)GetProcAddress(g_hdll,
      "GetFileVersionInfoW");
    if (g_pGetFileVersionInfoWfun == NULL) {
      FreeLibrary(g_hdll);
      g_hdll = NULL;
      return 0;
    }
  } else {
    //m_hdll = LoadLibraryA("Api-ms-win-core-version-l1-1-0.dll");
    g_hdll = LoadLibraryA("version.dll");
    if (g_hdll == NULL)
      return 0;

    g_pGetFileVersionInfoSizeExWfun = (GetFileVersionInfoSizeExWfun)GetProcAddress(g_hdll,
      "GetFileVersionInfoSizeExW");
    if (g_pGetFileVersionInfoSizeExWfun == NULL) {
      FreeLibrary(g_hdll);
      g_hdll = NULL;
      return 0;
    }

    g_pGetFileVersionInfoExWfun = (GetFileVersionInfoExWfun)GetProcAddress(g_hdll,
      "GetFileVersionInfoExW");
    if (g_pGetFileVersionInfoExWfun == NULL) {
      FreeLibrary(g_hdll);
      g_hdll = NULL;
      return 0;
    }
  }

#endif
  return 1;
}


int FreeExtend()
{
#ifndef _WIN32
  if (g_fp!=NULL)
  {
    fclose(g_fp);
  }
#else
  if (g_hdll != NULL) {
    FreeLibrary(g_hdll);
    g_hdll = NULL;
  }

#endif
  return 1;
}

int ResetFileCache()
{
#ifndef _WIN32

  FILE *fp;
  int ret = 0;
  if (g_fp!=NULL)
  {
    fclose(g_fp);
  }
  remove("aisfileversion");
  if (g_RpmOS) {
    fp = popen("rpm -qa>aisfileversion", "r");
  } else {
    fp = popen("dpkg -l | awk '{printf \"%s-%s\\n\",$2,$3}' > aisfileversion", "r");
  }
  if (NULL == fp) {
    return ret;
  }
  if (fp!=NULL)
  {
    pclose(fp);
  }

  g_fp = fopen("aisfileversion", "r");

#else
#endif
  return 0;
}
