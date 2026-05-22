#define _WIN32_DCOM
#include "ExtendFunc.h"
#include <string>
#include <atlenc.h>
#include "base.h"
#include <windows.h>
#include <string>
#include <WinBase.h>
#include <WinReg.h>
#include <WinNT.h>
#include <wbemidl.h>
#include <comdef.h>
#include <WinVer.h>
#include <vector>
#include <regex>
#include <map>
#include <iostream>
#include <lm.h>
#include <iphlpapi.h>
#include <io.h>
#include <fstream>
#include "utility/Logger.h"
#include "utility/ConfigSave.h"
#include "utility/HraUtils.h"
#include "utility/HraReport.h"
#include "utility/HraKbDataMgr.h"
#include "utility/HraCtrlCmd.h"
#include "Libs/LibUtilityBase/WMICommInterface.h"

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Version.lib")

#define MAX_LEN_1024       1024
#define MAX_LEN_512         512
#define MAX_LEN_256         256

int PrintLog(lua_State* L)
{
    int iParaCount = lua_gettop(L);
    if (5 != iParaCount)
    {
        return 0;
    }

    int iLevel = (int)lua_tointeger(L, 1);
    const char* pszFile = (const char*)lua_tostring(L, 2);
    const char* pszFun = (const char*)lua_tostring(L, 3);
    int iLine = (int)lua_tointeger(L, 4);
    const char* pszLogLine = (const char*)lua_tostring(L, 5);
    std::string strLogLine = pszLogLine == NULL ? "" : pszLogLine;
    std::regex percentRegex("%");
    strLogLine = std::regex_replace(strLogLine, percentRegex, "%%");
    CLoger::Log(iLevel, pszFile == NULL ? "" : pszFile, pszFun == NULL ? "" : pszFun, iLine, strLogLine.c_str());
    
    return 0;
}

int PrintDbgMsgA(lua_State *L)
{
	int iParaCount = lua_gettop(L);
	if (1 == iParaCount)
	{
		const char* pszDbgMsg = (const char*)lua_tostring(L, 1);
		if (strlen(pszDbgMsg) > 0)
		{
			OutputDebugStringA(pszDbgMsg);
		}
	}
	return 0;
}

int PrintDbgMsgW(lua_State *L)
{

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
	return 0;
}


std::string cmdPopen(char* cmdLine) {
  char buffer[1024] = { '\0' };
  FILE* pf = NULL;
  pf = _popen(cmdLine, "r");
  if (NULL == pf) {
    printf("open pipe failed\n");
    return std::string("");
  }
  std::string ret;
  while (fgets(buffer, sizeof(buffer), pf)) {
    ret += buffer;
  }
  _pclose(pf);
  return ret;
}


int FunCmdPopen(lua_State *L)
{
  char cmd[256] = "0";

  int iParaCount = lua_gettop(L);
  if (iParaCount != 1){
    return 0;
  }

  if (0 == lua_isstring(L, 1)) {
    return 0;
  }

  char* pcmd = (char*)lua_tostring(L, 1);
  std::string result = cmdPopen(pcmd);

  lua_pushstring(L, (const char*)result.c_str());
  return 1;
}


std::string AisRegQueryValue(HKEY RootKey, char* lpSubKey,char* lpKeyName)
{
  std::string data = "error";
  char szBuffer[MAX_PATH] = {0};
  DWORD dwKeyLen = MAX_PATH;
  DWORD dwBuffLen = MAX_PATH;
  DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
  HKEY hkRKey;
  LONG lReturn;
  lReturn = RegOpenKeyExA(RootKey, lpSubKey, 0, KEY_ALL_ACCESS, &hkRKey);
  if (lReturn == ERROR_SUCCESS) {
    if (RegQueryValueExA(hkRKey, lpKeyName, 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
      //data = szBuffer;
      data = std::string(szBuffer, dwBuffLen);
    }
    RegCloseKey(hkRKey);
  }

  return data;
}

int AisRegQueryValueInt(HKEY RootKey, char* lpSubKey,char* lpKeyName)
{
  int iret = -1;
  char szBuffer[MAX_PATH] = {0};
  DWORD dwKeyLen = MAX_PATH;
  DWORD dwBuffLen = MAX_PATH;
  DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
  HKEY hkRKey;
  LONG lReturn;
  lReturn = RegOpenKeyExA(RootKey, lpSubKey, 0, KEY_ALL_ACCESS, &hkRKey);
  if (lReturn == ERROR_SUCCESS) {
    if (RegQueryValueExA(hkRKey, lpKeyName, 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
      iret = *(int *)szBuffer;
    }
    RegCloseKey(hkRKey);
  }

  return iret;
}

int FunGetRegStr(lua_State *L)
{
  HKEY RootKey = NULL;
  char* lpSubKey = NULL;
  char* lpKeyName = NULL;

  int iParaCount = lua_gettop(L);
  if (iParaCount != 3){
    return 0;
  }

  if (0 == lua_isstring(L, 1)) {
    return 0;
  }

  RootKey = (HKEY)lua_tostring(L, 1);

  if (*(char*)RootKey=='1')
  {
    RootKey = HKEY_CLASSES_ROOT;
  }
  else if (*(char*)RootKey=='2')
  {
    RootKey = HKEY_CURRENT_USER;
  }
  else if (*(char*)RootKey=='3')
  {
    RootKey = HKEY_LOCAL_MACHINE;
  }
  else if (*(char*)RootKey=='4')
  {
    RootKey = HKEY_USERS;
  }


  if (0 == lua_isstring(L, 2)) {
    return 0;
  }

  lpSubKey = (char*)lua_tostring(L, 2);

  if (0 == lua_isstring(L, 3)) {
    return 0;
  }

  lpKeyName = (char*)lua_tostring(L, 3);

  std::string result = AisRegQueryValue(RootKey,lpSubKey,lpKeyName);
  lua_pushstring(L, (const char*)result.c_str());

  return 1;
}

int FunGetRegInt(lua_State *L)
{
  HKEY RootKey = NULL;
  char* lpSubKey = NULL;
  char* lpKeyName = NULL;

  int iParaCount = lua_gettop(L);
  if (iParaCount != 3){
    return 0;
  }

  if (0 == lua_isstring(L, 1)) {
    return 0;
  }

  RootKey = (HKEY)lua_tostring(L, 1);

  if (*(char*)RootKey=='1')
  {
    RootKey = HKEY_CLASSES_ROOT;
  }
  else if (*(char*)RootKey=='2')
  {
    RootKey = HKEY_CURRENT_USER;
  }
  else if (*(char*)RootKey=='3')
  {
    RootKey = HKEY_LOCAL_MACHINE;
  }
  else if (*(char*)RootKey=='4')
  {
    RootKey = HKEY_USERS;
  }

  if (0 == lua_isstring(L, 2)) {
    return 0;
  }

  lpSubKey = (char*)lua_tostring(L, 2);

  if (0 == lua_isstring(L, 3)) {
    return 0;
  }

  lpKeyName = (char*)lua_tostring(L, 3);

  int result = AisRegQueryValueInt(RootKey,lpSubKey,lpKeyName);
  lua_pushinteger(L, result);

  return 1;
}


// 用正则匹配，遍历注册表路径下的子项
// "000001F4"，  "^[\\d]+"
//子项放在vecSubKeys中
bool AisRegQueryRegular(HKEY RootKey, char* lpSubKey, char* pRegular, std::vector<std::string>& vecSubKeys)
{
  bool bRet = true;
  vecSubKeys.clear();
  char szBuffer[MAX_PATH] = {0};
  DWORD dwBuffLen = MAX_PATH;
  HKEY hkRKey;
  LONG lReturn;

  lReturn = RegOpenKeyExA(RootKey, lpSubKey, 0, KEY_ALL_ACCESS , &hkRKey);
  if (lReturn == ERROR_SUCCESS) 
  {
    DWORD index = 0;
    try
    {
      std::regex reg(pRegular);
      while (ERROR_SUCCESS == RegEnumKeyA(hkRKey, index++, szBuffer, dwBuffLen))
      {
        if (std::regex_search(szBuffer, reg))
        {
          vecSubKeys.push_back(szBuffer);
        }
      }
    }
    catch(char*)
    {
      bRet = false;
    }
  }
  else
  {
    bRet = false;
  }

  RegCloseKey(hkRKey);
  return bRet;
}

//查找具有相同F值得用户
//返回值：-1没有拿到F值，0没有F值相同的用户，1有F值相同的用户
int FunUsersIdentification(lua_State *L)
{
  int result = -1;
  HKEY RootKey = NULL;
  char* lpSubKey = NULL;

  int iParaCount = lua_gettop(L);
  if (iParaCount != 2){
    return 0;
  }

  if (0 == lua_isstring(L, 1)) {
    return 0;
  }

  RootKey = (HKEY)lua_tostring(L, 1);

  if (*(char*)RootKey=='1')
  {
    RootKey = HKEY_CLASSES_ROOT;
  }
  else if (*(char*)RootKey=='2')
  {
    RootKey = HKEY_CURRENT_USER;
  }
  else if (*(char*)RootKey=='3')
  {
    RootKey = HKEY_LOCAL_MACHINE;
  }
  else if (*(char*)RootKey=='4')
  {
    RootKey = HKEY_USERS;
  }


  if (0 == lua_isstring(L, 2)) {
    return 0;
  }

  lpSubKey = (char*)lua_tostring(L, 2);

  //把子项放入vecSubKeys，000001F4、000001F5、000003E9
  std::vector<std::string> vecSubKeys;
  if (!AisRegQueryRegular(RootKey, lpSubKey, "^[\\d]+", vecSubKeys))
  {
    return 0;
  }

  //遍历每个用户路径下的F值
  std::vector<std::string> vecFValue;
  for (std::vector<std::string>::iterator it = vecSubKeys.begin(); it != vecSubKeys.end(); it++)
  {
    std::string sSubKey = lpSubKey + std::string("\\") + (*it);
    //将AisRegQueryValue() 中的 data = szBuffer   -->  data = std::string(szBuffer, dwBuffLen); F值是二进制数据
    std::string sRes = AisRegQueryValue(RootKey, (char*)sSubKey.c_str(), "F");
    if (sRes == "error")
    {
      goto END_FLAG;
    }

    for (std::vector<std::string>::iterator item = vecFValue.begin(); item != vecFValue.end(); item++)
    {
      if (sRes == (*item))
      {
        result = 1;
        goto END_FLAG;
      }
    }
    vecFValue.push_back(sRes);
  }
  result = 0;

END_FLAG:
  lua_pushinteger(L, result);
  return 1;
}

//获取系统所有用户名和是否被禁用
int GetALLUsersInfo(std::map<std::string, int>& mapUsersInfo)
{
  int iRet = 0;
  LPUSER_INFO_1 pBuf = NULL;
  LPUSER_INFO_1 pTmpBuf;
  DWORD dwLevel = 1;
  DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
  DWORD dwEntriesRead = 0;
  DWORD dwTotalEntries = 0;
  DWORD dwResumeHandle = 0;
  NET_API_STATUS nStatus;
  LPTSTR pszServerName = NULL;

  nStatus = NetUserEnum(pszServerName,dwLevel,FILTER_NORMAL_ACCOUNT, 
    (LPBYTE*)&pBuf,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,&dwResumeHandle);
  if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
  {
    if ((pTmpBuf = pBuf) != NULL)
    {
      DWORD i = 0;
      while (i < dwEntriesRead )
      {
        if (pTmpBuf == NULL)
        {
          break;
        }

        int iDisable = 0;
        if ((pTmpBuf->usri1_flags & UF_ACCOUNTDISABLE))
        {
          iDisable = 1;
        }

        int iTextLen = WideCharToMultiByte(CP_UTF8, 0, pTmpBuf->usri1_name, -1, NULL, 0, NULL, NULL);
        char* pElementText = new char[iTextLen + 1];
        memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
        ::WideCharToMultiByte(CP_UTF8, 0, pTmpBuf->usri1_name, -1, pElementText, iTextLen, NULL, NULL);

        mapUsersInfo.insert(std::pair<std::string, int>(pElementText, iDisable));

        delete[] pElementText;
        pTmpBuf++;

        if (++i == dwEntriesRead)
        {
          iRet = 1;
        }
      }

    }
  }

  if (pBuf != NULL)
  {
    NetApiBufferFree(pBuf);
  }
  return iRet;
}

//是否有$结尾的用户
//result：-1没有获取到用户，0没有$结尾的用户，1有$结尾的用户
int FunGetShareAccount(lua_State *L)
{

  int result = -1;
  std::map<std::string, int> mapUsersInfo;
  //获取所有用户名
  if (!GetALLUsersInfo(mapUsersInfo))
  {
    return 0;
  }

  for (std::map<std::string, int>::iterator it=mapUsersInfo.begin(); it!=mapUsersInfo.end();it++ )
  {
    std::string sUserName = it->first;
    if (!sUserName.empty())
    {
      if ('$' == sUserName.at(sUserName.length()-1))
      {
        result = 1;
        break;
      }
    }
    result = 0;
  }

  lua_pushinteger(L, result);

  return 1;
}


//是否存在被禁用的非Guest用户
//result：  -1执行出错，0不存在禁用且非Guest账户，1存在禁用且非Guest账户
int FunGetAccountDisableAndExceptGuest(lua_State *L)
{

  int result = -1;
  std::map<std::string, int> mapUsersInfo;
  //获取所有用户名
  if (!GetALLUsersInfo(mapUsersInfo))
  {
    return 0;
  }

  for (std::map<std::string, int>::iterator it=mapUsersInfo.begin(); it!=mapUsersInfo.end();it++ )
  {
    std::string sUserName = it->first;
    int iDisablle = it->second;
    if (iDisablle && _stricmp(sUserName.c_str(), "Guest"))
    {
      result = 1;
      break;
    }
    result = 0;
  }

  lua_pushinteger(L, result);

  return 1;
}


int FunGetTcpTable(lua_State *L)
{
    std::string port = GetTcpIpv4Port();
    port += GetTcpIpv6Port();
    port += GetUdpIpv4Port();
    port += GetUdpIpv6Port();
    lua_pushstring(L, port.c_str());

  return 1;
}


std::string WcharToString(const wchar_t* src)
{
    // wide char to multi char
    int iTextLen = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
    if (iTextLen + 1 >= MAX_LEN_1024*2){
        printf("WcharToString malloc a large buffer.");
    }
    char* pElementText = new char[iTextLen + 1];
    memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
    ::WideCharToMultiByte(CP_UTF8, 0, src, -1, pElementText, iTextLen, NULL, NULL);
    std::string strText(pElementText);
    delete[] pElementText;
    return strText;
}

std::string byteToHexStr(unsigned char* byte_arr, int arr_len)
{
    std::string hexstr;
    for (int i = 0; 0 != byte_arr && i < arr_len; ++i)
    {
        char hex1;
        char hex2;

        /*借助C++支持的unsigned和int的强制转换，把unsigned char赋值给int的值，那么系统就会自动完成强制转换*/
        int value = byte_arr[i];
        int S = value / 16;
        int Y = value % 16;

        //将C++中unsigned char和int的强制转换得到的商转成字母
        if (S >= 0 && S <= 9)
            hex1 = (char)(48 + S);
        else
            hex1 = (char)(55 + S);

        //将C++中unsigned char和int的强制转换得到的余数转成字母
        if (Y >= 0 && Y <= 9)
            hex2 = (char)(48 + Y);
        else
            hex2 = (char)(55 + Y);

        //最后一步的代码实现，将所得到的两个字母连接成字符串达到目的
        hexstr = hexstr + hex1 + hex2;
    }
    return hexstr;
}


std::string AisGetGPOInRegistryFileStr(const char* pKey, const char* pValue)
{

    std::string sRegistryFilePath = cmdPopen("cmd /c echo %systemroot%\\System32\\GroupPolicy\\Machine\\Registry.pol");
    sRegistryFilePath.erase(sRegistryFilePath.find_last_not_of("\n") + 1);
    if (_access(sRegistryFilePath.c_str(), 0) != 0)
    {
        return "";
    }

    std::ifstream fin;
    fin.open(sRegistryFilePath.c_str(), std::ios::binary);
    if(!fin.is_open())
    {
        return "-1";
    }

    size_t index = 2;
    std::wstring wsLine;
    std::string sLine,sType,sKey,sValue;
    DWORD dwType;
    bool flag = false;
    int indexSemicolon = 0;
    wchar_t wch;

    //解析每一个策略[key;value;type;size;data]
    while (!fin.eof())
    {
        if (!flag)
        {
            fin.seekg(index, std::ios::beg);
            fin.read((char *)(&wch), 2);

            if (wch == 0x005B)// 判断'['符
            {
                flag = true;
            }
            index += 2;
            continue;
        }

        fin.seekg(index, std::ios::beg);
        fin.read((char *)(&wch), 2);
        if (wch == 0x005D) // 判断']'符
        {
            indexSemicolon = 0;
            wsLine.clear();
            flag = false;

        }else if(wch == 0x003B)  // 判断分号';'
        {
            switch (indexSemicolon++)
            {
            case 0:
                {
                    sLine = WcharToString(wsLine.c_str());
                    wsLine.clear();
                    sKey = sLine;
                }
                break;
            case 1:
                {
                    sLine = WcharToString(wsLine.c_str());
                    wsLine.clear();
                    sValue = sLine;
                }
                break;
            case 2:
                {
                    sLine = WcharToString(wsLine.c_str()).c_str();
                    sType = byteToHexStr((unsigned char *)sLine.c_str(), (int)sLine.size());
                    if (sType.size() > 0)
                    {
                        switch (std::stoi(sType, 0, 16))
                        {
                        case REG_SZ:
                            dwType = 1;
                            break;
                        case REG_DWORD:
                            dwType = 4;
                            break;
                        case REG_QWORD:
                            dwType = 11;
                            break;
                        default:
                            dwType = 0;
                            break;
                        }
                    }
                }
                break;
            case 3:
                {
                    int iDataLen = 0;
                    std::string sData, sSize;
                    sLine = WcharToString(wsLine.c_str()).c_str();
                    sSize = byteToHexStr((unsigned char *)sLine.c_str(),(int)sLine.size());

                    if (sSize.size() > 0)
                    {
                        //跳过分号;
                        index += 2;
                        fin.seekg(index, std::ios::beg);

                        iDataLen = std::stoi(sSize, 0, 16);
                        wchar_t wszData[MAX_PATH] = {0};
                        fin.read((char *)wszData, iDataLen);
                        sLine = WcharToString(wszData).c_str();
                        switch (dwType)
                        {
                        case REG_DWORD:
                        case REG_QWORD:
                            {
                                sData = byteToHexStr((unsigned char *)sLine.c_str(),(int)sLine.size());
                                if (sData.empty())
                                {
                                    sData = "00";
                                }
                                sData = std::to_string(std::stoull(sData, 0, 16));
                            }
                            break;
                        default:
                            sData = sLine;
                            break;
                        }
                    }
                    if (!_stricmp(pKey, sKey.c_str()) && !_stricmp(pValue, sValue.c_str()))
                    {
                        fin.close();
                        return sData;
                    }
                }
                break;
            default:
                break;
            }
        }else
        {
            wsLine.append(1, wch);
        }
        index += 2;
    }

    fin.close();
    return "";
}

int FunGetGPOInRegistryFileStr(lua_State *L)
{
    char* pKey = NULL;
    char* pValue = NULL;

    int iParaCount = lua_gettop(L);
    if (iParaCount != 2){
        return 0;
    }

    if (0 == lua_isstring(L, 1)) {
        return 0;
    }
    pKey = (char*)lua_tostring(L, 1);

    if (0 == lua_isstring(L, 2)) {
        return 0;
    }
    pValue = (char*)lua_tostring(L, 2);

    std::string result = AisGetGPOInRegistryFileStr(pKey, pValue);
    lua_pushstring(L, (const char*)result.c_str());

    return 1;
}


//获取文件/目录的用户/组名和对应的权限，读、写、执行 --> 4、2、1, （5读执行，7读写执行）
//用户名和权限信息放入map集合中
int FileAccountAccesstList(const char* pPath, std::map<std::string, int>& mapAccountAccess)
{
    if (_access(pPath,0) != 0)
    {
        return 0;
    }
    
    DWORD dwSize = 0;
    int iRetCode = 1;
    PSECURITY_DESCRIPTOR psd = NULL;  
    SECURITY_INFORMATION si = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;  
    // 获取文件权限信息结构体大小  
    BOOL bRet = GetFileSecurityA( pPath, si, psd, 0, &dwSize );  
    if ( bRet || GetLastError() != ERROR_INSUFFICIENT_BUFFER )  
    {  
        return 0;  
    }  

    char* pBuf = new char[dwSize]; 
    ZeroMemory( pBuf, dwSize );
    psd = (PSECURITY_DESCRIPTOR)pBuf;  

    // 获取文件权限信息结构体
    bRet = GetFileSecurityA(pPath, si, psd, dwSize, &dwSize );  
    if ( !bRet )  
    {  
        iRetCode = 0;
        goto END_FALG;  
    }

    //获取文件DACL
    BOOL DaclPresent; //是否存在DACL
    PACL pDACL = NULL;
    BOOL DaclDefaulted;  
    if (!GetSecurityDescriptorDacl(psd, &DaclPresent, &pDACL, &DaclDefaulted)) {

        iRetCode = 0;
        goto END_FALG; 
    }

    // 获取ACE个数，ACE代表此文件中，哪些用户拥有哪些权限
    ACL_SIZE_INFORMATION AclInfo;
    AclInfo.AceCount = 0; 
    AclInfo.AclBytesFree = 0;
    AclInfo.AclBytesInUse = sizeof(ACL);

    if (pDACL == NULL)
    {
        iRetCode = 0;
        goto END_FALG; 
    }

    if (!GetAclInformation(pDACL, &AclInfo,sizeof(ACL_SIZE_INFORMATION), AclSizeInformation)) {
        iRetCode = 0;
        goto END_FALG; 
    }

    UINT uiAceIndex = 0; 
    //循环遍历DACL中的ACE
    for (uiAceIndex = 0;uiAceIndex < AclInfo.AceCount; uiAceIndex++)
    {
        LPVOID pAce;
        if (!GetAce(pDACL, uiAceIndex, &pAce))
        {
            iRetCode = 0;
            goto END_FALG; 
        }
        PACE_HEADER pAceHeader = (PACE_HEADER)pAce;
        if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {

            PACCESS_ALLOWED_ACE pAceHdr = (PACCESS_ALLOWED_ACE)pAceHeader;
            char name[MAX_PATH];
            char domainName[MAX_PATH];
            DWORD dwNamelen = MAX_PATH;
            DWORD dwDomainNamelen = MAX_PATH;
            SID_NAME_USE nameUse;

            //通过用户或组的SID，获取其账户名称
            PSID pSid = (PSID)&(pAceHdr->SidStart);
            ACCESS_MASK mask = pAceHdr->Mask;

            //权限, 读、写、执行 --> 4、2、1
            int iAccess = 0;
            if ((mask & FILE_READ_DATA))
            {
                iAccess += 4;
            }
            if ((mask & FILE_WRITE_DATA))
            {
                iAccess += 2;
            }
            if (mask & FILE_EXECUTE)
            {
                iAccess += 1;
            }

            if(!LookupAccountSidA(NULL,pSid,name,&dwNamelen,domainName,&dwDomainNamelen,&nameUse))
            {
                iRetCode = 0;
                goto END_FALG; 
            }

            //有些目录的ACE有重复，重复的起占位作用? 其中无权限信息
            if (mapAccountAccess.count(name) > 0 && mapAccountAccess[name] != 0)
            {
                continue;

            }else
            {
                mapAccountAccess[name] = iAccess;
            }
        }
    }

END_FALG:
    if (pBuf)
    {
        delete []pBuf;
    }
    return iRetCode;
}


int FunGetPathAccountsPrivilege(lua_State *L)
{
    int result = 0;
    char* pFilePath = NULL;
    char* pAccount = NULL;

    int iParaCount = lua_gettop(L);
    if (iParaCount != 2){
        return 0;
    }

    if (0 == lua_isstring(L, 1)) {
        return 0;
    }

    pFilePath = (char*)lua_tostring(L, 1);

    if (0 == lua_isstring(L, 2)) {
        return 0;
    }

    pAccount = (char*)lua_tostring(L, 2);

    std::map<std::string, int> mapAccountAccess;
    if (!FileAccountAccesstList(pFilePath, mapAccountAccess))
    {
        return 0;
    }

    for (std::map<std::string, int>::iterator it = mapAccountAccess.begin(); it != mapAccountAccess.end(); it++)
    {
        if (!_stricmp(pAccount, it->first.c_str()))
        {
            result = it->second;
        }
    }
    lua_pushinteger(L, result);

    return 1;
}


//输入：目录或文件路径
//result: 把目录文件的所有用户串成一个字符串 --> Administrators;Authenticated Users;Guests;SYSTEM;Users
int FunGetPathUsers(lua_State *L)
{
    int iParaCount = lua_gettop(L);
    if (iParaCount != 1){
        return 0;
    }

    if (0 == lua_isstring(L, 1)) {
        return 0;
    }

    char* pPath = (char*)lua_tostring(L, 1);
    if (pPath == NULL)
    {
        return 0;
    }

    std::string sPath = std::string("cmd /c echo ") + pPath;
    sPath = cmdPopen((char*)sPath.c_str());
    sPath.erase(sPath.find_last_not_of("\n") + 1);

    if (_access(sPath.c_str(), 0) != 0)
    {
        return 0;
    }

    std::map<std::string, int> mapAccountAccess;
    if (!FileAccountAccesstList(sPath.c_str(), mapAccountAccess))
    {
        return 0;
    }

    std::string result;
    for (std::map<std::string, int>::iterator it = mapAccountAccess.begin(); it != mapAccountAccess.end(); it++)
    {
        result = result + it->first + ";";
    }
    if (!result.empty())
    {
        result.erase(result.length() - 1);
    }

    lua_pushstring(L, (const char*)result.c_str());
    return 1;
}

//获得所有用户的权限信息
int GetAllUserInfo1Priv(std::map<std::string,DWORD>& mapUsers)
{
    int iRet = 0;
    LPUSER_INFO_1 pBuf = NULL;
    LPUSER_INFO_1 pTmpBuf;
    DWORD dwLevel = 1;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    DWORD dwResumeHandle = 0;
    NET_API_STATUS nStatus;
    LPTSTR pszServerName = NULL;
    mapUsers.clear();

    nStatus = NetUserEnum(pszServerName,dwLevel,FILTER_NORMAL_ACCOUNT, 
        (LPBYTE*)&pBuf,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,&dwResumeHandle);
    if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
    {
        if ((pTmpBuf = pBuf) != NULL)
        {
            DWORD i = 0;
            while (i < dwEntriesRead )
            {
                if (pTmpBuf == NULL)
                {
                    break;
                }

                int iTextLen = WideCharToMultiByte(CP_UTF8, 0, pTmpBuf->usri1_name, -1, NULL, 0, NULL, NULL);
                char* pElementText =(char*)malloc(iTextLen + 1);
                if (pElementText == NULL)
                {
                    break;
                }
                memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
                ::WideCharToMultiByte(CP_UTF8, 0, pTmpBuf->usri1_name, -1, pElementText, iTextLen, NULL, NULL);
                mapUsers.insert(std::map<std::string, DWORD>::value_type(pElementText, pTmpBuf->usri1_priv));
                if (pElementText != NULL)
                {
                    free(pElementText);
                    pElementText = NULL;
                }
                pTmpBuf++;

                if (++i == dwEntriesRead)
                {
                    iRet = 1;
                }
            }
        }
    }

    if (pBuf != NULL)
    {
        NetApiBufferFree(pBuf);
    }
    return iRet;
}

//获得具有admin权限的用户，字符串格式逗号分割，示例：user1,user2
int FunGetAdminUsers(lua_State *L)
{
    std::map<std::string,DWORD> mapUsers;
    if (!GetAllUserInfo1Priv(mapUsers))
    {
        return 0;
    }
    std::string strUsers;
    for (std::map<std::string,DWORD>::const_iterator it = mapUsers.begin();
        it != mapUsers.end(); ++it)
    {
        if (it->second != USER_PRIV_ADMIN)
        {
            continue;
        }

        if (!strUsers.empty())
        {
            strUsers += ",";
        }
        strUsers += it->first;
    }

    lua_pushstring(L, (const char*)strUsers.c_str());
    return 1;
}


// 通过进程ID获取所启动进程的用户名
int FunGetUserNameByProcessId(lua_State* L)
{
    DWORD dwProcessId = 0;

    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("FunGetUserNameByProcessId paramCount not equal 1");
        return 0;
    }
    if (lua_isnumber(L, 1) == 0)
    {
        LOG_ERROR("FunGetUserNameByProcessId paramType is not number");
        return 0;
    }
    dwProcessId = (DWORD)lua_tonumber(L, 1);

    wchar_t szUserName[1024] = { 0 };
    char charUserName[2048] = { 0 };
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwProcessId);
    HANDLE hToken;
    if (hProcess == NULL){
        LOG_ERROR("OpenPrcess is failed");
        return 0;
    }

    BOOL bTokenOK = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    if (!bTokenOK){
        LOG_ERROR("OpenPrcessToken is failed");
        CloseHandle(hProcess);
        return 0;
    }

    DWORD dwSize = 0;
    BOOL bGetTokenOK = GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (!bGetTokenOK){
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            LOG_ERROR("GetTokenInformation is failed");
            CloseHandle(hToken);
            CloseHandle(hProcess);
            return 0;
        }
    }

    PTOKEN_USER  pTokenUser = (PTOKEN_USER)new BYTE[dwSize];
    bGetTokenOK = GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize);
    if (!bGetTokenOK){
        LOG_ERROR("GetTokenInformation is failed");
        if (pTokenUser)
            delete[] pTokenUser;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 0;
    }
    
    BOOL bLookupSid;
    SID_NAME_USE snu;
    int nLen = sizeof(szUserName) / sizeof(WCHAR);
    DWORD dwUserSize = sizeof(szUserName) / sizeof(WCHAR);
    WCHAR szDomain[1024] = {0};
    DWORD cbDomain = sizeof(szDomain) / sizeof(TCHAR);
    bLookupSid = LookupAccountSid(NULL, pTokenUser->User.Sid, szUserName, &dwUserSize, 
        szDomain, &cbDomain, &snu);
    if (!bLookupSid)
    {
        LOG_ERROR("LookupAccountSid is failed");
        if (pTokenUser)
            delete[] pTokenUser;
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 0;
    }

    std::string userName = WcharToString(szUserName);
    lua_pushstring(L, userName.c_str());

    if (pTokenUser)
        delete[] pTokenUser;
    CloseHandle(hToken);
    CloseHandle(hProcess);

    return 1;
}


int InitWmi(HRESULT& hres, IWbemLocator** pLoc, IWbemServices** pSvc)
{

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        LOG_ERROR("CoInitializeEx is failed");
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
        LOG_ERROR("CoInitializeSecurity is failed");
        CoUninitialize();
        return -1;  // Program has failed.
    }

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&(*pLoc));

    if (FAILED(hres)) {
        LOG_ERROR("CoCreateInstance is failed");
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
        LOG_ERROR("IWbemLocator.ConnectServer() is failed");
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
        LOG_ERROR("CoSetProxyBlanket is failed");
        (*pSvc)->Release();
        (*pLoc)->Release();
        CoUninitialize();
        return -1;  // Program has failed.
    }

    return 0;
}

std::string GetWMIInfo(HRESULT hres, IWbemLocator* pLoc, IWbemServices* pSvc, const std::string& wql, const std::wstring& field, const std::string& dataType, bool flags=true)
{

    std::string info;
    IEnumWbemClassObject* pEnumerator = NULL;

    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wql.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
        LOG_ERROR("IWbemServices.ExecQuery() is failed");
        return "falied";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }
        if (FAILED(hr))
        {
            LOG_WARN("pEnumerator->Next failed, errorCode:%x", hr);
            if (pclsObj)
            {
                pclsObj->Release();
                pclsObj = NULL;
            }
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(field.c_str(), 0, &vtProp, 0, 0);
        if (FAILED(hr))
        {
            LOG_WARN("pclsObj->Get failed, errorCode:%x", hr);
            if (pclsObj)
            {
                pclsObj->Release();
                pclsObj = NULL;
            }
            break;
        }
        if (dataType == "string" && !(vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL))
        {
            if (vtProp.bstrVal != NULL)
            {
                std::string tempInfo = WcharToString(vtProp.bstrVal);
                if (flags)
                {
                    info.append(tempInfo).append("\r\n");
                }
                else
                {
                    info.append(tempInfo).append(",");
                }
            }

        }
        else if (dataType == "int" && !(vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL))
        {
            info = std::to_string(vtProp.intVal);
        }
        else if (dataType == "bool" && !(vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL))
        {
            if (vtProp.boolVal) {
                info = "true";
            }
            else {
                info = "false";
            }
        }
        VariantClear(&vtProp);
        pclsObj->Release();
        pclsObj = NULL;
    }

    if (pEnumerator)
    {
        pEnumerator->Release();
        pEnumerator = NULL;
    }

    return info;
}

int UnInitWmi(HRESULT& hres, IWbemLocator* pLoc, IWbemServices* pSvc)
{
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return 0;
}


// 通过WMI获取计算机信息; 传入WSQL,属性名,属性类型; 
int FunGetInfoByWMISql(lua_State* L) {
    const char* cStrSql;
    const wchar_t* cwProperty;
    const char* cDataType;

    int paramCount = lua_gettop(L);
    if (paramCount != 3) {
        LOG_ERROR("FunGetInfoByWMISql paramCount not equal 3");
        return 0;
    }

    if (lua_isstring(L, 1) == 0) {
        LOG_ERROR("FunGetInfoByWMISql paramType1 is not string");
        return 0;
    }
    cStrSql = lua_tostring(L, 1);

    if (lua_isstring(L, 2) == 0) {
        LOG_ERROR("FunGetInfoByWMISql paramType2 is not string");
        return 0;
    }
    const char* fieldTemp = lua_tostring(L, 2);
    DWORD fieldTempLen = (DWORD)strlen(fieldTemp);
    WCHAR* field = new WCHAR[fieldTempLen + 1];
    memset(field, 0, sizeof(WCHAR) * (fieldTempLen + 1));
    MultiByteToWideChar(CP_ACP, 0, fieldTemp, fieldTempLen, field, fieldTempLen + 1);
    cwProperty = field;

    if (lua_isstring(L, 3) == 0) {
        LOG_ERROR("FunGetInfoByWMISql paramType3 is not string");
        if (field)
            delete[] field;
        return 0;
    }
    cDataType = lua_tostring(L, 3);

    HRESULT hr;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    int count = 0;
    std::string data;

    while (InitWmi(hr, &pLoc, &pSvc) != 0) {
        if (count < 3) {
            count++;
            continue;
        }
        else {
            LOG_ERROR("InitWmi is failed");
            if (field)
                delete[] field;
            return 0;
        }
    }

    data = GetWMIInfo(hr, pLoc, pSvc, cStrSql, cwProperty, cDataType);
    if (data.empty()){
        LOG_INFO("GetWMIInfo returned data is NULL");
        //std::cout << "data in NULL" << std::endl;
    }

    UnInitWmi(hr, pLoc, pSvc);
    // 把结果压入虚拟栈中; 
    lua_pushstring(L, data.c_str());
    if (field)
        delete[] field;
    return 1;
}

// 获取现在domain的用户账号, 用户之间以“,”号分割
int FunGetDomainUserAccount(lua_State* L) {
    const char* cStrSql;
    const wchar_t* cwProperty;
    const char* cDataType;

    int paramCount = lua_gettop(L);
    if (paramCount != 3) {
        LOG_ERROR("FunGetDomainUserAccount paramCount not equal 3");
        return 0;
    }

    if (lua_isstring(L, 1) == 0) {
        LOG_ERROR("FunGetDomainUserAccount paramType1 is not string");
        return 0;
    }
    cStrSql = lua_tostring(L, 1);

    if (lua_isstring(L, 2) == 0) {
        LOG_ERROR("FunGetDomainUserAccount paramType2 is not string");
        return 0;
    }
    const char* fieldTemp = lua_tostring(L, 2);
    DWORD fieldTempLen = (DWORD)strlen(fieldTemp);
    WCHAR* field = new WCHAR[fieldTempLen + 1];
    memset(field, 0, sizeof(WCHAR) * (fieldTempLen + 1));
    MultiByteToWideChar(CP_ACP, 0, fieldTemp, fieldTempLen, field, fieldTempLen + 1);
    cwProperty = field;

    if (lua_isstring(L, 3) == 0) {
        LOG_ERROR("FunGetDomainUserAccount paramType3 is not string");
        if (field)
            delete[] field;
        return 0;
    }
    cDataType = lua_tostring(L, 3);

    HRESULT hr;
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    int count = 0;
    std::string data;

    while (InitWmi(hr, &pLoc, &pSvc) != 0) {
        if (count < 3) {
            count++;
            continue;
        }
        else {
            LOG_ERROR("InitWmi is failed");
            if (field)
                delete[] field;
            return 0;
        }
    }

    data = GetWMIInfo(hr, pLoc, pSvc, cStrSql, cwProperty, cDataType, false);
    if (data.empty()){
        LOG_INFO("GetWMIInfo returned data is NULL");
        //std::cout << "data in NULL" << std::endl;
    }
    size_t index01 = data.rfind(",");
    std::string res = data.substr(0, index01);

    UnInitWmi(hr, pLoc, pSvc);
    // 把结果压入虚拟栈中; 
    lua_pushstring(L, res.c_str());
    if (field)
        delete[] field;
    return 1;
}

bool FileQueryValue(const std::string& ValueName, const std::string& szModuleName, char* dataBuf, int dataBufLen)
{
    bool bSuccess = FALSE;
    BYTE* m_lpVersionData = NULL;
    DWORD   m_dwLangCharset = 0;

    do
    {
        if (!ValueName.size() || !szModuleName.size())
            break;

        DWORD dwHandle;
        // 判断系统能否检索到指定文件的版本信息
        DWORD dwDataSize = ::GetFileVersionInfoSizeA((LPCSTR)szModuleName.c_str(), &dwHandle);
        if (dwDataSize == 0)
        {
            LOG_ERROR("GetFileVersionInfoSizeA() failed");
            break;
        }

        m_lpVersionData = new (std::nothrow) BYTE[dwDataSize];// 分配缓冲区
        if (NULL == m_lpVersionData)
        {
            LOG_ERROR("m_lpVersionData new failed");
            break;
        }

        // 检索信息
        if (!::GetFileVersionInfoA((LPCSTR)szModuleName.c_str(), dwHandle, dwDataSize, (void*)m_lpVersionData))
        {
            LOG_ERROR("GetFileVersionInfoA() failed");
            break;
        }

        VS_FIXEDFILEINFO* pVsInfo = NULL;
        unsigned int fileInfoSize = sizeof(VS_FIXEDFILEINFO);
        if (::VerQueryValueA((LPCVOID)m_lpVersionData, "\\", (LPVOID*)&pVsInfo, &fileInfoSize))
        {
            sprintf_s(dataBuf, dataBufLen, "%d.%d.%d.%d", HIWORD(pVsInfo->dwFileVersionMS), LOWORD(pVsInfo->dwFileVersionMS), HIWORD(pVsInfo->dwFileVersionLS), LOWORD(pVsInfo->dwFileVersionLS));
            bSuccess = TRUE;
        }
    } while (FALSE);

    // 销毁缓冲区
    if (m_lpVersionData)
    {
        delete[] m_lpVersionData;
        m_lpVersionData = NULL;
    }

    return bSuccess;
}

int FunGetFileVersion(lua_State* L)
{
    std::string filePath;
    std::string data;
    char dataBuf[MAX_LEN_256] = {0};

    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("FunGetFileVersion paramCount not equal 1");
        return 0;
    }

    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("FunGetFileVersion paramType is not string");
        return 0;
    }
    filePath = lua_tostring(L, 1);
    LOG_INFO("FunGetVersion() filePath:%s\n", filePath.c_str());

    if (FileQueryValue("FileVersion",filePath, dataBuf, MAX_LEN_256)==FALSE)
    {
        LOG_ERROR("FileQueryValue() failed");
        return 0;
    }

    data = std::string(dataBuf);
    LOG_INFO("FunGetVersion() FileVersion:%s\n", data.c_str());
    lua_pushstring(L, data.c_str());
    return 1;
}

int FunGetHraConfigValue(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 2)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        return 0;
    }
    std::string strTable = lua_tostring(L, 1);
    
    if (lua_isstring(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 2);
        return 0;
    }
    std::string strKey = lua_tostring(L, 2);
    std::string strValue = g_ConfigSave.ConfigSaveGetValue(strTable, strKey);
    lua_pushstring(L, strValue.c_str());

    return 1;
}

int FunGetIniValue(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 3)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        return 0;
    }
    std::string strFilePath = lua_tostring(L, 1);

    if (lua_isstring(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 2);
        return 0;
    }
    std::string strSection = lua_tostring(L, 2);

    if (lua_isstring(L, 3) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 3);
        return 0;
    }
    std::string strKey = lua_tostring(L, 3);

    std::string strValue = UtilsGetIniValue(strFilePath, strSection, strKey);
    lua_pushstring(L, strValue.c_str());
    return 1;
}

/// <summary>
/// 获得已安装的软件列表
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetInstalledSoftware(lua_State* L)
{
    std::vector<BASELINE_SOFTWARE> vctSoftware;
    GetSoftWare(vctSoftware, HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GetSoftWare(vctSoftware, HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GetSoftWare(vctSoftware, HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GeRegUserWare(vctSoftware, HKEY_USERS);

    lua_newtable(L);
    int nIndex = 0;
    for (std::vector<BASELINE_SOFTWARE>::const_iterator it = vctSoftware.begin(); it != vctSoftware.end(); ++it)
    {
        ++nIndex;
        lua_newtable(L);
        lua_pushstring(L, "reg_full_path");
        lua_pushstring(L, it->szRegFullPath);
        lua_settable(L, -3);

        lua_pushstring(L, "vendor");
        lua_pushstring(L, it->szVendor);
        lua_settable(L, -3);

        lua_pushstring(L, "soft_name");
        lua_pushstring(L, it->szSoftName);
        lua_settable(L, -3);

        lua_pushstring(L, "version");
        lua_pushstring(L, it->szSoftVersion);
        lua_settable(L, -3);

        lua_pushstring(L, "install_location");
        lua_pushstring(L, it->szInstallLocation);
        lua_settable(L, -3);

        lua_pushstring(L, "install_time");
        lua_pushstring(L, it->szInstallTime);
        lua_settable(L, -3);

        //lua_pushstring(L, "size");
        //lua_pushinteger(L, it->nSize);
        //lua_settable(L, -3);

        lua_pushinteger(L, nIndex);
        lua_insert(L, -2);
        lua_settable(L, -3);
    }

    //std::string strValue = "{";
    //for (std::map<std::string, BASELINE_SOFTWARE>::const_iterator it = mapSoftware.begin(); it != mapSoftware.end();
    //     ++it)
    //{
    //    ++nIndex;
    //    char szInfoTmp[1024 * 6];
    //    memset(szInfoTmp, 0, sizeof(szInfoTmp));
    //    _snprintf_s(
    //        szInfoTmp, sizeof(szInfoTmp),
    //        "[%d]={[\"vendor\"]=\"%s\",[\"soft_name\"]=\"%s\",[\"version\"]=\"%s\",[\"install_location\"]=\"%s\","
    //        "[\"install_time\"]=\"%s\",[\"size\"]=%u}",
    //        nIndex, it->second.szVendor, it->second.szSoftName, it->second.szSoftVersion,
    //        /*it->second.szInstallLocation*/ "", it->second.szInstallTime, it->second.nSize);

    //    if (it != mapSoftware.begin())
    //    {
    //        strValue += ",";
    //    }
    //    strValue += szInfoTmp;
    //}
    //strValue += "}";
    //lua_pushstring(L, strValue.c_str());
    return 1;
}

/// <summary>
/// 获得运行的进程列表
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetRunningProcess(lua_State* L)
{
    std::map<std::string, BASELINE_APPLICATION> mapApplication;
    GetApplicationInfo(mapApplication);

    lua_newtable(L);
    int nIndex = 0;
    for (std::map<std::string, BASELINE_APPLICATION>::const_iterator it = mapApplication.begin();
         it != mapApplication.end(); ++it)
    {
        ++nIndex;
        lua_newtable(L);
        lua_pushstring(L, "vendor");
        lua_pushstring(L, it->second.szVendor);
        lua_settable(L, -3);

        lua_pushstring(L, "application");
        lua_pushstring(L, it->second.szApplication);
        lua_settable(L, -3);

        lua_pushstring(L, "application_version");
        lua_pushstring(L, it->second.szApplicationVersion);
        lua_settable(L, -3);

        lua_pushstring(L, "file_name");
        lua_pushstring(L, it->second.szFileName);
        lua_settable(L, -3);

        lua_pushstring(L, "file_version");
        lua_pushstring(L, it->second.szFileVersion);
        lua_settable(L, -3);

        lua_pushstring(L, "path");
        lua_pushstring(L, it->second.szPath);
        lua_settable(L, -3);

        std::string strSha1;
        char szFormatTmp[8];
        memset(szFormatTmp, 0, sizeof(szFormatTmp));
        for (int i = 0; i < sizeof(it->second.ucSha1) - 1; ++i)
        {
            _snprintf_s(szFormatTmp, sizeof(szFormatTmp), "%02x", it->second.ucSha1[i]);
            strSha1 += szFormatTmp;
        }
        lua_pushstring(L, "sha1");
        lua_pushstring(L, strSha1.c_str());
        lua_settable(L, -3);

        //lua_pushstring(L, "use_time");
        //lua_pushinteger(L, it->second.nUseTime);
        //lua_settable(L, -3);

        lua_pushinteger(L, nIndex);
        lua_insert(L, -2);
        lua_settable(L, -3);
    }

    return 1;
}

/// <summary>
/// 发送补丁数据请求
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunRequestKbData(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isnumber(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 1);
        return 0;
    }

    unsigned long long nSeq = (unsigned long long)lua_tonumber(L, 1);

    //先清理内存中数据，后发送请求
    HraKbDataMgr::getInstance().clear();
    CReportInfo cReportKbDataReq;
    int ret = cReportKbDataReq.KbRequest(nSeq);

    lua_pushinteger(L, ret);
    return 1;
}

/// <summary>
/// 查询内存中的补丁数据
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetKbData(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isnumber(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 1);
        return 0;
    }

    unsigned long long nSeq = (unsigned long long)lua_tonumber(L, 1);
    HraKbDataMgr::KbData data;
    bool bRet = HraKbDataMgr::getInstance().getData(data, nSeq);
    LOG_INFO("Get KB data, seq:%llu, ret:%s", nSeq, bRet ? "true" : "false");
    if (bRet)
    {
        lua_pushstring(L, data.strData.c_str());
    }
    else
    {
        lua_pushstring(L, "");
    }
    
    return 1;
}

/// <summary>
/// sleep函数，单位毫秒
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunSleep(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 1)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    if (lua_isnumber(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not number!", 1);
        return 0;
    }

    unsigned long nMillisecond = (unsigned long)lua_tonumber(L, 1);
    ::Sleep(nMillisecond);

    return 0;
}

/// <summary>
/// 获取控制命令
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunGetCtrlCmd(lua_State* L)
{
    int iCmd = HraCtrlCmd::getInstance()->getCmd(::GetCurrentThreadId());
    lua_pushinteger(L, iCmd);
    return 1;
}


/// <summary>
/// 当variant.vt为VT_ARRAY时,转换variant数据为 Lua_table
/// </summary>
/// <param name="L"> Lua虚拟栈 </param>
/// <param name="pSafeArray"> variant中的安全数组 </param>
/// <param name="varType"> 安全数组的类型 </param>
void FunConvertVariant(lua_State* L, SAFEARRAY* pSafeArray, VARENUM varType)
{
    int cDims      = pSafeArray->cDims; // 维度数
    long totalSize = 1;
    for (int i = 0; i < cDims; ++i)
    { // 计算一维数组大小
        totalSize *= pSafeArray->rgsabound[i].cElements;
    }

    void* pData = nullptr;
    HRESULT hr  = SafeArrayAccessData(pSafeArray, (void**)&pData);
    if (!SUCCEEDED(hr))
    {
        LOGW_WARN(L"SafeArrayAccessData failed,vt_array|type:%u, errorCode:%lu", varType, GetLastError());
        lua_pushnil(L);
        return;
    }

    lua_newtable(L);
    for (size_t i = 0; i < totalSize; i++)
    {
        lua_pushinteger(L, i + 1);
        // 以下没有处理  VT_CY | VT_DISPATCH | VT_ERROR | VT_VARIANT | VT_UNKNOWN | VT_DECIMAL | VT_RECORD
        switch (varType)
        {
        case VT_I1:
            lua_pushinteger(L, (signed char)((char*)(pData))[i]);
            break;
        case VT_I2:
            lua_pushinteger(L, ((short*)(pData))[i]);
            break;
        case VT_I4:
            lua_pushinteger(L, ((int32_t*)(pData))[i]);
            break;
        case VT_I8:
            lua_pushinteger(L, ((int64_t*)(pData))[i]); // 在安全数组中不会出现
            break;
        case VT_UI1:
            lua_pushinteger(L, ((unsigned char*)(pData))[i]);
            break;
        case VT_UI2:
            lua_pushinteger(L, ((unsigned short*)(pData))[i]);
            break;
        case VT_UI4:
            lua_pushinteger(L, ((uint32_t*)(pData))[i]);
            break;
        case VT_UI8:
            lua_pushinteger(L, ((uint64_t*)(pData))[i]); // 在安全数组中不会出现
            break;
        case VT_R4:
            lua_pushnumber(L, ((float*)(pData))[i]);
            break;
        case VT_R8:
            lua_pushnumber(L, ((double*)(pData))[i]);
            break;
        case VT_INT:
            lua_pushinteger(L, ((int*)(pData))[i]);
            break;
        case VT_UINT:
            lua_pushinteger(L, ((unsigned int*)(pData))[i]);
            break;
        case VT_DATE:
            lua_pushnumber(L, ((double*)(pData))[i]);
            break;
        case VT_BSTR:
            lua_pushstring(L, UtilsUnicodeToString(((BSTR*)(pData))[i], CP_ACP).c_str());
            break;
        case VT_BOOL:
            lua_pushboolean(L, ((VARIANT_BOOL*)(pData))[i]);
            break;
        // case VT_LPSTR:
        //    lua_pushstring(); // 在安全数组中不会出现
        //    break;
        // case VT_LPWSTR:
        //    lua_pushstring(); // 在安全数组中不会出现
        //    break;
        default:
            LOGW_WARN(L"FunConvertVariant Not support data type:%u", varType);
            lua_pushnil(L);
            break;
        }
        lua_settable(L, -3);
    }

    SafeArrayUnaccessData(pSafeArray);
    return;
}

/// <summary>
/// 执行WQL语句，获取数据
/// </summary>
/// <param name="L"></param>
/// <returns></returns>
int FunWqlExecQuery(lua_State* L)
{
    int paramCount = lua_gettop(L);
    if (paramCount != 3)
    {
        LOG_ERROR("paramCount:%d error!", paramCount);
        return 0;
    }

    // NameSpace
    if (lua_isstring(L, 1) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 1);
        return 0;
    }
    std::string strNameSpace = lua_tostring(L, 1);
    if (strNameSpace.empty())
    {
        LOG_ERROR("NameSpace empty!");
        return 0;
    }

    // WQL
    if (lua_isstring(L, 2) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 2);
        return 0;
    }
    std::string strWQL = lua_tostring(L, 2);
    if (strWQL.empty())
    {
        LOG_ERROR("WQL empty!");
        return 0;
    }

    // Field
    if (lua_isstring(L, 3) == 0)
    {
        LOG_ERROR("Param:%d is not string!", 3);
        return 0;
    }
    std::string strField = lua_tostring(L, 3);
    if (strField.empty())
    {
        LOG_ERROR("Field empty!");
        return 0;
    }

    std::set<std::wstring> setField;
    std::vector<std::string> vctField = UtilsStringSplit(strField, ",");
    for (std::vector<std::string>::const_iterator it = vctField.begin(); vctField.end() != it; ++it)
    {
        std::string strTmp = *it;
        UtilsTrim(strTmp);
        std::wstring wstrTmp = UtilsStringToUnicode(strTmp);
        if (setField.find(wstrTmp) != setField.end())
        {
            LOGW_ERROR(L"Repeat field:%s!", wstrTmp.c_str());
            return 0;
        }
        setField.insert(wstrTmp);
    }

    //查询
    WMICommInterface wql;
    if (!wql.Initialize(UtilsStringToUnicode(strNameSpace).c_str()))
    {
        LOGW_ERROR(L"WMI Initialize faild! msg:%s", wql.GetErrorMsg());
        return 0;
    }
    if (!wql.ExecQuery(UtilsStringToUnicode(strWQL).c_str()))
    {
        LOGW_ERROR(L"WMI ExecQuery error! msg:%s", wql.GetErrorMsg());
        return 0;
    }

    int nIndex = 0;
    std::map<int, std::map<std::wstring, _variant_t>> mapResultAll;
    std::map<std::wstring, _variant_t> mapResult;
    while (wql.GetNext(mapResult, setField) > 0)
    {
        ++nIndex;
        mapResultAll.insert(std::map<int, std::map<std::wstring, _variant_t>>::value_type(nIndex, mapResult));
    }
    if (mapResultAll.empty())
    {
        return 0;
    }

    lua_newtable(L);
    for (std::map<int, std::map<std::wstring, _variant_t>>::const_iterator itAll = mapResultAll.begin();
         itAll != mapResultAll.end(); ++itAll)
    {
        lua_newtable(L);
        for (std::map<std::wstring, _variant_t>::const_iterator itRet = itAll->second.begin();
             itAll->second.end() != itRet; ++itRet)
        {
            lua_pushstring(L, UtilsUnicodeToString(itRet->first, CP_ACP).c_str());
            // 目前variant不支持: VT_EMPTY|VT_NULL|VT_CY|VT_DISPATCH|VT_ERROR|VT_VARIANT|VT_UNKNOWN|VT_DECIMAL|VT_RECORD
            switch (itRet->second.vt)
            {
            case VT_I2:
                lua_pushinteger(L, itRet->second.iVal);
                break;
            case VT_I4:
                lua_pushinteger(L, itRet->second.intVal);
                break;
            case VT_R4:
                lua_pushnumber(L, itRet->second.fltVal);
                break;
            case VT_R8:
                lua_pushnumber(L, itRet->second.dblVal);
                break;
            case VT_DATE:
                lua_pushnumber(L, itRet->second.date);
                break;
            case VT_BSTR:
                lua_pushstring(L, UtilsUnicodeToString(itRet->second.bstrVal, CP_ACP).c_str());
                break;
            case VT_BOOL:
                lua_pushboolean(L, itRet->second.boolVal);
                break;
            case VT_I1:
                lua_pushinteger(L, itRet->second.cVal);
                break;
            case VT_UI1:
                lua_pushinteger(L, itRet->second.bVal);
                break;
            case VT_UI2:
                lua_pushinteger(L, itRet->second.uiVal);
                break;
            case VT_UI4:
                lua_pushinteger(L, itRet->second.ulVal);
                break;
            case VT_I8:
                lua_pushinteger(L, itRet->second.llVal);
                break;
            case VT_UI8:
                lua_pushinteger(L, itRet->second.ullVal);
                break;
            case VT_INT:
                lua_pushinteger(L, itRet->second.intVal);
                break;
            case VT_UINT:
                lua_pushinteger(L, itRet->second.uintVal);
                break;
            // case VT_LPSTR:
            //    lua_pushstring(L, itRet->second.pcVal);
            //    break;
            // case VT_LPWSTR:
            //    lua_pushstring(L, UtilsUnicodeToString(*(itRet->second.pbstrVal), CP_ACP).c_str());
            //    break;
            case VT_ARRAY | VT_I1: {
                FunConvertVariant(L, itRet->second.parray, VT_I1);
            }
            break;
            case VT_ARRAY | VT_I2: {
                FunConvertVariant(L, itRet->second.parray, VT_I2);
            }
            break;
            case VT_ARRAY | VT_I4: {
                FunConvertVariant(L, itRet->second.parray, VT_I4);
            }
            break;
            case VT_ARRAY | VT_I8: {
                FunConvertVariant(L, itRet->second.parray, VT_I8);
            }
            break;
            case VT_ARRAY | VT_UI1: {
                FunConvertVariant(L, itRet->second.parray, VT_UI1);
            }
            break;
            case VT_ARRAY | VT_UI2: {
                FunConvertVariant(L, itRet->second.parray, VT_UI2);
            }
            break;
            case VT_ARRAY | VT_UI4: {
                FunConvertVariant(L, itRet->second.parray, VT_UI4);
            }
            break;
            case VT_ARRAY | VT_UI8: {
                FunConvertVariant(L, itRet->second.parray, VT_UI8);
            }
            break;
            case VT_ARRAY | VT_R4: {
                FunConvertVariant(L, itRet->second.parray, VT_R4);
            }
            break;
            case VT_ARRAY | VT_R8: {
                FunConvertVariant(L, itRet->second.parray, VT_R8);
            }
            break;
            case VT_ARRAY | VT_INT: {
                FunConvertVariant(L, itRet->second.parray, VT_INT);
            }
            break;
            case VT_ARRAY | VT_UINT: {
                FunConvertVariant(L, itRet->second.parray, VT_UINT);
            }
            break;
            case VT_ARRAY | VT_DATE: {
                FunConvertVariant(L, itRet->second.parray, VT_DATE);
            }
            break;
            case VT_ARRAY | VT_BSTR: {
                FunConvertVariant(L, itRet->second.parray, VT_BSTR);
            }
            break;
            case VT_ARRAY | VT_BOOL: {
                FunConvertVariant(L, itRet->second.parray, VT_BOOL);
            }
            break;
            // case VT_ARRAY | VT_LPSTR: {
            //    FunConvertVariant(L, itRet->second.parray, VT_LPSTR);
            //}
            // break;
            // case VT_ARRAY | VT_LPWSTR: {
            //    FunConvertVariant(L, itRet->second.parray, VT_LPWSTR);
            //}
            // break;
            default:
                LOGW_WARN(L"Not support data type:%u", itRet->second.vt);
                lua_pushnil(L);
            }
            lua_settable(L, -3);
        }

        //加入一条数据
        lua_pushinteger(L, itAll->first);
        lua_insert(L, -2);
        lua_settable(L, -3);
    }

    return 1;
}