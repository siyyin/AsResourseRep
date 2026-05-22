#include "DIAssetPort.h"
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <Psapi.h>
#include "LogManager.h"
#include "StringUtils.h"
#include "DIUtils.h"

#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib,"psapi.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))
#define BUFFER_READ_SIZE 0x40000
#define MAX_LEN_256         256

extern BOOL g_IsWinXP;

namespace di_rest_client
{
DIAssetPort::DIAssetPort(void)
{
}


DIAssetPort::~DIAssetPort(void)
{
	m_map_tcp_table.clear();
	m_map_udp_table.clear();
	m_map_all_table.clear();
}

int inet_pton(int af, const wchar_t *src, void *dst)
{
  struct sockaddr_storage ss;
  int size = sizeof(ss);
  wchar_t src_copy[INET6_ADDRSTRLEN+1];

  ZeroMemory(&ss, sizeof(ss));
  /* stupid non-const API */
  wcsncpy_s(src_copy, src, INET6_ADDRSTRLEN+1);
  src_copy[INET6_ADDRSTRLEN] = 0;

  if (WSAStringToAddress(src_copy, af, NULL, (struct sockaddr *)&ss, &size) == 0) {
    switch(af) {
      case AF_INET:
    *(struct in_addr *)dst = ((struct sockaddr_in *)&ss)->sin_addr;
    return 1;
      case AF_INET6:
    *(struct in6_addr *)dst = ((struct sockaddr_in6 *)&ss)->sin6_addr;
    return 1;
    }
  }
  return 0;
}

const wchar_t * inet_ntop(int af, const void *src, wchar_t *dst, socklen_t size)
{
  struct sockaddr_storage ss;
  unsigned long s = size;

  ZeroMemory(&ss, sizeof(ss));
  ss.ss_family = af;

  switch(af) {
    case AF_INET:
      ((struct sockaddr_in *)&ss)->sin_addr = *(struct in_addr *)src;
      break;
    case AF_INET6:
      ((struct sockaddr_in6 *)&ss)->sin6_addr = *(struct in6_addr *)src;
      break;
    default:
      return NULL;
  }
  /* cannot direclty use &size because of strict aliasing rules */
  return (WSAAddressToString((struct sockaddr *)&ss, sizeof(ss), NULL, dst, &s) == 0)?
          dst : NULL;
}

bool DIAssetPort::InitDIAssetPort(void)
{
	m_map_tcp_table.clear();
	m_map_udp_table.clear();
	m_map_all_table.clear();

	bool bRet = false;
	if (get_tcp_table_msg() && get_udp_table_msg()){
		if (!g_IsWinXP){
			get_tcp_table_msg_ex();
			get_udp_table_msg_ex();
		}
		m_map_all_table.insert(m_map_tcp_table.begin(), m_map_tcp_table.end());
		m_map_all_table.insert(m_map_udp_table.begin(), m_map_udp_table.end());
		bRet = true;
	}

	return bRet;
}

std::map<std::string, DIAssetPortItem>& DIAssetPort::GetTcpPortList(void)
{
	return m_map_tcp_table;
}

std::map<std::string, DIAssetPortItem>& DIAssetPort::GetUdpPortList(void)
{
	return m_map_udp_table;
}

std::map<std::string, DIAssetPortItem>& DIAssetPort::GetAllPortList(void)
{
	return m_map_all_table;
}

bool DIAssetPort::get_tcp_table_msg()
{
	DWORD dwRetVal = 0;
	
	// 获取合适大小的buffer
	PMIB_TCPTABLE_OWNER_PID pTcpTable = (MIB_TCPTABLE_OWNER_PID *) MALLOC(sizeof (MIB_TCPTABLE_OWNER_PID));
	if (pTcpTable == NULL) {
		DI_LOG_ERROR("DIAssetPort::get_tcp_table_msg: Error allocating memory\n");
		return false;
	}

	DWORD dwSize = sizeof (MIB_TCPTABLE_OWNER_PID);
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE_OWNER_PID *) MALLOC(dwSize);
		if (pTcpTable == NULL) {
			DI_LOG_ERROR("DIAssetPort::get_tcp_table_msg: Error allocating memory\n");
			return false;
		}
	}

	// 获取TCPTable
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
		int nNum = (int) pTcpTable->dwNumEntries;
		for (int i = 0; i < nNum; i++) {
      // 只采集监听状态的端口
      if (pTcpTable->table[i].dwState != MIB_TCP_STATE_LISTEN)
        continue;

			DIAssetPortItem tcp_item;
			tcp_item.m_strPort = ansi_to_utf8("--");
			tcp_item.m_strProtocol = ansi_to_utf8("--");
			tcp_item.m_strBindIP = ansi_to_utf8("--");
			tcp_item.m_strProcessName = ansi_to_utf8("--");
			tcp_item.m_strProcessPath = ansi_to_utf8("--");
			tcp_item.m_strUser = ansi_to_utf8("--");
			tcp_item.m_strSHA1 = ansi_to_utf8("");   // zhangqiang request
			tcp_item.m_strStartTime = ansi_to_utf8("--");
			tcp_item.m_strRemoteAddr = ansi_to_utf8("--");
			tcp_item.m_strRemotePort = ansi_to_utf8("--");
			tcp_item.m_strState = ansi_to_utf8("--");
			tcp_item.m_strPid = ansi_to_utf8("--");

			tcp_item.m_strProtocol = ansi_to_utf8("TCP");    // 协议

			in_addr inAddrLocal, inAddrRemote;
			memcpy(&inAddrLocal, &(pTcpTable->table[i].dwLocalAddr), sizeof(DWORD));
			memcpy(&inAddrRemote, &(pTcpTable->table[i].dwRemoteAddr), sizeof(DWORD));
			std::string strTmp;
			strTmp = ansi_to_utf8(inet_ntoa(inAddrLocal));        // 监听IP
			if (!strTmp.empty())
				tcp_item.m_strBindIP = strTmp;

			strTmp = ansi_to_utf8(inet_ntoa(inAddrRemote));   // 远端地址
			if (!strTmp.empty())
				tcp_item.m_strRemoteAddr = strTmp;

			strTmp = ansi_to_utf8(std::to_string(ntohs((u_short)pTcpTable->table[i].dwLocalPort)).data());          // 端口号
			if (!strTmp.empty())
				tcp_item.m_strPort = strTmp;

			strTmp = ansi_to_utf8(std::to_string(ntohs((u_short)pTcpTable->table[i].dwRemotePort)).data());    // 远端端口
			if (!strTmp.empty())
				tcp_item.m_strRemotePort = strTmp;

			switch (pTcpTable->table[i].dwState) {               // 监听状态
			case MIB_TCP_STATE_CLOSED:
				tcp_item.m_strState = ansi_to_utf8("CLOSED");
				break;
			case MIB_TCP_STATE_LISTEN:
				tcp_item.m_strState = ansi_to_utf8("LISTENING");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				tcp_item.m_strState = ansi_to_utf8("SYN-SENT");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				tcp_item.m_strState = ansi_to_utf8("SYN-RECEIVED");
				break;
			case MIB_TCP_STATE_ESTAB:
				tcp_item.m_strState = ansi_to_utf8("ESTABLISHED");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				tcp_item.m_strState = ansi_to_utf8("FIN-WAIT-1");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				tcp_item.m_strState = ansi_to_utf8("FIN-WAIT-2");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				tcp_item.m_strState = ansi_to_utf8("CLOSE-WAIT");
				break;
			case MIB_TCP_STATE_CLOSING:
				tcp_item.m_strState = ansi_to_utf8("CLOSING");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				tcp_item.m_strState = ansi_to_utf8("LAST-ACK");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				tcp_item.m_strState = ansi_to_utf8("TIME-WAIT");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				tcp_item.m_strState = ansi_to_utf8("DELETE-TCB");
				break;
			default:
				break;
			}

			// 进程ID
			std::string strPid = ansi_to_utf8(std::to_string(pTcpTable->table[i].dwOwningPid).data());
			if (!strPid.empty())
				tcp_item.m_strPid = strPid;

			wchar_t wszFilePath[MAX_PATH] = {0};
			if (!GetProcessFullPath(pTcpTable->table[i].dwOwningPid, wszFilePath)){
				wcsncpy_s(wszFilePath, MAX_PATH, L"UNKNOWN", 7);
			}

      TCHAR achLongPath[MAX_PATH] = { 0 };
      ::GetLongPathName(wszFilePath, achLongPath, sizeof(achLongPath)/sizeof(TCHAR) ); 
      strTmp = UnicodeToUtf8String(achLongPath);
      if (!strTmp.empty()){
        tcp_item.m_strProcessPath = strTmp;        // 获取二进制路径
      }

			if (!_stricmp(tcp_item.m_strProcessPath.data(), "system")){
				tcp_item.m_strUser = ansi_to_utf8("SYSTEM");
			}

			if ((!tcp_item.m_strProcessPath.empty()) && tcp_item.m_strProcessPath.find("\\") != std::string::npos){

				// 进程名
				strTmp = tcp_item.m_strProcessPath.substr(tcp_item.m_strProcessPath.rfind("\\")+1);
				if (!strTmp.empty())
					tcp_item.m_strProcessName = strTmp;

				// 运行用户
				std::wstring strRunUser;
				if (ExtractProcessOwner(pTcpTable->table[i].dwOwningPid, strRunUser)){
					if (!strRunUser.empty())
						tcp_item.m_strUser = UnicodeToUtf8String(strRunUser);
				}

				// 进程SHA1
				byte sha1Buf[20] = {0};
				char sha1Str[MAX_LEN_256] = {0};
				DWORD dwBufSize = sizeof(sha1Buf);
				if (CalcFileSha1Entity(tcp_item.m_strProcessPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
					ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
					strTmp = ansi_to_utf8(sha1Str);
					if (!strTmp.empty())
						tcp_item.m_strSHA1 = strTmp;
				}

				// 启动时间
				strTmp = ansi_to_utf8(GetProcessStartTime1(pTcpTable->table[i].dwOwningPid).data());
				if (!strTmp.empty())
					tcp_item.m_strStartTime = strTmp;
			}
      else{
        if (!_stricmp(tcp_item.m_strProcessPath.data(), "system")){
          tcp_item.m_strProcessName = tcp_item.m_strProcessPath;
        }
      }

			m_map_tcp_table.insert(make_pair(tcp_item.m_strBindIP+ ":" + tcp_item.m_strPort, tcp_item));
			Sleep(1);
		}
	} else {
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
	}    
	return true;
}

// get_udp_table_msg
bool DIAssetPort::get_udp_table_msg()
{
	DWORD dwRetVal = 0; 
	
	// 获取合适大小的buffer
	PMIB_UDPTABLE_OWNER_PID pUdpTable = (MIB_UDPTABLE_OWNER_PID *) MALLOC(sizeof (MIB_UDPTABLE_OWNER_PID));
	if (pUdpTable == NULL) {
		DI_LOG_ERROR("DIAssetPort::get_udp_table_msg：Error allocating memory\n");
		return false;
	}

	DWORD dwSize = sizeof (MIB_UDPTABLE_OWNER_PID);
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pUdpTable);
		pUdpTable = (MIB_UDPTABLE_OWNER_PID *) MALLOC(dwSize);
		if (pUdpTable == NULL) {
			DI_LOG_ERROR("DIAssetPort::get_udp_table_msg：Error allocating memory\n");
			return false;
		}
	}

	// 获取UDPTable
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == NO_ERROR) {
		int nNum = (int) pUdpTable->dwNumEntries;
		for (int i = 0; i < nNum; i++) {
			DIAssetPortItem udp_item;
			udp_item.m_strPort = ansi_to_utf8("--");
			udp_item.m_strProtocol = ansi_to_utf8("--");
			udp_item.m_strBindIP = ansi_to_utf8("--");
			udp_item.m_strProcessName = ansi_to_utf8("--");
			udp_item.m_strProcessPath = ansi_to_utf8("--");
			udp_item.m_strUser = ansi_to_utf8("--");
			udp_item.m_strSHA1 = ansi_to_utf8("");
			udp_item.m_strStartTime = ansi_to_utf8("--");
			udp_item.m_strRemoteAddr = ansi_to_utf8("--");
			udp_item.m_strRemotePort = ansi_to_utf8("--");
			udp_item.m_strState = ansi_to_utf8("--");
			udp_item.m_strPid = ansi_to_utf8("--");

			udp_item.m_strProtocol = ansi_to_utf8("UDP");                    // 协议

			in_addr inAddrLocal;
			memcpy(&inAddrLocal, &(pUdpTable->table[i].dwLocalAddr), sizeof(DWORD));
			std::string strTmp;
			strTmp = ansi_to_utf8(inet_ntoa(inAddrLocal));     // 监听IP
			if (!strTmp.empty())
				udp_item.m_strBindIP = strTmp;

			strTmp = ansi_to_utf8(std::to_string(ntohs((u_short)pUdpTable->table[i].dwLocalPort)).data());   // 端口号
			if (!strTmp.empty())
				udp_item.m_strPort = strTmp; 

			// 进程ID
			std::string strPid = ansi_to_utf8(std::to_string(pUdpTable->table[i].dwOwningPid).data());
			if (!strPid.empty())
				udp_item.m_strPid = strPid;

      wchar_t wszFilePath[MAX_PATH] = {0};
			if (!GetProcessFullPath(pUdpTable->table[i].dwOwningPid, wszFilePath)){
				wcsncpy_s(wszFilePath, MAX_PATH, L"UNKNOWN", 7);
			}

			TCHAR achLongPath[MAX_PATH] = { 0 };
      ::GetLongPathName(wszFilePath, achLongPath, sizeof(achLongPath)/sizeof(TCHAR) ); 
      strTmp = UnicodeToUtf8String(achLongPath);
      if (!strTmp.empty()){
        udp_item.m_strProcessPath = strTmp;        // 获取二进制路径
      }

			if (!_stricmp(udp_item.m_strProcessPath.data(), "system")){
				udp_item.m_strUser = ansi_to_utf8("SYSTEM");
			}

			if ((!udp_item.m_strProcessPath.empty()) && udp_item.m_strProcessPath.find("\\") != std::string::npos){

				// 进程名
				strTmp = udp_item.m_strProcessPath.substr(udp_item.m_strProcessPath.rfind("\\")+1);
				if (!strTmp.empty())
					udp_item.m_strProcessName = strTmp;

				// 运行用户
				std::wstring strRunUser;
				if (ExtractProcessOwner(pUdpTable->table[i].dwOwningPid, strRunUser)){
					if (!strRunUser.empty())
						udp_item.m_strUser = UnicodeToUtf8String(strRunUser);
				}

				// 进程SHA1
				byte sha1Buf[20] = {0};
				char sha1Str[MAX_LEN_256] = {0};
				DWORD dwBufSize = sizeof(sha1Buf);
				if (CalcFileSha1Entity(udp_item.m_strProcessPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
					ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
					strTmp = ansi_to_utf8(sha1Str);
					if (!strTmp.empty())
						udp_item.m_strSHA1 = strTmp;
				}

				// 启动时间
				strTmp = ansi_to_utf8(GetProcessStartTime1(pUdpTable->table[i].dwOwningPid).data());
				if (!strTmp.empty())
					udp_item.m_strStartTime = strTmp;
			}
      else{
        if (!_stricmp(udp_item.m_strProcessPath.data(), "system")){
          udp_item.m_strProcessName = udp_item.m_strProcessPath;
        }
      }

			m_map_udp_table.insert(make_pair(udp_item.m_strBindIP + ":" + udp_item.m_strPort, udp_item));
			Sleep(1);
		}
	} else {
		FREE(pUdpTable);
		return 1;
	}

	if (pUdpTable != NULL) {
		FREE(pUdpTable);
		pUdpTable = NULL;
	}    
	return true;
}

bool DIAssetPort::get_tcp_table_msg_ex()
{
	DWORD dwRetVal = 0;
	
	// 获取合适大小的buffer
	PMIB_TCP6TABLE_OWNER_PID pTcpTable = (MIB_TCP6TABLE_OWNER_PID *) MALLOC(sizeof (MIB_TCP6TABLE_OWNER_PID));
	if (pTcpTable == NULL) {
		DI_LOG_ERROR("DIAssetPort::get_tcp_table_msg_ex: Error allocating memory\n");
		return false;
	}

	DWORD dwSize = sizeof (MIB_TCP6TABLE_OWNER_PID);
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCP6TABLE_OWNER_PID *) MALLOC(dwSize);
		if (pTcpTable == NULL) {
			DI_LOG_ERROR("DIAssetPort::get_tcp_table_msg_ex: Error allocating memory\n");
			return false;
		}
	}

	// 获取TCPTable
	if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR) {
		int nNum = (int) pTcpTable->dwNumEntries;
		for (int i = 0; i < nNum; i++) {
      // 只采集监听状态的端口
      if (pTcpTable->table[i].dwState != MIB_TCP_STATE_LISTEN)
        continue;
			DIAssetPortItem tcp_item;
			tcp_item.m_strPort = ansi_to_utf8("--");
			tcp_item.m_strProtocol = ansi_to_utf8("--");
			tcp_item.m_strBindIP = ansi_to_utf8("--");
			tcp_item.m_strProcessName = ansi_to_utf8("--");
			tcp_item.m_strProcessPath = ansi_to_utf8("--");
			tcp_item.m_strUser = ansi_to_utf8("--");
			tcp_item.m_strSHA1 = ansi_to_utf8("");   // zhangqiang request
			tcp_item.m_strStartTime = ansi_to_utf8("--");
			tcp_item.m_strRemoteAddr = ansi_to_utf8("--");
			tcp_item.m_strRemotePort = ansi_to_utf8("--");
			tcp_item.m_strState = ansi_to_utf8("--");
			tcp_item.m_strPid = ansi_to_utf8("--");

			tcp_item.m_strProtocol = ansi_to_utf8("TCP");    // 协议

			in6_addr inAddrLocal, inAddrRemote;
			memcpy(&inAddrLocal, &(pTcpTable->table[i].ucLocalAddr), sizeof(in6_addr));
			memcpy(&inAddrRemote, &(pTcpTable->table[i].ucRemoteAddr), sizeof(in6_addr));

      wchar_t szTmpBuf[46] = {0};
      inet_ntop(AF_INET6, &inAddrLocal, szTmpBuf, sizeof(szTmpBuf));

      std::string strTmp;
      strTmp = ansi_to_utf8(UnicodeToUtf8String(szTmpBuf).data());        // 监听IP
      if (!strTmp.empty())
        tcp_item.m_strBindIP = strTmp;

      memset(szTmpBuf, 0, 46);
      inet_ntop(AF_INET6, &inAddrRemote, szTmpBuf, sizeof(szTmpBuf));
      strTmp = ansi_to_utf8(UnicodeToUtf8String(szTmpBuf).data());        // 远端地址
      if (!strTmp.empty())
        tcp_item.m_strRemoteAddr = strTmp;

			strTmp = ansi_to_utf8(std::to_string(ntohs((u_short)pTcpTable->table[i].dwLocalPort)).data());          // 端口号
			if (!strTmp.empty())
				tcp_item.m_strPort = strTmp;

			strTmp = ansi_to_utf8(std::to_string(ntohs((u_short)pTcpTable->table[i].dwRemotePort)).data());    // 远端端口
			if (!strTmp.empty())
				tcp_item.m_strRemotePort = strTmp;

			switch (pTcpTable->table[i].dwState) {               // 监听状态
			case MIB_TCP_STATE_CLOSED:
				tcp_item.m_strState = ansi_to_utf8("CLOSED");
				break;
			case MIB_TCP_STATE_LISTEN:
				tcp_item.m_strState = ansi_to_utf8("LISTENING");
				break;
			case MIB_TCP_STATE_SYN_SENT:
				tcp_item.m_strState = ansi_to_utf8("SYN-SENT");
				break;
			case MIB_TCP_STATE_SYN_RCVD:
				tcp_item.m_strState = ansi_to_utf8("SYN-RECEIVED");
				break;
			case MIB_TCP_STATE_ESTAB:
				tcp_item.m_strState = ansi_to_utf8("ESTABLISHED");
				break;
			case MIB_TCP_STATE_FIN_WAIT1:
				tcp_item.m_strState = ansi_to_utf8("FIN-WAIT-1");
				break;
			case MIB_TCP_STATE_FIN_WAIT2:
				tcp_item.m_strState = ansi_to_utf8("FIN-WAIT-2");
				break;
			case MIB_TCP_STATE_CLOSE_WAIT:
				tcp_item.m_strState = ansi_to_utf8("CLOSE-WAIT");
				break;
			case MIB_TCP_STATE_CLOSING:
				tcp_item.m_strState = ansi_to_utf8("CLOSING");
				break;
			case MIB_TCP_STATE_LAST_ACK:
				tcp_item.m_strState = ansi_to_utf8("LAST-ACK");
				break;
			case MIB_TCP_STATE_TIME_WAIT:
				tcp_item.m_strState = ansi_to_utf8("TIME-WAIT");
				break;
			case MIB_TCP_STATE_DELETE_TCB:
				tcp_item.m_strState = ansi_to_utf8("DELETE-TCB");
				break;
			default:
				break;
			}

			// 进程ID
			std::string strPid = ansi_to_utf8(std::to_string(pTcpTable->table[i].dwOwningPid).data());
			if (!strPid.empty())
				tcp_item.m_strPid = strPid;

			wchar_t wszFilePath[MAX_PATH] = {0};
			if (!GetProcessFullPath(pTcpTable->table[i].dwOwningPid, wszFilePath)){
				wcsncpy_s(wszFilePath, MAX_PATH, L"UNKNOWN", 7);
			}

			TCHAR achLongPath[MAX_PATH] = { 0 };
      ::GetLongPathName(wszFilePath, achLongPath, sizeof(achLongPath)/sizeof(TCHAR) ); 
      strTmp = UnicodeToUtf8String(achLongPath);
      if (!strTmp.empty()){
        tcp_item.m_strProcessPath = strTmp;        // 获取二进制路径
      }

			if (!_stricmp(tcp_item.m_strProcessPath.data(), "system")){
				tcp_item.m_strUser = ansi_to_utf8("SYSTEM");
			}

			if ((!tcp_item.m_strProcessPath.empty()) && tcp_item.m_strProcessPath.find("\\") != std::string::npos){

				// 进程名
				strTmp = tcp_item.m_strProcessPath.substr(tcp_item.m_strProcessPath.rfind("\\")+1);
				if (!strTmp.empty())
					tcp_item.m_strProcessName = strTmp;

				// 运行用户
				std::wstring strRunUser;
				if (ExtractProcessOwner(pTcpTable->table[i].dwOwningPid, strRunUser)){
					if (!strRunUser.empty())
						tcp_item.m_strUser = UnicodeToUtf8String(strRunUser);
				}

				// 进程SHA1
				byte sha1Buf[20] = {0};
				char sha1Str[MAX_LEN_256] = {0};
				DWORD dwBufSize = sizeof(sha1Buf);
				if (CalcFileSha1Entity(tcp_item.m_strProcessPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
					ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
					strTmp = ansi_to_utf8(sha1Str);
					if (!strTmp.empty())
						tcp_item.m_strSHA1 = strTmp;
				}

				// 启动时间
				strTmp = ansi_to_utf8(GetProcessStartTime1(pTcpTable->table[i].dwOwningPid).data());
				if (!strTmp.empty())
					tcp_item.m_strStartTime = strTmp;
			}
      else{
        if (!_stricmp(tcp_item.m_strProcessPath.data(), "system")){
          tcp_item.m_strProcessName = tcp_item.m_strProcessPath;
        }
      }

			m_map_tcp_table.insert(make_pair(tcp_item.m_strBindIP+ ":" + tcp_item.m_strPort, tcp_item));
			Sleep(1);
		}
	} else {
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
	}    
	return true;
}

// get_udp_table_msg
bool DIAssetPort::get_udp_table_msg_ex()
{
	DWORD dwRetVal = 0; 
	
	// 获取合适大小的buffer
	PMIB_UDP6TABLE_OWNER_PID pUdpTable = (MIB_UDP6TABLE_OWNER_PID *) MALLOC(sizeof (MIB_UDP6TABLE_OWNER_PID));
	if (pUdpTable == NULL) {
		DI_LOG_ERROR("DIAssetPort::get_udp_table_msg：Error allocating memory\n");
		return false;
	}

	DWORD dwSize = sizeof (MIB_UDP6TABLE_OWNER_PID);
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
		FREE(pUdpTable);
		pUdpTable = (MIB_UDP6TABLE_OWNER_PID *) MALLOC(dwSize);
		if (pUdpTable == NULL) {
			DI_LOG_ERROR("DIAssetPort::get_udp_table_msg_ex：Error allocating memory\n");
			return false;
		}
	}

	// 获取UDPTable
	if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0)) == NO_ERROR) {
		int nNum = (int) pUdpTable->dwNumEntries;
		for (int i = 0; i < nNum; i++) {
			DIAssetPortItem udp_item;
			udp_item.m_strPort = ansi_to_utf8("--");
			udp_item.m_strProtocol = ansi_to_utf8("--");
			udp_item.m_strBindIP = ansi_to_utf8("--");
			udp_item.m_strProcessName = ansi_to_utf8("--");
			udp_item.m_strProcessPath = ansi_to_utf8("--");
			udp_item.m_strUser = ansi_to_utf8("--");
			udp_item.m_strSHA1 = ansi_to_utf8("");
			udp_item.m_strStartTime = ansi_to_utf8("--");
			udp_item.m_strRemoteAddr = ansi_to_utf8("--");
			udp_item.m_strRemotePort = ansi_to_utf8("--");
			udp_item.m_strState = ansi_to_utf8("--");
			udp_item.m_strPid = ansi_to_utf8("--");

			udp_item.m_strProtocol = ansi_to_utf8("UDP");                    // 协议

			in6_addr inAddrLocal;
			memcpy(&inAddrLocal, &(pUdpTable->table[i].ucLocalAddr), sizeof(in6_addr));
			std::string strTmp;
			wchar_t szTmpBuf[46] = {0};
      inet_ntop(AF_INET6, &inAddrLocal, szTmpBuf, sizeof(szTmpBuf));
      strTmp = ansi_to_utf8(UnicodeToUtf8String(szTmpBuf).data());        // 监听IP
      if (!strTmp.empty())
        udp_item.m_strBindIP = strTmp;

			strTmp = ansi_to_utf8(std::to_string(ntohs((u_short)pUdpTable->table[i].dwLocalPort)).data());   // 端口号
			if (!strTmp.empty())
				udp_item.m_strPort = strTmp; 

			// 进程ID
			std::string strPid = ansi_to_utf8(std::to_string(pUdpTable->table[i].dwOwningPid).data());
			if (!strPid.empty())
				udp_item.m_strPid = strPid;

			wchar_t wszFilePath[MAX_PATH] = {0};
			if (!GetProcessFullPath(pUdpTable->table[i].dwOwningPid, wszFilePath)){
				wcsncpy_s(wszFilePath, MAX_PATH, L"UNKNOWN", 7);
			}

			TCHAR achLongPath[MAX_PATH] = { 0 };
      ::GetLongPathName(wszFilePath, achLongPath, sizeof(achLongPath)/sizeof(TCHAR) ); 
      strTmp = UnicodeToUtf8String(achLongPath);
      if (!strTmp.empty()){
        udp_item.m_strProcessPath = strTmp;        // 获取二进制路径
      }

			if (!_stricmp(udp_item.m_strProcessPath.data(), "system")){
				udp_item.m_strUser = ansi_to_utf8("SYSTEM");
			}

			if ((!udp_item.m_strProcessPath.empty()) && udp_item.m_strProcessPath.find("\\") != std::string::npos){

				// 进程名
				strTmp = udp_item.m_strProcessPath.substr(udp_item.m_strProcessPath.rfind("\\")+1);
				if (!strTmp.empty())
					udp_item.m_strProcessName = strTmp;

				// 运行用户
				std::wstring strRunUser;
				if (ExtractProcessOwner(pUdpTable->table[i].dwOwningPid, strRunUser)){
					if (!strRunUser.empty())
						udp_item.m_strUser = UnicodeToUtf8String(strRunUser);
				}

				// 进程SHA1
				byte sha1Buf[20] = {0};
				char sha1Str[MAX_LEN_256] = {0};
				DWORD dwBufSize = sizeof(sha1Buf);
				if (CalcFileSha1Entity(udp_item.m_strProcessPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
					ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
					strTmp = ansi_to_utf8(sha1Str);
					if (!strTmp.empty())
						udp_item.m_strSHA1 = strTmp;
				}

				// 启动时间
				strTmp = ansi_to_utf8(GetProcessStartTime1(pUdpTable->table[i].dwOwningPid).data());
				if (!strTmp.empty())
					udp_item.m_strStartTime = strTmp;
			}
      else{
        if (!_stricmp(udp_item.m_strProcessPath.data(), "system")){
          udp_item.m_strProcessName = udp_item.m_strProcessPath;
        }
      }

			m_map_udp_table.insert(make_pair(udp_item.m_strBindIP + ":" + udp_item.m_strPort, udp_item));
			Sleep(1);
		}
	} else {
		FREE(pUdpTable);
		return 1;
	}

	if (pUdpTable != NULL) {
		FREE(pUdpTable);
		pUdpTable = NULL;
	}    
	return true;
}
}