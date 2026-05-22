#pragma once

#include <string>
#include <iostream>
#include <vector>
#include <map>

namespace di_rest_client
{
class DIAssetPortItem
{
public:
	// 关键字段
	std::string m_strPort;            // 端口号
	std::string m_strProtocol;        // 协议
	std::string m_strBindIP;          // 监听IP
	std::string m_strProcessName;     // 进程名
	std::string m_strProcessPath;     // 进程路径
	std::string m_strUser;            // 运行用户
	std::string m_strSHA1;            // 进程sha1
	std::string m_strStartTime;       // 启动时间

	// 扩展字段
	std::string m_strRemoteAddr;      // 远端地址
	std::string m_strRemotePort;      // 远端端口
	std::string m_strState;           // 连接状态
	std::string m_strPid;             // 监听进程PID
};

class DIAssetPort
{
public:
	DIAssetPort(void);
	~DIAssetPort(void);

	bool InitDIAssetPort(void);
	std::map<std::string, DIAssetPortItem>& GetTcpPortList(void);
	std::map<std::string, DIAssetPortItem>& GetUdpPortList(void);
	std::map<std::string, DIAssetPortItem>& GetAllPortList(void);

private:
	bool get_tcp_table_msg();      // AF_INET
	bool get_udp_table_msg();

	bool get_tcp_table_msg_ex();   // AF_INET6
	bool get_udp_table_msg_ex();

private:
	std::map<std::string, DIAssetPortItem> m_map_tcp_table;
	std::map<std::string, DIAssetPortItem> m_map_udp_table;
	std::map<std::string, DIAssetPortItem> m_map_all_table;
};
}
