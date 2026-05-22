#include "HraCtrlCmd.h"
#include "Logger.h"

HraCtrlCmd* HraCtrlCmd::m_pInstance = new HraCtrlCmd();

HraCtrlCmd::HraCtrlCmd()
{
}

HraCtrlCmd::~HraCtrlCmd()
{
}

HraCtrlCmd* HraCtrlCmd::getInstance()
{
    return m_pInstance;
}

bool HraCtrlCmd::pushCmd(uint64_t nThreadID, int iCmd)
{
    if (iCmd <= (int)CmdDef::cmd_init)
    {
        LOG_ERROR("Push command error! nThreadID:%llu, cmd:%d", nThreadID, iCmd);
        return false;
    }
    
    m_mutex.lock();
    std::map<uint64_t, int>::iterator it = m_mapCmd.find(nThreadID);
    if (m_mapCmd.end() != it)
    {
        it->second = iCmd;
    }
    else
    {
        m_mapCmd.insert(std::map<uint64_t, int>::value_type(nThreadID, iCmd));
    }
    LOG_INFO("Push command, nThreadID:%llu, cmd:%d", nThreadID, iCmd);

    m_mutex.unlock();
    return true;
}

int HraCtrlCmd::popCmd(uint64_t nThreadID)
{
    m_mutex.lock();
    int iCmd                             = (int)CmdDef::cmd_init;
    std::map<uint64_t, int>::const_iterator it = m_mapCmd.find(nThreadID);
    if (m_mapCmd.end() != it)
    {
        iCmd = it->second;
        m_mapCmd.erase(it);
        LOG_INFO("Pop command, nThreadID:%llu, cmd:%d", nThreadID, iCmd);
    }
    m_mutex.unlock();
    return iCmd;
}

int HraCtrlCmd::getCmd(uint64_t nThreadID)
{
    m_mutex.lock();
    int iCmd                             = (int)CmdDef::cmd_init;
    std::map<uint64_t, int>::const_iterator it = m_mapCmd.find(nThreadID);
    if (m_mapCmd.end() != it)
    {
        iCmd = it->second;
        LOG_INFO("Get command, nThreadID:%llu, cmd:%d", nThreadID, iCmd);
    }
    m_mutex.unlock();
    return iCmd;
}

void HraCtrlCmd::clear()
{
    m_mutex.lock();
    for (std::map<uint64_t, int>::const_iterator it = m_mapCmd.begin(); m_mapCmd.end() != it; ++it)
    {
        LOG_INFO("Clear command, nThreadID:%llu, cmd:%d", it->first, it->second);
    }
    m_mapCmd.clear();
    m_mutex.unlock();
}