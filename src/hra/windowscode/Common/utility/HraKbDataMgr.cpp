#include "HraKbDataMgr.h"

HraKbDataMgr::HraKbDataMgr()
{
}

HraKbDataMgr::~HraKbDataMgr()
{
}

HraKbDataMgr& HraKbDataMgr::getInstance()
{
    static HraKbDataMgr stcInstance;
    return stcInstance;
}

bool HraKbDataMgr::pushData(const KbData& data)
{
    m_mutex.lock();
    for (std::list<KbData>::iterator it = m_lstData.begin(); m_lstData.end() != it;)
    {
        if (it->nSeq != data.nSeq)
        {
            ++it;
            continue;
        }

        it = m_lstData.erase(it);
    }
    m_lstData.push_back(data);
    m_mutex.unlock();
    return true;
}

bool HraKbDataMgr::popData(KbData& data, unsigned long long nSeq)
{
    m_mutex.lock();
    if (m_lstData.empty())
    {
        m_mutex.unlock();
        return false;
    }

    if (nSeq <= 0)
    {
        data = *m_lstData.begin();
        m_lstData.pop_front();
        m_mutex.unlock();
        return true;
    }

    for (std::list<KbData>::iterator it = m_lstData.begin(); m_lstData.end() != it;)
    {
        if (nSeq != it->nSeq)
        {
            ++it;
            continue;
        }

        data = *it;
        it   = m_lstData.erase(it);
        m_mutex.unlock();
        return true;
    }

    m_mutex.unlock();
    return false;
}

bool HraKbDataMgr::getData(KbData& data, unsigned long long nSeq)
{
    m_mutex.lock();
    if (m_lstData.empty())
    {
        m_mutex.unlock();
        return false;
    }

    if (nSeq <= 0)
    {
        data = *m_lstData.begin();
        m_mutex.unlock();
        return true;
    }

    for (std::list<KbData>::iterator it = m_lstData.begin(); m_lstData.end() != it;)
    {
        if (nSeq != it->nSeq)
        {
            ++it;
            continue;
        }

        data = *it;
        m_mutex.unlock();
        return true;
    }

    m_mutex.unlock();
    return false;
}

void HraKbDataMgr::clear()
{
    m_mutex.lock();
    m_lstData.clear();
    m_mutex.unlock();
}