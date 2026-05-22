#include "RwLock.h"

CDIMutex::CDIMutex(void)
	: m_mutex()
{
	InitializeCriticalSection(&m_mutex);
}

CDIMutex::~CDIMutex(void)
{
	DeleteCriticalSection(&m_mutex);

}

void CDIMutex::Lock()
{
	EnterCriticalSection(&m_mutex);
}

void CDIMutex::UnLock()
{
	LeaveCriticalSection(&m_mutex);
}

CDIMutexGuard::CDIMutexGuard(CDIMutex& mutex)
	: m_mutex(mutex)
{
	m_mutex.Lock();
}

CDIMutexGuard::~CDIMutexGuard()
{
	m_mutex.UnLock();
}

