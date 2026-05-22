#include "DIMutex.h"

namespace di_rest_client
{
CDIMutex::CDIMutex(void)
    : m_mutex()
{
#ifdef _WIN32
    InitializeCriticalSection(&m_mutex);
#else
    pthread_mutex_init(&m_mutex, NULL);
#endif
}

CDIMutex::~CDIMutex(void)
{
#ifdef _WIN32
    DeleteCriticalSection(&m_mutex);
#else
    pthread_mutex_destroy(&m_mutex);
#endif
}

void CDIMutex::Lock()
{
#ifdef _WIN32
    EnterCriticalSection(&m_mutex);
#else
    pthread_mutex_lock(&m_mutex);
#endif
}

void CDIMutex::Unlock()
{
#ifdef _WIN32
    LeaveCriticalSection(&m_mutex);
#else
    pthread_mutex_unlock(&m_mutex);
#endif
}

CDIMutexGuard::CDIMutexGuard(CDIMutex& mutex)
    : m_mutex(mutex)
{
    m_mutex.Lock();
}

CDIMutexGuard::~CDIMutexGuard()
{
    m_mutex.Unlock();
}
}  // namespace di_rest_client
