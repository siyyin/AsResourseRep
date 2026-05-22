#ifndef DIAGENT_DIMUTEX_H
#define DIAGENT_DIMUTEX_H

#ifdef _WIN32
#include <Windows.h>
#else
#include <pthread.h>
#endif  // WIN32

namespace di_rest_client
{
class CDIMutex
{
  public:
    CDIMutex(void);
    ~CDIMutex(void);

    void Lock(void);
    void Unlock(void);

  private:
#ifdef _WIN32
    CRITICAL_SECTION m_mutex;
#else
    pthread_mutex_t m_mutex;
#endif
};

class CDIMutexGuard
{
  public:
    CDIMutexGuard(CDIMutex& mutex);
    ~CDIMutexGuard(void);

  private:
    CDIMutex m_mutex;
};
}  // namespace di_rest_client
#endif  // DIAGENT_MUTEX_H
