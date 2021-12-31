#pragma once

#if defined(_WIN32)
#define PLATFORM_WINDOWS
#elif defined(unix) || defined(__unix) || defined(__unix__)
#define PLATFORM_UNIX
#if defined(__linux__)
#define PLATFORM_LINUX
#endif
#endif