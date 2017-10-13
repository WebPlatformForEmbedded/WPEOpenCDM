#pragma once

// FIXME: Really don't need this, but all callers of the old logging macro need to be nuked.
#include <iostream>

namespace media {

// Log a formatted message to stderr, ensuring the message contains a trailing newline.
void CDMLogLine(const char* format, ...);

// Log a formatted message
void CDMLog(const char* format, ...);

// Perform a hex dump of the passed in memory.
void CDMDumpMemory(const uint8_t* memory, const int nbytes);

#define CDM_LOG(...) do { \
    fprintf(stderr, "WPEOpenCDM: %s(%d) %s: ", __FILE__, __LINE__, __func__); \
    CDMLog(__VA_ARGS__); \
    } while (0)
#define CDM_LOG_LINE(...) do { \
    fprintf(stderr, "WPEOpenCDM: %s(%d) %s: ", __FILE__, __LINE__, __func__); \
    CDMLogLine(__VA_ARGS__); \
    } while (0)

// FIXME: Get rid of this.
#define CDM_DLOG() std::cout << "\n" <<__FILE__<<":"<<  __func__ <<":"<< __LINE__ <<"::"
}  // namespace media
