#include "cdm_logging.h"

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstddef>
#include <cctype>
#include <memory>

namespace media {

static void vprintfToStderrWithTrailingNewline(const char* format, va_list args)
{
    size_t formatLength = strlen(format);
    if (formatLength && format[formatLength - 1] == '\n') {
        vfprintf(stderr, format, args);
        return;
    }

    auto formatWithNewline = std::make_unique<char[]>(formatLength + 2);
    memcpy(formatWithNewline.get(), format, formatLength);
    formatWithNewline[formatLength] = '\n';
    formatWithNewline[formatLength + 1] = 0;

    vfprintf(stderr, formatWithNewline.get(), args);
}

void CDMLogLine(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vprintfToStderrWithTrailingNewline(format, args);
    fflush(stderr);
    va_end(args);
}

void CDMLog(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    fflush(stderr);
    va_end(args);
}

void CDMDumpMemory(const uint8_t *memory, const int nbytes)
{
    static const int bytesPerLine = 16;
    int bytesRead = 0;
    const uint8_t* ptr = memory;
    const uint8_t* end = memory + nbytes;
    int nlines = nbytes / bytesPerLine; // always one less than total.

    while (nlines--) {
        fprintf(stderr, "%08x ", bytesRead);
        // Write the bytes
        for (int byteCol = 0; byteCol < bytesPerLine; byteCol++)
            fprintf(stderr, "%-3x", *(ptr + byteCol));

        // Now format the ASCII
        fputc('|', stderr);
        for (int asciiByte = 0; asciiByte < bytesPerLine; asciiByte++) {
            const uint8_t byte = *(ptr + asciiByte);
            fputc(isgraph(byte) ? byte : '.', stderr);
        }

        fprintf(stderr, "|\n");
        ptr += bytesPerLine;
        bytesRead += bytesPerLine;
    }

    ptrdiff_t bytesRemaining = end - ptr;
    if (!bytesRemaining)
        return; // avoid printing emptiness in bars.
    int byteCol = 0;
    // Now write out the final line
    fprintf(stderr, "%08x ", bytesRead);
    for ( ; byteCol < bytesRemaining; byteCol++)
        fprintf(stderr, "%-3x", *(ptr + byteCol));
    for ( ; byteCol < bytesPerLine; byteCol++)
        fprintf(stderr, "   ");
    // Now format the ASCII
    fputc('|', stderr);
    int asciiByte = 0;
    for ( ; asciiByte < bytesRemaining; asciiByte++) {
        const uint8_t byte = *(ptr + asciiByte);
        fputc(isgraph(byte) ? byte : '.', stderr);
    }
    for ( ; asciiByte < bytesPerLine; asciiByte++) {
        fputc(' ', stderr);
    }

    fprintf(stderr, "|\n");
}

} // namespace media
