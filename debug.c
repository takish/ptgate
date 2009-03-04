#include <stdio.h>
#include <stdarg.h>

#include "debug.h"

int	debug_verbose = 0;

void
debug(int debug_level, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    if (debug_level <= debug_verbose) {
        vprintf(format, ap);
    }
}
