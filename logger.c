#include "logger.h"

int log_level = LOG_LEVEL_DEBUG;

void logger_set_level(int level)
{
    log_level = level;
}