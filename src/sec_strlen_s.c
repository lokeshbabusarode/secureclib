#include "../include/securec.h"

/**
 * @file sec_strlen.c
 * @brief Safe bounded strlen implementation
 *
 * Prevents scanning beyond allowed memory.
 */

size_t sec_strlen_s(const char *str, size_t maxlen)
{
    if (str == NULL)
    {
        return 0U;
    }

    if (maxlen == 0U || maxlen > SEC_MAX_BUFFER)
    {
        return 0U;
    }

    size_t len = 0U;

    while ((len < maxlen) && (str[len] != '\0'))
    {
        len++;
    }

    return len;
}
