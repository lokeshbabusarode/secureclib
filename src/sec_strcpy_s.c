#include "../include/securec.h"

/**
 * @file sec_strcpy.c
 * @brief Secure replacement for strcpy()
 *
 * Features:
 *  - NULL validation
 *  - Destination bounds checking
 *  - Guaranteed NULL termination
 *  - Overflow protection
 */

int sec_strcpy_s(char *dest, size_t destsz,
                 const char *src)
{
    int rc;

    /* Pointer validation */
    rc = sec_validate_ptr(dest);
    if (rc != SEC_OK) return rc;

    rc = sec_validate_ptr(src);
    if (rc != SEC_OK) return rc;

    /* Size validation */
    rc = sec_validate_size(destsz);
    if (rc != SEC_OK) return rc;

    size_t i = 0U;

    /* Copy loop */
    while (src[i] != '\0')
    {
        if (i >= destsz - 1U)
        {
            /* Overflow risk → clear dest */
            volatile unsigned char *d = (volatile unsigned char *)dest;
            for (size_t j = 0U; j < destsz; j++)
                d[j] = 0U;

            return SEC_ERR_OVERFLOW;
        }

        dest[i] = src[i];
        i++;
    }

    dest[i] = '\0';
    return SEC_OK;
}
