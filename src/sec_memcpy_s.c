#include "../include/securec.h"

/**
 * @file sec_memcpy.c
 * @brief Secure replacement for memcpy()
 *
 * Features:
 *  - NULL validation
 *  - Bounds checking
 *  - Overflow protection
 *  - Overlap detection
 */

int sec_memcpy_s(void *dest, size_t destsz,
                 const void *src, size_t count)
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

    /* Range validation */
    rc = sec_validate_range(destsz, count);
    if (rc != SEC_OK)
    {
        /* Defensive clear if overflow */
        if (rc == SEC_ERR_OVERFLOW)
        {
            volatile unsigned char *d = (volatile unsigned char *)dest;
            for (size_t i = 0U; i < destsz; i++)
                d[i] = 0U;
        }
        return rc;
    }

    /* Overlap validation */
    rc = sec_validate_overlap(dest, src, count);
    if (rc != SEC_OK)
    {
        return rc;
    }

    /* Secure copy */
    unsigned char *d = (unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    for (size_t i = 0U; i < count; i++)
    {
        d[i] = s[i];
    }

    return SEC_OK;
}
