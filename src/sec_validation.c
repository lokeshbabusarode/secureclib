#include "../include/securec.h"

/*
 * Central validation helpers for SecureC library
 * Used by all secure APIs to enforce consistent checks
 */

/* -----------------------------------------------------------
 * Validate pointer
 * ----------------------------------------------------------- */
int sec_validate_ptr(const void *ptr)
{
    if (ptr == NULL)
    {
        return SEC_ERR_NULL;
    }

    return SEC_OK;
}

/* -----------------------------------------------------------
 * Validate size (generic)
 * ----------------------------------------------------------- */
int sec_validate_size(size_t size)
{
    if (size == 0U)
    {
        return SEC_ERR_SIZE;
    }

    if (size > SEC_MAX_BUFFER)
    {
        return SEC_ERR_RANGE;
    }

    return SEC_OK;
}

/* -----------------------------------------------------------
 * Validate destination range
 * Ensures count does not exceed destination buffer
 * ----------------------------------------------------------- */
int sec_validate_range(size_t destsz, size_t count)
{
    if (destsz == 0U)
    {
        return SEC_ERR_SIZE;
    }

    if (destsz > SEC_MAX_BUFFER)
    {
        return SEC_ERR_RANGE;
    }

    if (count > destsz)
    {
        return SEC_ERR_OVERFLOW;
    }

    return SEC_OK;
}

/* -----------------------------------------------------------
 * Validate memory overlap
 * Required for memcpy_s safety
 * ----------------------------------------------------------- */
int sec_validate_overlap(const void *dest, const void *src, size_t len)
{
    if ((dest == NULL) || (src == NULL))
    {
        return SEC_ERR_NULL;
    }

    const unsigned char *d = (const unsigned char *)dest;
    const unsigned char *s = (const unsigned char *)src;

    /* Check overlap */
    if ((d < (s + len)) && (s < (d + len)))
    {
        return SEC_ERR_INVAL;  /* overlap detected */
    }

    return SEC_OK;
}
