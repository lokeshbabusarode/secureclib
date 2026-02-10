#include "../include/securec.h"

/*
 * sec_memset_s
 * ------------------------------------------------------------
 * Secure replacement for memset()
 *
 * Features:
 *  - NULL pointer validation
 *  - Destination size validation
 *  - Overflow protection
 *  - Prevent compiler optimization (for secure zeroization)
 *  - Returns standardized error codes
 *
 * Parameters:
 *  dest    : destination buffer
 *  destsz  : total size of destination buffer
 *  ch      : byte value to set
 *  count   : number of bytes to set
 *
 * Returns:
 *  SEC_OK on success
 *  Error code otherwise
 */

int sec_memset_s(void *dest, size_t destsz,
                 int ch, size_t count)
{
    /* ---------------------------------------------------------
     * Basic pointer validation
     * --------------------------------------------------------- */
    if (dest == NULL)
    {
        return SEC_ERR_NULL;
    }

    /* ---------------------------------------------------------
     * Size validation
     * --------------------------------------------------------- */
    if (destsz == 0U || destsz > SEC_MAX_BUFFER)
    {
        return SEC_ERR_SIZE;
    }

    /* ---------------------------------------------------------
     * Overflow / bounds check
     * --------------------------------------------------------- */
    if (count > destsz)
    {
        /* If overflow risk, clear full buffer defensively */
        volatile unsigned char *d = (volatile unsigned char *)dest;
        size_t i;

        for (i = 0U; i < destsz; i++)
        {
            d[i] = 0U;
        }

        return SEC_ERR_OVERFLOW;
    }

    /* ---------------------------------------------------------
     * Perform memory set using volatile pointer
     * Prevents compiler optimization removal
     * --------------------------------------------------------- */
    volatile unsigned char *d = (volatile unsigned char *)dest;
    size_t i;

    for (i = 0U; i < count; i++)
    {
        d[i] = (unsigned char)ch;
    }

    return SEC_OK;
}
