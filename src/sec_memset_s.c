#include "../include/securec.h"

/**
 * @file sec_memset_s.c
 * @brief Secure implementation of memory set function.
 *
 * @details
 * This file implements sec_memset_s(), a secure and defensive replacement
 * for standard C memset() and optional libc memset_s() implementations.
 *
 * The function is designed for enterprise, embedded, and automotive-grade
 * secure coding environments where memory safety, deterministic behavior,
 * and compliance with standards such as CERT-C, MISRA C, and ISO/SAE 21434
 * are required.
 *
 * ---------------------------------------------------------------------------
 * @section comparison Comparison with Standard memset() and libc memset_s()
 *
 * | Feature / Criteria                  | Standard memset() | libc memset_s() (Annex K) | sec_memset_s() |
 * |------------------------------------|-------------------|----------------------------|----------------|
 * | Bounds checking                     | No                | Yes                        | Yes (strict + configurable) |
 * | NULL pointer handling               | Undefined behavior| Returns error              | Explicit error handling |
 * | Overflow protection                 | No                | Yes                        | Yes + defensive clearing |
 * | Guaranteed memory write             | No (may optimize) | Yes                        | Yes (volatile enforced) |
 * | Cross-platform availability         | Universal         | Limited/inconsistent       | Fully controlled internal |
 * | Standardized error codes            | None              | Implementation dependent   | Unified error model |
 * | Configurable max buffer protection  | No                | No                         | Yes (SEC_MAX_BUFFER) |
 * | Defensive clearing on error         | No                | Not guaranteed             | Yes |
 * | Secure coding compliance alignment  | No                | Partial                    | CERT-C, MISRA, ISO21434 |
 * | Embedded/automotive suitability     | Risky             | Limited                    | Designed for safety/security |
 * | Internal trade-secret value         | No                | No                         | Yes |
 *
 * ---------------------------------------------------------------------------
 * @section benefits Key Security Benefits
 *
 * - Prevents buffer overflow and misuse
 * - Ensures deterministic secure memory clearing
 * - Prevents compiler optimization removal of sensitive memory wiping
 * - Provides standardized error handling across secure library
 * - Supports enterprise secure coding best practices
 *
 * This implementation forms part of the SecureC Library initiative aimed at
 * strengthening secure-by-design software development across the organization.
 *
 */

int sec_memset_s(void *dest, size_t destsz,
                 int ch, size_t count)
{
    int rc;

    /* ---------------------------------------------------------
     * Validate destination pointer
     * --------------------------------------------------------- */
    rc = sec_validate_ptr(dest);
    if (rc != SEC_OK)
    {
        return rc;
    }

    /* ---------------------------------------------------------
     * Validate destination size
     * --------------------------------------------------------- */
    rc = sec_validate_size(destsz);
    if (rc != SEC_OK)
    {
        return rc;
    }

    /* ---------------------------------------------------------
     * Validate requested operation range
     * --------------------------------------------------------- */
    rc = sec_validate_range(destsz, count);
    if (rc != SEC_OK)
    {
        /* Defensive clearing if overflow attempt detected */
        if (rc == SEC_ERR_OVERFLOW)
        {
            volatile unsigned char *d = (volatile unsigned char *)dest;
            size_t i;

            for (i = 0U; i < destsz; i++)
            {
                d[i] = 0U;
            }
        }
        return rc;
    }

    /* ---------------------------------------------------------
     * Perform secure memory set
     * Using volatile pointer prevents optimization removal
     * --------------------------------------------------------- */
    volatile unsigned char *d = (volatile unsigned char *)dest;
    size_t i;

    for (i = 0U; i < count; i++)
    {
        d[i] = (unsigned char)ch;
    }

    return SEC_OK;
}
