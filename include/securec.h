#ifndef __SECURELIB__
#define __SECURELIB__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Version Info
 * ============================================================*/
#define SECUREC_VERSION_MAJOR   1
#define SECUREC_VERSION_MINOR   0
#define SECUREC_VERSION_PATCH   0

/* ============================================================
 * Common Return Codes
 * ============================================================*/
#define SEC_OK              0
#define SEC_ERR_NULL       -1
#define SEC_ERR_SIZE       -2
#define SEC_ERR_OVERFLOW   -3
#define SEC_ERR_RANGE      -4
#define SEC_ERR_INVAL      -5
#define SEC_ERR_NOMEM      -6
#define SEC_ERR_FAIL       -7

/* ============================================================
 * Limits / Config
 * ============================================================*/
#ifndef SEC_MAX_BUFFER
#define SEC_MAX_BUFFER (1024U * 1024U * 10U)   /* 10MB safety cap */
#endif

#ifndef SEC_ENABLE_LOGGING
#define SEC_ENABLE_LOGGING 1
#endif

/* ============================================================
 * Validation Helpers
 * ============================================================*/
int sec_validate_ptr(const void *ptr);
int sec_validate_size(size_t size);
int sec_validate_range(size_t destsz, size_t count);
int sec_validate_overlap(const void *dest, const void *src, size_t len);

/* ============================================================
 * Memory Safe Functions
 * ============================================================*/
int sec_memcpy_s(void *dest, size_t destsz,
                 const void *src, size_t count);

int sec_memmove_s(void *dest, size_t destsz,
                  const void *src, size_t count);

int sec_memset_s(void *dest, size_t destsz,
                 int ch, size_t count);

int sec_memcmp_s(const void *buf1, size_t s1max,
                 const void *buf2, size_t s2max,
                 int *result);

int sec_zeroize(void *dest, size_t len);

/* ============================================================
 * String Safe Functions
 * ============================================================*/
int sec_strcpy_s(char *dest, size_t destsz,
                 const char *src);

int sec_strncpy_s(char *dest, size_t destsz,
                  const char *src, size_t count);

int sec_strcat_s(char *dest, size_t destsz,
                 const char *src);

size_t sec_strlen_s(const char *str, size_t maxlen);
size_t sec_strnlen_s(const char *str, size_t maxlen);

int sec_strcmp_s(const char *s1, const char *s2, int *result);
int sec_strncmp_s(const char *s1, const char *s2,
                  size_t n, int *result);

/* ============================================================
 * Formatting Safe Functions
 * ============================================================*/
int sec_snprintf_s(char *dest, size_t destsz,
                   const char *format, ...);

int sec_vsnprintf_s(char *dest, size_t destsz,
                    const char *format, va_list args);

/* ============================================================
 * Security Specific Functions
 * ============================================================*/

/* Constant-time compare (prevents timing attacks) */
int sec_constant_time_compare(const void *a,
                              const void *b,
                              size_t len);

/* Secure random bytes (platform dependent implementation) */
int sec_random_bytes(uint8_t *buf, size_t len);

/* Secure zeroization for sensitive data */
int sec_zeroize_sensitive(void *buf, size_t len);

/* ============================================================
 * Error Handling / Logging
 * ============================================================*/
void sec_set_error(int err);
int  sec_get_last_error(void);
const char* sec_error_string(int err);

/* Optional secure logging */
void sec_log_error(const char *msg);
void sec_log_warn(const char *msg);
void sec_log_info(const char *msg);

/* ============================================================
 * Utility / Config
 * ============================================================*/
void sec_init(void);
void sec_deinit(void);
const char* sec_version(void);

/* ============================================================
 * Test Function (your placeholder)
 * ============================================================*/
int testFun(int value);

#ifdef __cplusplus
}
#endif

#endif /* __SECURELIB__ */
