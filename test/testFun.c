#include <stdio.h>
#include "../include/securec.h"

int main()
{
	char buf[20];

	/* sec_memset_s() test */
    if (sec_memset_s(buf, sizeof(buf), 'A', 10) == SEC_OK)
        printf("memset success\n");
    else
        printf("memset failed\n");
	
	printf("--- %d\n", testFun(100));

	return(0);
}
