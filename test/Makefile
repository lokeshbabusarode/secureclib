GNULIBS = -lsecurec

CFLAGS =-Wall -Werror

testFun: 
	cc -L ../lib -o testFun testFun.c $(CFLAGS) $(GNULIBS)
	cc -L ../lib -o sec_memset sec_memset.c $(CFLAGS) $(GNULIBS)

clean:
	rm -r  testFun sec_memset
