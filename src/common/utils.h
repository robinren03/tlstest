#ifndef _TLSTEST_UTILS
#define _TLSTEST_UTILS
#include <string.h>
#include <cstdio>

inline int min(int a, int b) { return (a < b)? a : b; }
bool check(const char* a, const char* b, int len){
    // int min_len = min(min(strlen(a), strlen(b)),len);
    for (int i=0; i<len; i++)
        if (a[i] != b[i]) return false;
    return true;
}
inline int round_up(int a, int mod){ return ((a + mod - 1) / mod)* mod; }

#ifdef DEBUG
void hexify(const char* a, int len){
    for (int i=0; i < len; i++){
        if ((unsigned char)a[i]<16) printf("0");
        printf("%x ", (unsigned char)a[i]);
        // printf("%x ", (unsigned short)a[i]);
    }
    printf("\n");
}
#endif

#endif