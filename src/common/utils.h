#ifndef _TLSTEST_UTILS
#define _TLSTEST_UTILS

inline int min(int a, int b) { return (a < b)? a : b; }
bool check(const char* a, const char* b, int len){
    int min_len = min(min(strlen(a), strlen(b)),len);
    for (int i=0; i<min_len; i++)
        if (a[i] != b[i]) return false;
    return true;
}
#endif