#ifndef _TLSTEST_COMMON_CONF
#define _TLSTEST_COMMON_CONF

#define MAXBUF 4096

#define SSL_WHERE_INFO(ssl, w, flag, msg, name) {          \
    if(w & flag) {                                         \
      printf("+ %s: ", name);                              \
      printf("%20.20s", msg);                              \
      printf(" - %30.30s ", SSL_state_string_long(ssl));   \
      printf(" - %5.10s ", SSL_state_string(ssl));         \
      printf("\n");                                        \
    }                                                      \
  } 

#endif