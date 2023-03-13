#ifndef _TLSTEST_CTRL_LINK
#define _TLSTEST_CTRL_LINK
#include "conf.h"
#include <openssl/bio.h>
#include <sys/socket.h>
#include <cstring>

class CtrlLink{
protected:
    bool isReal;
public:
    CtrlLink(bool _isReal):isReal(_isReal){
    }
    virtual int link_send(const char* buf, int len)=0;
    virtual int link_recv(char* buf)=0;
};

class FakeCtrlLink : public CtrlLink{
private:
    char* data;
    int data_len;
public:
    FakeCtrlLink(int fd): CtrlLink(false){
        data = new char[MAXBUF];
    }

    ~FakeCtrlLink(){
        delete[] data;
    }

    int link_send(const char* buf, int len){
        memcpy(data, buf, len);
        data_len = len;

    };

    int link_recv(char* buf){
        if (data_len >= 0) memcpy(buf, data, data_len);
        return data_len;
    }
};

class TCPCtrlLink : public CtrlLink{
private:
    int fd;
public:
    TCPCtrlLink(int _fd):CtrlLink(true){
        fd = _fd;
    }

    int link_send(const char* buf, int len){
        send(fd, buf, len, 0);
        return -1;
    }

    int link_recv(char* buf){
        int len = recv(fd, buf, MAXBUF, 0);
        return len;
    }
};

#endif