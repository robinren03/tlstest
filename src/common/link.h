#ifndef _TLSTEST_LINK
#define _TLSTEST_LINK
#include "conf.h"
#include <openssl/bio.h>
#include <sys/socket.h>
// In this section, direct means no change in the ciphertext the server and client exchanged,
// and inter means the attacker deliberately modify the ciphertext exchanged in the MitM attack.

class Link{
protected:
    bool isReal;
    char *data;
    int data_len;
public:
    Link(bool _isReal):isReal(_isReal){
        data_len = 0;
    }
    char* get_data_ptr() {
        return data;
    }
    int get_data_len() {
        return data_len;
    }
    virtual int link_send()=0;
    virtual int link_recv()=0;
};

class FakeDirectLink : private Link{
private:
    BIO *my_out, *my_in;
    BIO *peer_out, *peer_in;
public:
    FakeDirectLink(BIO* _my_out , BIO* _my_in, BIO* _peer_out, BIO* _peer_in, char* _data): Link(false){
        my_out = _my_out; my_in = _my_in;
        peer_out = _peer_out; peer_in = _peer_in;
        data = _data;
    }

    int link_send(){
        int pending = BIO_ctrl_pending(my_out); // Make sure the data is fine, for use of handshaking only
        if(pending > 0) {
            int sock_len = BIO_read(my_out, data, MAXBUF);
            data_len = sock_len;
            printf("pending is %d, sock_len is %d\n", pending, sock_len);
            // hexify(socket_buf, encrypted_len);
            BIO_write(peer_in, data, data_len);
            return data_len;
        } 
        data_len = -1;
        return -1;
    };

    int link_recv(){
        return data_len;
    }
};

class TCPDirectLink : private Link{
private:
    int fd;
    BIO* my_out, *my_in;
public:
    TCPDirectLink(BIO* _my_out , BIO* _my_in,int _fd):Link(true){
        fd = _fd;
        my_out = _my_out;
        my_in = _my_in;
        data = new char[MAXBUF];
    }

    int link_send(){
        int pending = BIO_ctrl_pending(my_out); // Make sure the data is fine, for use of handshaking only
        if(pending > 0) {
            int sock_len = BIO_read(my_out, data, MAXBUF);
            data_len = sock_len;
            printf("pending is %d, sock_len is %d\n", pending, sock_len);
            // hexify(socket_buf, encrypted_len);
            if (sock_len > 0) return send(fd, data, sock_len, 0);
            return data_len;
        } 
        data_len = -1;
        return -1;
    }

    int link_recv(){
        int len = recv(fd, data, MAXBUF, 0);
        data_len = len;
        int written = BIO_write(my_in, data, len);
        return len;
    }
};

#endif