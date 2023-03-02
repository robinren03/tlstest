#ifndef _TLSTEST_LINK
#define _TLSTEST_LINK
#include "conf.h"
#include <openssl/bio.h>
// In this section, direct means no change in the ciphertext the server and client exchanged,
// and inter means the attacker deliberately modify the ciphertext exchanged in the MitM attack.

// class Link{
// private:
//     bool isReal;
// public:
//     Link(bool _isReal):isReal(_isReal){}
//     virtual void send(const char* buf, int len)=0;
//     virtual int recv(char* buf, int maxbuf=MAXBUF)=0;
// };

// class FakeDirectLink : Link{
// private:
//     BIO *my_out, *my_in;
//     BIO *peer_out, *peer_in;
// public:
//     FakeDirectLink(BIO* _my_out , BIO* _my_in, BIO* _peer_out, BIO* _peer_in): Link(false){
//         my_out = _my_out; my_in = _my_in;
//         peer_out = _peer_out; peer_in = _peer_in;
//     }
//     void send(const char* buf, int len){
//         BIO_write(peer_in);
        
//     };

//     int recv(char* buf, int maxbuf = MAXBUF){
        
//     }
// };

// class TCPDirectLink : Link{

// };

#endif