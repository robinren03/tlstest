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
#include "../common/conf.h"
#include "../common/instruction.h"

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char buffer[MAXBUF + 1];
    SSL_CTX *ctx;

    if (argc != 5) {
        printf("wrong format of arguments, please follow the guidelines on README\n");
        exit(0);
    }

    /* SSL 库初始化，参看 ssl-server.c 代码 */
    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv3_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    
    int valid = SSL_CTX_set_cipher_list(ctx, "DES-CBC-SHA:DES-CBC3-SHA:IDEA-CBC-SHA");
    if (valid != 1) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); 


    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected\n");
    
    T_Client* cli = new T_Client(ctx);
    cli->set_tcplink_fd(sockfd);
    cli->handshake();
    
    /* build a new ssl based on ctx
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) == -1)
        ERR_print_errors_fp(stderr);
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
    }
    */

    int ctrl_fd;
    if ((ctrl_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created\n");

    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[4]));
    if (inet_aton(argv[3], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[3]);
        exit(errno);
    }
    printf("controller address created\n");

    /* 连接服务器 */
    if (connect(ctrl_fd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("controller connected\n");

    bzero(buffer, MAXBUF + 1);
    strcpy(buffer, "client");
    send(ctrl_fd, buffer, strlen(buffer), 0);

    /* 接收对方发过来的消息，最多接收 MAXBUF 个字节 */
    bzero(buffer, MAXBUF + 1);
    /* 接收服务器来的消息 */
    len = cli->client_recv(buffer);
    if (len > 0)
        printf("接收消息成功:'%s'，共%d个字节的数据\n",
               buffer, len);
    else {
        printf
            ("消息接收失败！错误代码是%d，错误信息是'%s'\n",
             errno, strerror(errno));
    }
    
    bzero(buffer, MAXBUF + 1);
    strcpy(buffer, "from client->server");
    /* 发消息给服务器 */
    cli->client_send(buffer, strlen(buffer));
    if (len < 0)
        printf
            ("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
             buffer, errno, strerror(errno));
    else
        printf("消息'%s'发送成功，共发送了%d个字节！\n",
               buffer, len);
       
    T_Instr inst;
    len = recv(ctrl_fd, &inst, sizeof(T_Instr), 0);
    if (len > 0)
        printf("接收消息成功:'%d'，共%d个字节的数据\n", inst, len);
    else
        printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
        errno, strerror(errno));
    
    bool cont = true;
    while(cont){
        T_Instr inst;
        len = recv(ctrl_fd, &inst , sizeof(T_Instr), 0);
        // inst = *(T_Instr*)buffer;
        if (len <= 0) {
            printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
                errno, strerror(errno));
            break;
        }
        printf("Inst is %d, len is %d\n",inst, len);
        bzero(buffer, MAXBUF + 1);
        switch (inst){
            case T_Instr::ENCRYPTED_MESSAGE_TO_PEER:{
                int len = recv(ctrl_fd, buffer, MAXBUF, 0);
                cli->client_send(buffer, len);
                break;
            }
            case T_Instr::SHUTDOWN_CONNECTION: {
                cont = false;
                break;
            }

            case T_Instr::PLAIN_MESSAGE_TO_PEER: {
                int len = recv(ctrl_fd, buffer, MAXBUF, 0);
                cli->plain_send(buffer, len);
                break;
            }

            case T_Instr::RECEIVED_PLAIN_TO_ME: {
                cli->client_recv(buffer);
                send(ctrl_fd, cli->get_encrypted_text(), cli->get_encrypted_len(), 0);
                break;
            }

            case T_Instr::RECEIVED_CHECK_VALID: {
                int len = cli->client_recv(buffer);
                bool isValid = (len>0);
                send(ctrl_fd, (char*)&isValid, sizeof(bool), 0);
                break;
            }
            default: break;
        }
    }
    /* 关闭连接 */
    delete cli;
    close(sockfd);
    close(ctrl_fd);
    SSL_CTX_free(ctx);
    return 0;
}