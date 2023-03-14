#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include "server.h"
#include "../common/conf.h"
#include "../common/instruction.h"

int main(int argc, char **argv) {
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];
    SSL_CTX *ctx;

    if (argc != 7) {
        printf("wrong format of arguments, please follow the guidelines on README\n");
        exit(0);
    }

    myport = atoi(argv[1]);

    lisnum = atoi(argv[2]);

    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv3_server_method());
    
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    int valid = SSL_CTX_set_cipher_list(ctx, "ALL");
    if (valid != 1) {
        ERR_print_errors_fp(stdout);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); 
    
    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created\n");

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
            == -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded\n");

    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen\n");


    {
        len = sizeof(struct sockaddr);
        /* 等待客户端连上来 */
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))
                == -1) {
            perror("accept");
            exit(errno);
        } else
            printf("server: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
                    new_fd);
        /* 基于 ctx 产生一个新的 SSL 
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_fd);
        if (SSL_accept(ssl) == -1) {
            perror("accept");
            close(new_fd);
            break;
        }
        */
        T_Server* sev = new T_Server(ctx);
        sev->handshake();
        sev->show_certs();

        int ctrl_fd;
        if ((ctrl_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Socket");
            exit(errno);
        }
        printf("socket created\n");
        struct sockaddr_in dest;

        bzero(&dest, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(atoi(argv[6]));
        if (inet_aton(argv[5], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
            perror(argv[5]);
            exit(errno);
        }
        printf("controller address created\n");

        /* 连接服务器 */
        if (connect(ctrl_fd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
            perror("Connect ");
            exit(errno);
        }
        printf("controller connected\n");

        bzero(buf, MAXBUF + 1);
        strcpy(buf, "server");
        send(ctrl_fd, buf, strlen(buf), 0);

        /* 开始处理每个新连接上的数据收发 */
        bzero(buf, MAXBUF + 1);
        strcpy(buf, "server->client");
        sev->send(buf, strlen(buf));

        bzero(buf, MAXBUF + 1);
        /* 接收客户端的消息 */
        len = sev->recv(buf);
        if (len > 0)
            printf("接收消息成功:'%s'，共%d个字节的数据\n", buf, len);
        else
            printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
            errno, strerror(errno));

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
            printf("Waiting for connection\n");
            len = recv(ctrl_fd, &inst , sizeof(T_Instr), 0);
            // inst = *(T_Instr*)buffer;
            if (len <= 0) {
                printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
                    errno, strerror(errno));
                break;
            }
            printf("Inst is %d, len is %d\n",inst, len);
            bzero(buf, MAXBUF + 1);
            switch (inst){
                case T_Instr::ENCRYPTED_MESSAGE_TO_PEER:{
                int len = recv(ctrl_fd, buf, MAXBUF, 0);
                sev->send(buf, len);
                break;
            }
            case T_Instr::SHUTDOWN_CONNECTION: {
                cont = false;
                break;
            }

            case T_Instr::PLAIN_MESSAGE_TO_PEER: {
                int len = recv(ctrl_fd, buf, MAXBUF, 0);
                sev->plain_send(buf, len);
                break;
            }

            case T_Instr::RECEIVED_PLAIN_TO_ME: {
                sev->recv(buf);
                send(ctrl_fd, sev->get_encrypted_text(), sev->get_encrypted_len(), 0);
                break;
            }

            case T_Instr::RECEIVED_CHECK_VALID: {
                int len = sev->recv(buf);
                bool isValid = (len>0);
                send(ctrl_fd, (char*)&isValid, sizeof(bool), 0);
                break;
            }

                default: break;
            }
        }
        delete sev;
        close(new_fd);
        close(ctrl_fd);
    }
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}