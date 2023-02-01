#ifndef _TLSTEST_CONTROLLER
#define _TLSTEST_CONTROLLER
#include "../common/instruction.h"
#include <stdio.h>

class T_Controller{
private:
    char* server_buf;
    char* client_buf;
    int server_fd; // the socket file number
    int client_fd; // the client file number
public:
   T_Controller(int _server_fd, int _client_fd);
   void send_client_instruction(T_Instr ins, const char* buf, int len);
   void send_server_instruction(T_Instr ins, const char* buf, int len);

   int recv_client_message(char* buf);
   int recv_server_message(char* buf);
};

#endif