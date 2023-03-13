#ifndef _TLSTEST_CONTROLLER
#define _TLSTEST_CONTROLLER
#include "../common/instruction.h"
#include "../common/ctrl_link.h"
#include <stdio.h>

class T_Controller{
private:
    char* server_buf;
    char* client_buf;
    CtrlLink *sev_lk, *cli_lk;
public:
   T_Controller(CtrlLink* _sev_lk, CtrlLink* _cli_lk);
   void send_client_instruction(T_Instr ins, const char* buf, int len);
   void send_server_instruction(T_Instr ins, const char* buf, int len);

   int recv_client_message(char* buf);
   int recv_server_message(char* buf);
};

#endif