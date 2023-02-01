#ifndef _TLSTEST_COMMON_INSTRUCTION
#define _TLSTEST_COMMON_INSTRUCTION

enum T_Instr{
    ENCRYPTED_MESSAGE_TO_PEER,
    PLAIN_MESSAGE_TO_PEER,
    SHUTDOWN_CONNECTION,
    RECEIVED_PLAIN_TO_ME,
};

#endif