/*
This is a basic implementation of the BEAST attack discovered by TBD in 2010.
Our current implementation only support to discover the first block_size bits
of encrypted information while with a little more improvements, we can infer
more information through this.
*/
#ifndef _TLSTEST_DOWNGRADE
#define _TLSTEST_DOWNGRADE
#include <cstring>
#include <iostream>
#include "controller.h"
#include "../common/version.h"

class DownGrader{
private:
    T_Controller* ctrl;

public:
    DownGrader(int max_len, int _block_size, T_Controller* _ctrl);
    
    ~DownGrader(){
    }
    
    bool run(P_Version old, P_Version neo);

};

#endif
