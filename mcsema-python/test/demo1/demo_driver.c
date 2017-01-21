#include <stdio.h>
#include <string.h>

#include "../../../mc-sema/common/RegisterState.h"

#define add_one_raw sub_8000001
extern void add_one_raw(RegState *);

int add_one_driver(int v)
{
    RegState        reg_state;
    unsigned long   stack[4096*10];

    memset(&reg_state, 0, sizeof(reg_state));

    reg_state.ESP = (unsigned long)&stack[4096*9];
    reg_state.EAX = v;

    add_one_raw(&reg_state);

    return reg_state.EAX;
}


int main(int argc, char *argv[])
{
    int a = add_one_driver(12);
    printf("%d -> %d\n", 12, a);
	return 0;
}