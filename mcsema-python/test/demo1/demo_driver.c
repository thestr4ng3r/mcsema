#include <stdio.h>
#include <string.h>

#include "../../../mc-sema/common/RegisterState.h"

extern void demo_entry(RegState *);

unsigned long getNextPC(void)
{
    return 0;
}

int doDemo1(int k)
{
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));

    //set up the stack 
    rState.ESP = (unsigned long) &stack[4096*9];
    rState.EAX = k;

    demo_entry(&rState);

    return rState.EAX;
}


int main(int argc, char *argv[]) {

    int k = doDemo1(12);

    printf("%d -> %d\n", 12, k);

	return 0;
}

/*
extern int demo_entry(int a);

int main(int argc, char *argv[])
{
    printf("Result: %d\n", demo_entry(41));

    return 0;
}
*/