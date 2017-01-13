#include <stdio.h>
#include <stdint.h>
#include "../../../mc-sema/common/RegisterState.h"

//extern int demo_entry(int a);
extern void demo_entry(RegState *);
extern void* __mcsema_create_alt_stack(size_t stack_size);
extern void* __mcsema_free_alt_stack(size_t stack_size);


int demo_driver(int a)
{
    RegState        rState;
    unsigned long   stack[4096*10];

    memset(&rState, 0, sizeof(rState));
	memset(&stack, 0, sizeof(stack));

    //set up the stack
    rState.ESP = (uint32_t)&stack[4096*9];
    //rState.EAX = a;

	stack[4096*9 + 1] = a;

    demo_entry(&rState);

    return (int)rState.EAX;
}

int main(int argc, char *argv[])
{
    __mcsema_create_alt_stack(4096*2);
    printf("Result: %d\n", demo_driver(1));
    __mcsema_free_alt_stack(4096*2);
    return 0;
}