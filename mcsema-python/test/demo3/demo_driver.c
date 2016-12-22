#include <stdio.h>

extern int demo_entry(int a);
extern void* __mcsema_create_alt_stack(size_t stack_size);
extern void* __mcsema_free_alt_stack(size_t stack_size);

int main(int argc, char *argv[])
{
    __mcsema_create_alt_stack(4096*2);
    printf("Result: %d\n", demo_entry(1));
    __mcsema_free_alt_stack(4096*2);
    return 0;
}