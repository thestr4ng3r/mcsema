#include <stdio.h>

extern int demo_entry(int a);

int main(int argc, char *argv[])
{
    printf("Result: %d\n", demo_entry(37));
    return 0;
}
