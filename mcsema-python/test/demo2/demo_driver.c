#include <stdio.h>

//extern int demo_entry(int a);

extern int fancy_calculation(int a);

int main(int argc, char *argv[])
{
    //printf("Result: %d\n", demo_entry(37));
    printf("Result: %d\n", fancy_calculation(37));
    return 0;
}
