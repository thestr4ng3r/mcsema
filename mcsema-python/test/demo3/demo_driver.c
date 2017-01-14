#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

extern int switch_func(int a);

int main(int argc, char *argv[])
{
	int a = 1;
	if(argc > 1)
	{
		a = atoi(argv[1]);
	}

    printf("Result: %d\n", switch_func(a));

    return 0;
}