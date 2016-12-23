
#include <stdio.h>

int fancy_calculation(int a)
{
	return a + 5;
}

void start(void)
{
	int v = fancy_calculation(37);
	printf("calculated %d\n", v);
}