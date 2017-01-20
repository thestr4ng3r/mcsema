
#include <stdio.h>

int fancy_calculation(int a)
{
	return a + 5;
}

void test_fancy(void)
{
	int v = fancy_calculation(37);
	printf("calculated %d\n", v);
}