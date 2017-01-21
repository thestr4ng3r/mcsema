
#include <stdio.h>
#include <stdlib.h>

int blackest_eyes(int a)
{
	return a * 7;
}

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		printf("Usage: %s [number]\n", argv[0]);
		return 1;
	}

	int a = atoi(argv[1]);
	a = blackest_eyes(a);

	printf("The result is %d.\n", a);
	return 0;
}