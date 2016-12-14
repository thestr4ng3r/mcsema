
#include <stdio.h>
#include <string.h>

void check_pw(char *s)
{
	if(strcmp(s, "password") == 0)
	{
		printf("Correct.\n");
	}
	else
	{
		printf("Wrong.\n");
	}

}

int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		printf("Wrong parameter count.\n");
		return 1;
	}

	check_pw(argv[1]);

	return 0;
}

int test_entry()
{
	check_pw("djkfls");
	return 42;
}
