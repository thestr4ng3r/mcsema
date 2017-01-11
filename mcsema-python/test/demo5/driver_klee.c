
#include <stddef.h>
#include <string.h>
#include <klee/klee.h>
#include "RegisterState.h"

extern void password_main(RegState *);



/*int doDemo2(int k) {
	RegState            rState = {0};
	unsigned long   stack[4096*10];

	//set up the stack
	rState.RSP = (uint64_t) &stack[4096*9];
	rState.RAX = k;

	demo2_entry(&rState);

	return rState.RAX;
}*/


uint64_t password_driver(int argc, char* argv[])
{
	RegState        rState;
	unsigned long   stack[4096*10];

	memset(&rState, 0, sizeof(rState));

	//set up the stack
	stack[(4096*9)+1] = (uint64_t)argc;
	stack[(4096*9)+2] = (uint64_t)argv;
	rState.RSP = (unsigned long) &stack[4096*9];

	rState.RAX = 42;

	password_main(&rState);

	return rState.RAX;
}


uint64_t password_driver2(int test)
{
	RegState        rState;
	unsigned long   stack[4096*10];

	memset(&rState, 0, sizeof(rState));

	//set up the stack
	//stack[(4096*9)+1] = (uint64_t)argc;
	//stack[(4096*9)+2] = (uint64_t)argv;
	rState.RSP = (unsigned long) &stack[4096*9];

	rState.RAX = test;

	password_main(&rState);

	return rState.RAX;
}


int main(int argc, char *argv[])
{
	/*char pw_value[16];
	klee_make_symbolic(pw_value, sizeof(pw_value), "password");

	int pw_argc = 2;
	char *pw_argv[2] = { argv[0], pw_value };

	int r = password_driver(pw_argc, pw_argv);

	return r;*/



	int test = 42;
	//klee_make_symbolic(&test, sizeof(test), "test");

	password_driver2(test);

	return 0;
}