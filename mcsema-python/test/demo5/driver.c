
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "RegisterState.h"

#ifdef DEMO_KLEE
#include <klee/klee.h>
#endif


#define password_raw sub_4004e0

extern void password_raw(RegState *);

unsigned long stack[4096*10];
RegState reg_state;

int password_driver(int a)
{
	memset(&reg_state, 0, sizeof(reg_state));

	reg_state.RBP = 0;
	reg_state.RSP = (unsigned long)&stack[4096*9];

	reg_state.RDI = (unsigned long)a;

	password_raw(&reg_state);

	return (int)reg_state.RAX;
}


int main(int argc, char *argv[])
{
	/*char pw_value[16];
	klee_make_symbolic(pw_value, sizeof(pw_value), "password");

	int pw_argc = 2;
	char *pw_argv[2] = { argv[0], pw_value };

	int r = password_driver(pw_argc, pw_argv);

	return r;*/

	int pw;

#ifndef DEMO_KLEE
	if(argc != 2)
	{
		printf("usage: %s [password number]\n", argv[0]);
		return 1;
	}

	pw = atoi(argv[1]);
#else
	klee_make_symbolic(&pw, sizeof(pw), "password");
#endif

	int result = password_driver(pw);

	if(result == 1)
	{
		printf("Correct.\n");
	}
	else
	{
		printf("Wrong.\n");
	}

	return 0;
}