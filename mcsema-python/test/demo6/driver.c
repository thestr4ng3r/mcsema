
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RegisterState.h"

#ifdef DEMO_KLEE
#include <klee/klee.h>
#endif

unsigned long stack[4096*10];
RegState reg_state;


char password[25] = "thisistheinputstring....";

char *_fgets(char *s, int size, FILE *stream)
{
	reg_state.RSP += 8;
	printf("Skipping fgets with stub data.\n");
	strcpy(s, password);
	return s;
}

int _puts(const char *s)
{
	reg_state.RSP += 8;
	return puts(s);
}

void _free(void *ptr)
{
	reg_state.RSP += 8;
	free(ptr);
}

void *_malloc(size_t size)
{
	reg_state.RSP += 8;
	return malloc(size);
}

void *_memcpy(void *dest, const void *src, size_t n)
{
	reg_state.RSP += 8;
	return memcpy(dest, src, n);
}

void _exit(int status)
{
	reg_state.RSP += 8;
	exit(status);
}

extern void b64d(RegState *reg_state);

void b64d_fake(RegState *reg_state)
{
	reg_state->RSP += 8;
	char *b64_str = (char *)reg_state->RDI;
	unsigned char **out_buf = (unsigned char **)reg_state->RSI;

	unsigned char *buf = (unsigned char *)malloc(16);
#ifdef DEMO_KLEE
	klee_make_symbolic(buf, 16, "password");
#else
	memset(buf, 0, 16);
#endif
	(*out_buf) = buf;

	int ret = 16;
	reg_state->RAX = (unsigned long)ret;
}



#define qual_main_raw sub_40079f
extern void qual_main_raw(RegState *);

int qual_main_driver(int argc, char **argv)
{
	memset(&stack, 0, sizeof(stack));
	memset(&reg_state, 0, sizeof(reg_state));

	reg_state.RBP = 0;
	reg_state.RSP = (unsigned long)&stack[4096*9];

	reg_state.RDI = (unsigned long)argc;
	reg_state.RSI = (unsigned long)argv;

	qual_main_raw(&reg_state);

	return (int)reg_state.RAX;
}


int main(int argc, char **argv)
{
	return qual_main_driver(argc, argv);
}