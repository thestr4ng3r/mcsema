
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RegisterState.h"

#ifdef DEMO_KLEE
#include <klee/klee.h>
#endif


char password[] = "stBjdZAUz0L12TDxENstpw==";
//char password[25] = "thisisthepassword.......";

char *_fgets(char *s, int size, FILE *stream)
{
	printf("Called fgets %ld %d %ld\n", (unsigned long)s, size, (unsigned long)stream);

#ifdef DEMO_KLEE
	klee_make_symbolic(password, sizeof(password), "password");
#endif

	memcpy(s, password, sizeof(password));
	//return fgets(s, size, stream);

	return s;
}


int _puts(const char *s)
{
	return puts(s);
}

void _free(void *ptr)
{
	printf("free");
	free(ptr);
}

void *_malloc(size_t size)
{
	printf("malloc %ld\n", size);
	return malloc(size);
}

void *_memcpy(void *dest, const void *src, size_t n)
{
	printf("memcpy %ld\n", n);
	return memcpy(dest, src, n);
}

void _exit(int status)
{
	printf("Exit with status %d\n", status);
	exit(status);
}

unsigned char pw_bin[] = { 0xb2, 0xd0, 0x63, 0x75,
						   0x90, 0x14, 0xcf, 0x42,
						   0xf5, 0xd9, 0x30, 0xf1,
						   0x10, 0xdb, 0x2d, 0xa7 };

void b64d(RegState *reg_state)
{
	char *b64_str = (char *)reg_state->RDI;
	unsigned char **out_buf = (unsigned char **)reg_state->RSI;

	printf("b64d %s\n", b64_str);

	unsigned char *buf = (unsigned char *)malloc(16);
	memcpy(buf, pw_bin, 16);
	(*out_buf) = buf;

	//reg_state->RSP -= 8;

	int ret = 16;
	reg_state->RAX = (unsigned long)ret;
}



#define qual_main_raw sub_40079f

extern void qual_main_raw(RegState *);

unsigned long stack[4096*10];
RegState reg_state;

int main_driver(int argc, char **argv)
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



void hexDump (char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf ("%s:\n", desc);

	if (len == 0) {
		printf("  ZERO LENGTH\n");
		return;
	}
	if (len < 0) {
		printf("  NEGATIVE LENGTH: %i\n",len);
		return;
	}

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0)
				printf ("  %s\n", buff);

			// Output the offset.
			printf ("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf (" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf ("   ");
		i++;
	}

	// And print the final ASCII bit.
	printf ("  %s\n", buff);
}


extern void b64d_original(RegState *reg_state);

void b64d_original_test()
{
	unsigned char *buf = 0;

	memset(&stack, 0, sizeof(stack));
	memset(&reg_state, 0, sizeof(reg_state));

	reg_state.RBP = 0;
	reg_state.RSP = (unsigned long)&stack[4096*9];

	printf("rsp %ld\n", reg_state.RSP);

	reg_state.RDI = (unsigned long)password;
	reg_state.RSI = (unsigned long)&buf;

	b64d_original(&reg_state);

	int len = (int)reg_state.RAX;

	printf("decoded %d to %ld\n", len, buf);

	printf("rsp %ld\n", reg_state.RSP);

	hexDump(0, reg_state.RSP, 8);

	hexDump(0, buf, len);
}

int main(int argc, char **argv)
{
	//return main_driver(argc, argv);

	b64d_original_test();
	return 0;
}