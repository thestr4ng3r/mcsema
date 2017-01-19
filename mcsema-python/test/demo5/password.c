
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>


int password(int a)
{
	if(a == 42)
		return 1;

	return 0;
}


#define rotl64(value, n) (value << n | (value >> (64 - n)))
#define rotr64(value, n) (value >> n | (value << (64 - n)))

const uint32_t stuff[4] = { 0xdeadbeef, 0x1337f000, 0x42424242, 0x00c0ffee };

int main(int argc, char *argv[])
{
	uint32_t pw[4];
	memcpy(pw, argv[1], 4*4);

	uint64_t rcx = 0;
	uint64_t rsi = 0;
	uint64_t rdi = 0;
	uint64_t rdx = 0;

	int i;
	for(i = 0; i < 4; i++)
	{
		rcx = rotl64(rcx, 0xd);
		rcx ^= pw[i];
		rcx += (uint64_t)stuff[i];

		rsi = rotr64(rsi, 0xd);
		rsi ^= pw[i];
		rsi -= (uint64_t)stuff[i];

		rdi = rotr64(rdi, 0x13);
		rdi ^= pw[i];
		rdi += ((uint64_t) stuff[i] << 32);

		rdx = rotl64(rdx, 0x13);
		rdx ^= pw[i];
		rdx -= ((uint64_t) stuff[i] << 32);
	}

	if(rcx == 0xa19dafc056c3ba8
	   && rsi == 0x9f344823201abf5c
	   && rdi == 0x4dabf41f9d50bc19
	   && rdx == 0xc4af094d3c696e8f)
	{
		printf("correct\n");
		return 0;
	}
	else
	{
		printf("wrong\n");
		return 1;
	}
}
