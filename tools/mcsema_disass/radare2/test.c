
int offset_func(int a)
{
	return a * 3;
}

int vermillion(int a)
{
	return a + 1;
}

int core(int a, int b)
{
	if(a < b)
	{
		return vermillion(a);
	}
	else if(b < a)
	{
		return vermillion(b);
	}

	return 42;
}

int main(void)
{
	core(10, 15);
	return 0;
}