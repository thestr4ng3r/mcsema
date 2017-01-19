
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