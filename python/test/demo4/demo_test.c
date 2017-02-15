
#include <stdio.h>

int switch_func(int a)
{
	//printf("begin of switch_func\n");

	switch(a)
	{
		case 0:
			printf("42\n");
			//return 42;
			break;
		case 1:
			printf("1337\n");
			//return 1337;
			break;
		case 2:
			printf("-1\n");
			//return -1;
			break;
		case 3:
			printf("1233\n");
			//return 1233;
			break;
		case 4:
			printf("3453\n");
			//return 3453;
			break;
		case 5:
			printf("4563\n");
			//return 4563;
			break;
		case 6:
			printf("-45656");
			//return -45656;
			break;
		case 7:
			printf("4563");
			//return 4563;
			break;
		default:
			//return 1234;
			break;
	}

	printf("end of switch_func\n");

	return 12345;
}