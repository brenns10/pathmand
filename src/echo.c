/* MPTCP Path Manager which simply echoes the messages.
 * Stephen Brennan
 */
#include <stdio.h>

void created(void)
{
	printf("created\n");
}

void established(void)
{
	printf("established\n");
}

void closed(void)
{
	printf("closed\n");
}

void announced(void)
{
	printf("announced\n");
}

void removed(void)
{
	printf("removed\n");
}

void sub_created(void)
{
	printf("sub_created\n");
}

void sub_established(void)
{
	printf("sub_established\n");
}

void sub_closed(void)
{
	printf("sub_closed\n");
}

void sub_priority(void)
{
	printf("sub_priority\n");
}

void sub_error(void)
{
	printf("sub_error\n");
}

void init_path_manager(void)
{
	printf("init echo.c path manager\n");
}

void exit_path_manager(void)
{
	printf("exit echo.c path manager\n");
}
