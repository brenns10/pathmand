/* MPTCP Path Manager which simply echoes the messages.
 * Stephen Brennan
 */
#include <stdio.h>

void new_connection(void)
{
	printf("new_connection\n");
}

void new_addr(void)
{
	printf("new_addr\n");
}

void join_attempt(void)
{
	printf("join_attempt\n");
}

void new_subflow(void)
{
	printf("new_subflow\n");
}

void subflow_closed(void)
{
	printf("subflow_closed\n");
}

void conn_closed(void)
{
	printf("conn_closed\n");
}

void init_path_manager(void)
{
	printf("init echo.c path manager\n");
}

void exit_path_manager(void)
{
	printf("exit echo.c path manager\n");
}
