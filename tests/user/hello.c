/* A static PIE program that init runs with execve. It checks its arguments and exits with 7. */
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	static const char msg[] = "hello: static pie runs\n";
	if (argc != 2 || strcmp(argv[1], "arg") != 0)
		return 1;
	write(1, msg, sizeof(msg) - 1);
	return 7;
}
