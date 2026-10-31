/* A static PIE program that init runs with execve. It checks its arguments and exits with 7.
 * With the argument "personality", it exits with 8 if its personality has ADDR_NO_RANDOMIZE and
 * with 9 if not. */
#include <string.h>
#include <sys/personality.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "personality") == 0)
		return personality(0xffffffff) & ADDR_NO_RANDOMIZE ? 8 : 9;
	static const char msg[] = "hello: static pie runs\n";
	if (argc != 2 || strcmp(argv[1], "arg") != 0)
		return 1;
	write(1, msg, sizeof(msg) - 1);
	return 7;
}
