#include <stdio.h>
#include <string.h>
#include <talloc.h>

int main(int argc, char *argv[])
{
	// strdup returns pointer to a first char of the string
	char *str = strdup("I am NOT a talloc context");
	// free can free only memory returned by malloc
	free(str);

	char *str2 = talloc_strdup(NULL, "I AM a talloc context");
	talloc_free(str2);

	return 0;
}

