#include <stdio.h>
#include "talloc.h"

int main(int argc, char *argv[])
{

	// create new top level context (because of NULL)
	int *i = talloc(NULL, int);

	int *p_i;
	if ((p_i = talloc_get_type(i, int)) == NULL)
		printf("i is not int\n");
	else
		printf("i = %d\n", *p_i);

	// free talloc context
	talloc_free(i);
	return 0;
}

