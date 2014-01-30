/*
 * Stealing context.
 */
#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>

int main(int argc, char *argv[])
{

	int *root_a = talloc(NULL, int);
	int *root_b = talloc(NULL, int);

	int *child = talloc(root_a, int);

	// change the parent of child to root_b
	talloc_steal(root_b, child);

	talloc_free(root_a);
	talloc_free(root_b);
	return 0;
}

