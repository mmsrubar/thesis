/*
 * Show hierarchy.
 */
#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>

int main(int argc, char *argv[])
{

	int *i = talloc(NULL, int);
	int *j = talloc(i, int);
	printf("i: %d\n", *i);
	printf("j: %d\n", *j);


	// it frees only j variable
	// talloc_free(j);
	
	// free i and also j variable because j is j's parrent
	talloc_free(i);
	return 0;
}

