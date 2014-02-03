/*
 * Demostrate usage of talloc with simple structure.
 * - try valgrind
 * - compile with -ltalloc
 */

#include <stdio.h>
#include <stdlib.h>
#include "talloc.h"

struct user {
	uid_t uid;
	char *username;
	size_t num_groups;
	char **groups;
};

int main(int argc, char *argv[])
{

	// create new top level context (because of NULL)
	struct user *user = talloc(NULL, struct user);
	if (user == NULL) {
		printf("talloc () error\n");
		return -1;
	}

	user->uid = 1000;
	user->num_groups = 1;

	// make user the parent of the username and groups contexts
	user->username = talloc_strdup(user, "test user");
	user->groups = talloc_array(user, char *, user->num_groups);

	// make user the parent of the groups array contexts
	int i;
	for (i = 0; i < user->num_groups; i++) {
		user->groups[i] = talloc_asprintf(user->groups, "Test group %d", i);
	}

	// free entire structure
	talloc_free(user);
	return 0;
}

