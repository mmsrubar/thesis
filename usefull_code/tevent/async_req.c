/*
 * Tevent which will be repeated for a minute with interval of 2 seconds (will
 * be triggered 30 times). After exceeding this limit, the event loop will
 * finish and all the memory resources will be freed.
 *
 * gcc -ltevent -ltalloc
 */
#include <stdio.h>
#include <unistd.h>
#include <tevent.h>
#include <sys/time.h>

/*
 * Callback can obtain two kind of data.
 */
static void my_print(struct tevent_req *req) {

	// get data that are bind with the request event
	int *event_data = tevent_req_data(req, int);
	printf("Event's private data:\t\t%d\n", *event_data);

	// get data that was given to the callback 
	void *c_data = tevent_req_callback_data_void(req);
	printf("Callback's private data:\t%s\n", (char *) c_data);
}

int main(void) {
	
	TALLOC_CTX *mem_ctx;						// pointer to talloc context
	struct tevent_context *ctx;			// pointer to tevent context
	struct tevent_req *event_req;		// pointer to tevent request
	int *event_data;								// pointer to private request data
	char *callback_data = "callback's data"; // pointer to a data

	// parent - top level talloc context
	mem_ctx = talloc_new(NULL); 
	if (mem_ctx == NULL) {
		fprintf(stderr, "Not enough memory.\n");
		return -1;
	}
	
	ctx = tevent_context_init(mem_ctx);

	// this also allocate memory for private request's data 
	event_req = tevent_req_create(mem_ctx, &event_data, int);
	if (event_req == NULL) {
		fprintf(stderr, "Error while creating tevent request.\n");
		return -1;
	}

	// set private request's data
	*event_data = 312;

	// bind a callback to a asynchronous request
	tevent_req_set_callback(event_req, my_print, callback_data);

	// mark request af finished immediatly
	//tevent_req_done(event_req);

	// mark request as finished after 1s
	tevent_req_set_endtime(event_req, ctx, tevent_timeval_current_ofs(1, 0));

	tevent_loop_wait(ctx);
	talloc_free(mem_ctx);
	return EXIT_SUCCESS;
}


