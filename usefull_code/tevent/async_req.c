/*
 * Tevent which will be repeated for a minute with interval of 2 seconds (will
 * be triggered 30 times). After exceeding this limit, the event loop will
 * finish and all the memory resources will be freed.
 *
 * Naming convencions:
 * foo_send(...) - funciton that creates request and sets callback
 * foo_done(...) - 
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

int foo_send(TALLOC_CTX *mem_ctx, struct tevent_req **req) {
	int *event_data;													// pointer to private request data
	char *callback_data = "callback's data"; 	// pointer to a data

	// this also allocate memory for private request's data 
	*req = tevent_req_create(mem_ctx, &event_data, int);
	if (*req == NULL) {
		fprintf(stderr, "Error while creating tevent request.\n");
		return -1;
	}

	// set private request's data
	*event_data = 312;

	// bind a callback to a asynchronous request
	tevent_req_set_callback(*req, my_print, callback_data);

	return 0;
}

int foo_done(TALLOC_CTX *mem_ctx, struct tevent_req **req) {
	// do some computation with data
	printf("prg> doing an event computation\n");

	// set event as successful
	// This sets the request as TEVENT_REQ_DONE
	tevent_req_done(*req);

	// request can end up being unsuccessful
	// It sets TEVENT_REQ_USER_ERROR
	// tevent_req_error(*req, 
}

int main(void) {
	
	TALLOC_CTX *mem_ctx;						// pointer to talloc context
	struct tevent_context *ctx;			// pointer to tevent context
	struct tevent_req *event_req;		// pointer to tevent request

	// parent - top level talloc context
	mem_ctx = talloc_new(NULL); 
	if (mem_ctx == NULL) {
		fprintf(stderr, "Not enough memory.\n");
		return -1;
	}
	
	ctx = tevent_context_init(mem_ctx);

	// create tevent request, set callback and continue
	if (foo_send(mem_ctx, &event_req) != 0) {
		return -1;
	}

	printf("prg> I've created tevent request and now I continue.\n");

	/******************************************************************************
	 * A FEW EXAMPLES OF FINISHIN REQUEST
	/*****************************************************************************/
	// mark request af finished immediatly
	foo_done(mem_ctx, &event_req);

	// mark request as finished after 1s
	//tevent_req_set_endtime(event_req, ctx, tevent_timeval_current_ofs(1, 0));

	tevent_loop_wait(ctx);
	talloc_free(mem_ctx);
	return EXIT_SUCCESS;
}


