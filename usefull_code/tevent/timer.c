/*
 * Tevent which will be repeated for a minute with interval of 2 seconds (will
 * be triggered 30 times). After exceeding this limit, the event loop will
 * finish and all the memory resources will be freed.
 */
#include <stdio.h>
#include <unistd.h>
#include <tevent.h>
#include <sys/time.h>

struct state {
	struct timeval endtime;
	/* var couter is only used for counting the number of triggered functions */
	int counter;
	TALLOC_CTX *ctx;
};

static void callback(	struct tevent_context *ev, 
											struct tevent_timer *tim,
											struct timeval current_time, 
											void *private_data)
{
	struct state *data = talloc_get_type(private_data, struct state);
	struct tevent_timer *time_event;
	struct timeval schedule;
	
	printf("Data value: %d\n", data->counter);
	data->counter += 1; // increase counter

	// if time has not reached its limit, set another event
	if (tevent_timeval_compare(&current_time, &(data->endtime)) < 0) {
		// do something
		// set repeat with delay 2 seconds
		schedule = tevent_timeval_current_ofs(2, 0);

		time_event = tevent_add_timer(ev, data->ctx, schedule, callback, data);
		if (time_event == NULL) { // error ...
			fprintf(stderr, "MEMORY PROBLEM\n");
		return;
	}
	} else {
	// time limit exceeded
	}
}

int main(void) {
	// pointer to talloc context
	TALLOC_CTX *mem_ctx;

	struct tevent_context *event_ctx;		// pointer to tevent context
	struct tevent_timer *time_event;
	struct timeval schedule;

	// parent - top level context
	mem_ctx = talloc_new(NULL); 
	event_ctx = tevent_context_init(mem_ctx);

	// allocate new structure and put into talloc tree - child of mem_ctx
	struct state *data = talloc(mem_ctx, struct state);

	schedule = tevent_timeval_current_ofs(2, 0); // +2 second time value
	data->endtime = tevent_timeval_add(&schedule, 10, 0); // one minute time limit
	data->ctx = mem_ctx;
	data->counter = 0;

	// add time event
	// callback - function to call on event
	time_event = tevent_add_timer(event_ctx, mem_ctx, schedule, callback, data);
	if (time_event == NULL) {
		fprintf(stderr, "FAILED\n");
		return EXIT_FAILURE;
	}

	tevent_loop_wait(event_ctx);
	talloc_free(mem_ctx);
	return EXIT_SUCCESS;
}


