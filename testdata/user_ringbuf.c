#include "common.h"

char _license[] __section("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 4096);
} user_ringbuf __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} kernel_ringbuf __section(".maps");

#define NULL ((void *)0)

struct test_data {
	char data1;
	char pad[15];
};

static void *(*bpf_dynptr_data)(const void *ptr, uint32_t offset, uint32_t len) = (void *)203;

static long (*bpf_user_ringbuf_drain)(const void *map, const void *cb_fn, const void *cb_ctx, uint64_t flags) = (void *)209;

static void *(*bpf_ringbuf_reserve)(void *ringbuf, uint64_t size, uint64_t flags) = (void *)131;

static void (*bpf_ringbuf_submit)(void *data, uint64_t flags) = (void *)132;

static long test_cb(void *dynptr, void *context) {
	struct test_data *msg1 = NULL;
	struct test_data *msg2 = NULL;

	msg1 = bpf_dynptr_data(dynptr, 0, sizeof(*msg1));
	if (!msg1)
		return 0;

	msg2 = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*msg2), 0);
	if (!msg2)
		return 1;

	msg2->data1 = msg1->data1 + 1;

	bpf_ringbuf_submit(msg2, 0);

	return 0;
}

__section("xdp") int test_user_ringbuf() {
	long status = 0;

	status = bpf_user_ringbuf_drain(&user_ringbuf, test_cb, NULL, 0);
	if (status <= 0)
		return 1;

	return 0;
}
