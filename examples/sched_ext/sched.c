//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("struct_ops.s/null_init")
int null_sched_init(void) {
	bpf_printk("null scheduler running\n");
	return 0;
};

SEC(".struct_ops.link")
struct sched_ext_ops null_sched = {
	.init       = (void *)null_sched_init,
	.timeout_ms = 10000U,
	.name       = "null_sched",
};
