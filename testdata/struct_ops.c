#include "common.h"

#include "struct_ops.h"

char __license[] __section("license") = "GPL";

__section("struct_ops/dummy_test_1") int dummy_test_1(void *arg) {
	return 0;
}

__section(".struct_ops.link") struct bpf_testmod_st_ops dummy_ops = {
	.test_prologue = (void *)dummy_test_1,
};
