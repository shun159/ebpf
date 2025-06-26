#include "common.h"

#include "struct_ops.h"

struct bpf_testmod_ops2 {
	int (*test_1)(void);
};

struct bpf_testmod_ops3 {
	int (*test_1)(void);
	int (*test_2)(void);
};

char __license[] __section("license") = "GPL";

__section("struct_ops/dummy_test_1") int dummy_test_1(void) {
	return 0;
}

__section("struct_ops/dummy_test_1") int dummy_test_2(void) {
	return 0;
}

__section(".struct_ops.link") struct bpf_testmod_ops2 dummy_ops_1 = {
	.test_1 = (void *)dummy_test_1,
};
__section(".struct_ops.link") struct bpf_testmod_ops3 dummy_ops_2 = {
	.test_1 = (void *)dummy_test_1,
	.test_2 = (void *)dummy_test_2,
};
