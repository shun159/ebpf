//go:build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
	u8 comm[80];
};

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 1 << 24);
} user_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} kernel_ringbuf SEC(".maps");


static long
handle_msg(struct bpf_dynptr *dynptr, void *context)
{
    bpf_printk("handle_msg received");
	return 0;
}

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx)
{
    long status;
	u64 id   = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct event *task_info;

    // send task info to userspece program
	task_info = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(struct event), 0);
	if (!task_info) {
		return 0;
	}
	task_info->pid = tgid;
	bpf_get_current_comm(&task_info->comm, 80);
	bpf_ringbuf_submit(task_info, 0);

    // receive something from userspece program
	status = bpf_user_ringbuf_drain(&user_ringbuf, handle_msg, NULL, 0);
	if (status < 0) {
		return 0;
	}

	return 0;
}
