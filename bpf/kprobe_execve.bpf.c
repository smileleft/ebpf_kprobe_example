#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";

// 이벤트 데이터를 사용자 공간으로 보내기 위한 맵
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// 이벤트 데이터 구조체 (사용자 공간으로 전달될 정보)
struct event {
    //pid_t pid;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[256]; // execve의 첫 번째 인자 (경로)
};

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(sys_execve_entry, const char *filename, const char *const argv[], const char *const envp[])
{
    __u64 id;
    int ret;

    // init event struct
    struct event event_data = {};

    // get PID
    id = bpf_get_current_pid_tgid();
    event_data.pid = id >> 32;

    // get current process name
    bpf_get_current_comm(&event_data.comm, sizeof(event_data.comm));

    // get execution filename
    ret = bpf_probe_read_user_str(&event_data.filename, sizeof(event_data.filename), filename);
    if (ret < 0) {
        //memcpy(event_data.filename, "<failed>", sizeof("<failed>"));
	bpf_printk("Failed to read filename: %d\n", ret);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));
    return 0;

}
