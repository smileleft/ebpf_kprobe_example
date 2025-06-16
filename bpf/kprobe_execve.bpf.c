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
    pid_t pid;
    char comm[TASK_COMM_LEN];
    char filename[256]; // execve의 첫 번째 인자 (경로)
};

SEC("kprobe/sys_execve")
int BPF_KPROBE(sys_execve_entry, const char *filename, const char *const argv[], const char *const envp[])
{
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    
    // filename 인자를 안전하게 복사
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
