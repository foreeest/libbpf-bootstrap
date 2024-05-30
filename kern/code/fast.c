#include <net/if.h>
// if_nametoindex

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <sys/resource.h>
#include <asm-generic/posix_types.h>
#include <linux/if_link.h>
#include <linux/limits.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
//0513
#include "fast.skel.h"
#include "fast_common.h"

//#define BPF_SYSFS_ROOT "/sys/fs/bpf"


__u32 xdp_flags = 0;
int *interfaces_idx;
int interface_count = 0;
static int nr_cpus = 0;

void parse_cmdline(int argc, char *argv[]) {
	interface_count = argc - optind; // 网络接口数量 2 - 1 = 1，就是ens1f1np1
	if (interface_count <= 0) {
		fprintf(stderr, "Missing at least one required interface index\n");
		exit(EXIT_FAILURE);
	}

	interfaces_idx = calloc(sizeof(int), interface_count);
	if (interfaces_idx == NULL) {
		fprintf(stderr, "Error: failed to allocate memory\n");
		exit(1); // return 1;
	}

	for (int i = 0; i < interface_count && optind < argc; i++) {
		interfaces_idx[i] = if_nametoindex(argv[optind + i]);
	}

	// asd123www: XDP_FLAGS_DRV_MODE not supported! use XDP_FLAGS_SKB_MODE.
	xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;// TYPE对应一些FLAGS
	// IF_NOEXIT 内核只在当前没XDP程序时attach  以Driver 模式加载//
	nr_cpus = libbpf_num_possible_cpus();// libbpf提供 获取cpu数量
	// libbpf手册：https://libbpf.readthedocs.io/en/latest/api.html
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}


int main(int argc, char *argv[]) {

	struct fast_bpf* skel;
	struct bpf_xdp_attach_opts *xdp_opts;
	int err;
	bool hook_created = false;

	parse_cmdline(argc, argv);// filename maybe unused
	// 0513
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = interfaces_idx[0],
			    .attach_point = BPF_TC_EGRESS);
	//DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	// see the default value
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts);
	//DECLARE_LIBBPF_OPTS(bpf_xdp_attach_opts, xdp_opts, .old_prog_fd = 0);
	xdp_opts->old_prog_fd = 0;
	xdp_opts->sz = 5;

	libbpf_set_print(libbpf_print_fn);

	skel = fast_bpf__open_and_load();// how to set prog type and log level?
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}
	err = bpf_tc_hook_create(&tc_hook);
	// add xdp
	if (!err)
		hook_created = true;
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}
	tc_opts.prog_fd = bpf_program__fd(skel->progs.FastBroadCast_main);

	/*initial_prog_map*/
	int index;
	int prog_fd;
	index = FAST_PROG_XDP_HANDLE_PREPARE;
    prog_fd = bpf_program__fd(skel->progs.HandlePrepare_main);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_progs_xdp),
		&index, &prog_fd, BPF_ANY);
	
	index = FAST_PROG_XDP_HANDLE_PREPAREOK;
    prog_fd = bpf_program__fd(skel->progs.HandlePrepareOK_main);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_progs_xdp),
		&index, &prog_fd, BPF_ANY);

	index = FAST_PROG_XDP_PREPARE_REPLY;
    prog_fd = bpf_program__fd(skel->progs.PrepareFastReply_main);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_progs_xdp),
		&index, &prog_fd, BPF_ANY);

	index = FAST_PROG_XDP_WRITE_BUFFER;
    prog_fd = bpf_program__fd(skel->progs.WriteBuffer_main);
    err = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_progs_xdp),
		&index, &prog_fd, BPF_ANY);

	int map_configure_fd = bpf_map__fd(skel->maps.map_configure);
	if (map_configure_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}

	FILE *fp;
	char buff[255];//暂存字符串
	int f = 0;
	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];
	struct paxos_configure conf;
	const char *eths[FAST_REPLICA_MAX] = {"9c:dc:71:56:8f:45",
										"9c:dc:71:56:bf:45", 
										"9c:dc:71:5e:2f:51", 
										"", 
										""}; 
	fp = fopen("../config.txt", "r");
	fscanf(fp, "%s", buff); // must be 'f'
	fscanf(fp, "%d", &f);
	for (int i = 0; i < 2*f + 1; ++i) {
		fscanf(fp, "%s", buff); // must be 'replica'
		fscanf(fp, "%s", buff); // eg：10.10.1.3:12345

		char *ipv4 = strtok(buff, ":");
		assert(ipv4 != NULL);
		char *port = strtok(NULL, ":");

		// store this IP address in sa:
		inet_pton(AF_INET, ipv4, &(sa.sin_addr));//将 IP 地址从文本表示转换为二进制表示
		// AF_INET表示IPv4地址族
		// now get it back and print it
		inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
		conf.port = htons(atoi(port));// 将其转换为网络字节序（big-endian）
		conf.addr = sa.sin_addr.s_addr;
		sscanf(eths[i], "%x:%x:%x:%x:%x:%x", conf.eth, conf.eth + 1, conf.eth + 2, conf.eth + 3, conf.eth + 4, conf.eth + 5);
		err = bpf_map_update_elem(map_configure_fd, &i, &conf, BPF_ANY);
	}

	fclose(fp);
	// how to pin map?

	err = bpf_tc_attach(&tc_hook, &tc_opts);// how t  pin tc
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}
	if (bpf_xdp_attach (interfaces_idx[0], bpf_program__fd(skel->progs.fastPaxos_main), xdp_flags, xdp_opts) < 0) {
		fprintf(stderr, "Error: bpf_set_link_xdp_fd failed for interface %d\n", interfaces_idx[0]);
		return 1;
	} else {
		printf("Main BPF program attached to XDP on interface %d\n", interfaces_idx[0]);
	}

	// handle interrupt

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}
	if (signal(SIGTERM, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}
	if (signal(SIGUSR1, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}


	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF program.\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}
	// add xdp
	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}
	bpf_xdp_detach(interfaces_idx[0], xdp_flags, xdp_opts);

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	fast_bpf__destroy(skel);
	return -err;

}

// gcc -g -O2 -Wall -DKBUILD_MODNAME="\"wzz\"" -I. -I./linux/tools/lib -I./linux/tools/include/uapi  -o test fast_test.c ./linux/tools/lib/bpf/libbpf.a -L./linux/tools/lib/bpf -l:libbpf.a -lelf  -lz