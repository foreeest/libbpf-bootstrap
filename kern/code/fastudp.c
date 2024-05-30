#include <signal.h>
#include <unistd.h>
#include <assert.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>

#include "fastudp.skel.h"
#include "fastudp.h"

#define IFINDEX 2 // modify it

static const char* base_folder = "/sys/fs/bpf";

static volatile sig_atomic_t exiting;

void sig_int(int signo)
{
    exiting = 1;
}

static bool setup_sig_handler() {
    // Add handlers for SIGINT and SIGTERM so we shutdown cleanly
    __sighandler_t sighandler = signal(SIGINT, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    sighandler = signal(SIGTERM, sig_int);
    if (sighandler == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        return false;
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}


static bool setup() {
    // Set up libbpf errors and debug info callback 
    libbpf_set_print(libbpf_print_fn);

    // Setup signal handler so we exit cleanly
    if (!setup_sig_handler()) {
        return false;
    }

    return true;
}


int main(int argc, char **argv)
{	

	// parse arg
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = IFINDEX,
			    .attach_point = BPF_TC_EGRESS);
	//DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
	// see the default value
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts);
    printf("tc_opts's Handle=%u\n", tc_opts.handle);
	printf("tc_opts's Priority=%u\n", tc_opts.priority);

	bool hook_created = false;
	struct fastudp_bpf *skel;
	int err;
	int index, prog_fd;

	// maybe prase argc in the future

	if (!setup()) {
        exit(1);
    }

	skel = fastudp_bpf__open_and_load();
	printf("Well,we now have loaded the skeleton \n");
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	int map_configure_fd = bpf_map__fd(skel->maps.map_configure);
	if (map_configure_fd < 0) {
		fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
		exit(1); //return 1;
	}

	FILE *fp;
	char buff[255];//暂存字符串
	int f = 0, port = 0;

	struct sockaddr_in sa;
	char str[INET_ADDRSTRLEN];
	struct paxos_configure conf;
	// we need to modify this
	const char *eths[NODE_MAX_NUM] = {"9c:dc:71:56:8f:45",
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
	/* The hook (i.e. qdisc) may already exists because:
	 *   1. it is created by other processes or users
	 *   2. or since we are attaching to the TC ingress ONLY,
	 *      bpf_tc_hook_destroy does NOT really remove the qdisc,
	 *      there may be an egress filter on the qdisc
	 */

	err = bpf_tc_hook_create(&tc_hook);
	if (!err)
		hook_created = true;
	if (err==-EEXIST){
		printf("Beacause creating more than once, Just a harmless Error\n");
	}
	if (err && err != -EEXIST) { // what about EEXIST ?
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		goto cleanup;
	}

	/* pin the prog*/
	if (access("/sys/fs/bpf", F_OK) != 0) {
		fprintf(stderr, "Make sure bpf filesystem mounted by running:\n");
		fprintf(stderr, "    sudo mount bpffs -t bpf /sys/fs/bpf\n");
		return 1;
	}

	char pin_path[100];
	sprintf(pin_path, "%s/FastBoardcast", base_folder);
retry1:
    err = bpf_program__pin(skel->progs.FastBroadCast_main, pin_path);
    if (err) {
        fprintf(stdout, "could not pin prog %s: %d\n", pin_path, err);
		if(err == -EEXIST){
			fprintf(stdout, "BPF obj already pinned, unpinning it to reload it\n");
			err = bpf_program__unpin(skel->progs.FastBroadCast_main, pin_path);
			if (err){
				fprintf(stdout, "Still could not pin\n");
				return err;
			}
			goto retry1;
		}
        return err;
    }
// pin it so that we can verify weather we load the map correctly
	sprintf(pin_path, "%s/configure", base_folder);
retry2:
    err = bpf_map__pin(skel->maps.map_configure, pin_path);
    if (err) {
        fprintf(stdout, "could not pin map %s: %d\n", pin_path, err);
		if(err == -EEXIST){
			fprintf(stdout, "BPF obj already pinned, unpinning it to reload it\n");
			err = bpf_map__unpin(skel->maps.map_configure, pin_path);
			if (err){
				fprintf(stdout, "Still could not pin\n");
				return err;
			}
			goto retry2;
		}
        return err;
    }

	tc_opts.prog_fd = bpf_program__fd(skel->progs.FastBroadCast_main);
	err = bpf_tc_attach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to attach TC: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started!\n");

	while (!exiting) {
		fprintf(stderr, ".");
		sleep(1);
	}

	tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	err = bpf_tc_detach(&tc_hook, &tc_opts);
	if (err) {
		fprintf(stderr, "Failed to detach TC: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (hook_created)
		bpf_tc_hook_destroy(&tc_hook);
	fastudp_bpf__destroy(skel);
	return -err;
}
