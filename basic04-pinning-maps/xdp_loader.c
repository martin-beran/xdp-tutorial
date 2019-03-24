/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";
char pin_dir[PATH_MAX];
char map_filename[PATH_MAX];

struct bpf_object *load_bpf_and_reuse_pinned(struct config *cfg, const char *subdir)
{
	struct bpf_object *bpf_obj;
	struct bpf_program *bpf_prog;
	struct bpf_map *map;
	int err, prog_fd = -1, len, offload_ifindex = 0;
	enum bpf_attach_type expected_attach_type;
	struct bpf_object_open_attr open_attr = {
                .file           = cfg->filename,
                .prog_type      = BPF_PROG_TYPE_XDP,
        };


	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
                offload_ifindex = cfg->ifindex;

	bpf_obj = bpf_object__open_xattr(&open_attr);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: opening file: %s\n", cfg->filename);
		return NULL;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return NULL;
	}
	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, subdir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return NULL;
	}

	int pinned_map_fd = bpf_obj_get(map_filename);
	if (pinned_map_fd >= 0) {
		fprintf(stderr, "Reuse map %s\n", map_name);
		struct bpf_map *map = bpf_object__find_map_by_name(bpf_obj, map_name);
		bpf_map__reuse_fd(map, pinned_map_fd);
	}

	bpf_object__for_each_program(bpf_prog, bpf_obj) {
                /*
                 * If type is not specified, try to guess it based on
                 * section name.
                 */
		bpf_program__set_ifindex(bpf_prog, offload_ifindex);
		expected_attach_type = 0;

                bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_XDP);
                bpf_program__set_expected_attach_type(bpf_prog,
                                                      expected_attach_type);
        }

	bpf_object__for_each_map(map, bpf_obj) {
                if (!bpf_map__is_offload_neutral(map))
                        bpf_map__set_ifindex(map, offload_ifindex);
        }


	if (bpf_object__load(bpf_obj)) {
		fprintf(stderr, "ERR: object load\n");
		return NULL;
	}
	
	if (cfg->progsec[0])
                /* Find a matching BPF prog section name */
                bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);    
        else
                /* Find the first program */
                bpf_prog = bpf_program__next(NULL, bpf_obj);

        if (!bpf_prog) {
                fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
                exit(EXIT_FAIL_BPF);
        }

	strncpy(cfg->progsec, bpf_program__title(bpf_prog, false), sizeof(cfg->progsec));

        prog_fd = bpf_program__fd(bpf_prog);
        if (prog_fd <= 0) {
                fprintf(stderr, "ERR: bpf_program__fd failed\n");
                exit(EXIT_FAIL_BPF);
        }

        /* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
         * is our select file-descriptor handle. Next step is attaching this FD
         * to a kernel hook point, in this case XDP net_device link-level hook.
         */
        err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
        if (err)
                exit(err);

        return bpf_obj;

}

/* Pinning maps under /sys/fs/bpf in subdir */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir)
{
	int err;

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;
	int err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload) {
		/* TODO: Miss unpin of maps on unload */
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	}

	bpf_obj = load_bpf_and_reuse_pinned(&cfg, cfg.ifname);
	//bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	err = pin_maps_in_bpf_object(bpf_obj, cfg.ifname);
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}

	return EXIT_OK;
}
