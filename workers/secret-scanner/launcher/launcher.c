#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "the secret scanner launcher supports Linux amd64 only"
#endif

#if defined(OPEN_TRESTLE_PRODUCTION_BUILD) && defined(OPEN_TRESTLE_TEST_WORKER_PATH)
#error "the production launcher worker path is fixed"
#endif

#ifndef OPEN_TRESTLE_TEST_WORKER_PATH
#define WORKER_PATH "/usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker"
#else
#define WORKER_PATH OPEN_TRESTLE_TEST_WORKER_PATH
#endif

#define REQUIRED_LANDLOCK_ABI 5
#define WORKER_ARGUMENT "--sandboxed-stdio-v1"
#define PUBLIC_ARGUMENT "--stdio-v1"
#define MAXIMUM_OPEN_FILES 16
#define CPU_LIMIT_SECONDS 6

static int equal_string(const char *left, const char *right) {
    while (*left != '\0' && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int set_limit(int resource, rlim_t value) {
    const struct rlimit limit = {.rlim_cur = value, .rlim_max = value};
    return setrlimit(resource, &limit);
}

static int apply_resource_limits(void) {
    if (set_limit(RLIMIT_CORE, 0) != 0) {
        return -1;
    }
    if (set_limit(RLIMIT_CPU, CPU_LIMIT_SECONDS) != 0) {
        return -1;
    }
    if (set_limit(RLIMIT_NOFILE, MAXIMUM_OPEN_FILES) != 0) {
        return -1;
    }
    return 0;
}

static uint64_t handled_filesystem_access(void) {
    return LANDLOCK_ACCESS_FS_EXECUTE |
           LANDLOCK_ACCESS_FS_WRITE_FILE |
           LANDLOCK_ACCESS_FS_READ_FILE |
           LANDLOCK_ACCESS_FS_READ_DIR |
           LANDLOCK_ACCESS_FS_REMOVE_DIR |
           LANDLOCK_ACCESS_FS_REMOVE_FILE |
           LANDLOCK_ACCESS_FS_MAKE_CHAR |
           LANDLOCK_ACCESS_FS_MAKE_DIR |
           LANDLOCK_ACCESS_FS_MAKE_REG |
           LANDLOCK_ACCESS_FS_MAKE_SOCK |
           LANDLOCK_ACCESS_FS_MAKE_FIFO |
           LANDLOCK_ACCESS_FS_MAKE_BLOCK |
           LANDLOCK_ACCESS_FS_MAKE_SYM |
           LANDLOCK_ACCESS_FS_REFER |
           LANDLOCK_ACCESS_FS_TRUNCATE |
           LANDLOCK_ACCESS_FS_IOCTL_DEV;
}

static int enter_landlock(int worker_fd) {
    const int abi = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                                 LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < REQUIRED_LANDLOCK_ABI) {
        return -1;
    }

    const struct landlock_ruleset_attr ruleset = {
        .handled_access_fs = handled_filesystem_access(),
    };
    const int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset,
                                        &ruleset, sizeof(ruleset), 0);
    if (ruleset_fd < 0) {
        return -1;
    }

    const struct landlock_path_beneath_attr worker_rule = {
        .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
        .parent_fd = worker_fd,
    };
    if (syscall(__NR_landlock_add_rule, ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH, &worker_rule, 0) != 0) {
        close(ruleset_fd);
        return -1;
    }
    if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) != 0) {
        close(ruleset_fd);
        return -1;
    }
    return ruleset_fd;
}

static int close_nonstandard_descriptors(int preserved_fd) {
    if (preserved_fd > 3 && syscall(__NR_close_range, 3U,
                                    (unsigned int)preserved_fd - 1U, 0U) != 0) {
        return -1;
    }
    if (syscall(__NR_close_range, (unsigned int)preserved_fd + 1U,
                UINT32_MAX, 0U) != 0) {
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || !equal_string(argv[1], PUBLIC_ARGUMENT)) {
        return 64;
    }
    if (chdir("/") != 0 || apply_resource_limits() != 0) {
        return 70;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        return 70;
    }

    const int worker_fd = open(WORKER_PATH, O_PATH | O_CLOEXEC | O_NOFOLLOW);
    struct stat worker_status;
    if (worker_fd < 3 || worker_fd >= MAXIMUM_OPEN_FILES ||
        fstat(worker_fd, &worker_status) != 0 || !S_ISREG(worker_status.st_mode)) {
        if (worker_fd >= 0) {
            close(worker_fd);
        }
        return 70;
    }
    const int ruleset_fd = enter_landlock(worker_fd);
    if (ruleset_fd < 0) {
        close(worker_fd);
        return 70;
    }
    close(ruleset_fd);
    if (close_nonstandard_descriptors(worker_fd) != 0) {
        close(worker_fd);
        return 70;
    }
    char *const worker_argv[] = {(char *)WORKER_PATH, (char *)WORKER_ARGUMENT, NULL};
    char *const worker_environment[] = {NULL};
    syscall(__NR_execveat, worker_fd, "", worker_argv, worker_environment,
            AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW);
    _exit(126);
}
