#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void *worker(void *arg) {
    usleep(50000);
    if (arg) { execl("/bin/true", "true", NULL); _exit(90); }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "fork")) {
        pid_t child = fork();
        if (child < 0) return 3;
        if (!child) { execl("/bin/true", "true", NULL); _exit(4); }
        printf("%d\n", child);
        int status;
        waitpid(child, &status, 0);
        return status != 0;
    }
    if (!strcmp(argv[1], "failedexec")) {
        execl("/vigil-fixture-does-not-exist", "missing", NULL);
        return errno == ENOENT ? 0 : 5;
    }
    if (!strcmp(argv[1], "threads") || !strcmp(argv[1], "threadexec")) {
        pthread_t thread;
        int replace = !strcmp(argv[1], "threadexec");
        if (pthread_create(&thread, NULL, worker, replace ? (void *)1 : NULL)) return 6;
        if (!replace) pthread_exit(NULL); // group leader exits before worker
        pthread_join(thread, NULL);
        return 7; // successful thread exec never returns here
    }
    if (!strcmp(argv[1], "network") && argc == 5) {
        int family = atoi(argv[2]) == 6 ? AF_INET6 : AF_INET;
        int fd = socket(family, SOCK_STREAM, 0);
        if (fd < 0) return 8;
        if (atoi(argv[4])) fcntl(fd, F_SETFL, O_NONBLOCK);
        int rc;
        if (family == AF_INET) {
            struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(atoi(argv[3]))};
            inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
            rc = connect(fd, (void *)&a, sizeof(a));
        } else {
            struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons(atoi(argv[3]))};
            inet_pton(AF_INET6, "::1", &a.sin6_addr);
            rc = connect(fd, (void *)&a, sizeof(a));
        }
        printf("%d\n", rc == 0 ? 0 : -errno);
        close(fd);
        return 0;
    }
    return 9;
}
