// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "ProtectShim"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define ENV_PROTECT_SOCK_PATH "VPN_PROTECT_SOCK_PATH"
#define MAX_TRACKED_FDS 65536

typedef int (*socket_fn_t)(int domain, int type, int protocol);
typedef int (*connect_fn_t)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
typedef ssize_t (*sendto_fn_t)(int sockfd, const void *buf, size_t len, int flags,
                               const struct sockaddr *dest_addr, socklen_t addrlen);
typedef int (*close_fn_t)(int fd);

static socket_fn_t real_socket = NULL;
static connect_fn_t real_connect = NULL;
static sendto_fn_t real_sendto = NULL;
static close_fn_t real_close = NULL;
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static _Atomic uint64_t protected_fd_bitmap[MAX_TRACKED_FDS / 64];

static void resolve_real_symbols(void) {
    real_socket = (socket_fn_t)dlsym(RTLD_NEXT, "socket");
    real_connect = (connect_fn_t)dlsym(RTLD_NEXT, "connect");
    real_sendto = (sendto_fn_t)dlsym(RTLD_NEXT, "sendto");
    real_close = (close_fn_t)dlsym(RTLD_NEXT, "close");
}

static inline bool is_fd_marked_protected(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return false;
    uint64_t mask = 1ULL << (fd & 63);
    return (atomic_load_explicit(&protected_fd_bitmap[fd >> 6], memory_order_relaxed) & mask) != 0;
}

static inline void mark_fd_protected(int fd, bool protected_state) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return;
    uint64_t mask = 1ULL << (fd & 63);
    if (protected_state) {
        atomic_fetch_or_explicit(&protected_fd_bitmap[fd >> 6], mask, memory_order_relaxed);
    } else {
        atomic_fetch_and_explicit(&protected_fd_bitmap[fd >> 6], ~mask, memory_order_relaxed);
    }
}

/**
 * Передает файловый дескриптор target_fd в родительский процесс VpnService
 * через Unix Domain Socket с использованием SCM_RIGHTS и синхронно ждет
 * 1 байт подтверждения (0x01 = успех).
 */
static int send_fd_for_protection(int target_fd) {
    pthread_once(&init_once, resolve_real_symbols);
    if (!real_socket || !real_connect || !real_close) return -1;

    const char *sock_path = getenv(ENV_PROTECT_SOCK_PATH);
    if (!sock_path || sock_path[0] == '\0') {
        return -1;
    }

    int saved_errno = errno;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    int uds_fd = -1;
    bool connected = false;

    // Retry connecting for up to ~1.5 seconds if socket doesn't exist yet or connection refused
    for (int retry = 0; retry < 50; retry++) {
        uds_fd = real_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (uds_fd < 0) {
            usleep(30000);
            continue;
        }

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(uds_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(uds_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (real_connect(uds_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            connected = true;
            break;
        }

        int conn_err = errno;
        real_close(uds_fd);
        uds_fd = -1;

        if (conn_err != ENOENT && conn_err != ECONNREFUSED) {
            LOGE("Failed to connect to protect UDS %s: errno=%d", sock_path, conn_err);
            break;
        }

        usleep(30000);
    }

    if (!connected || uds_fd < 0) {
        LOGE("Failed to connect to protect UDS %s after retries", sock_path);
        errno = saved_errno;
        return -1;
    }

    char dummy_payload = 'P';
    struct iovec iov = {
        .iov_base = &dummy_payload,
        .iov_len = sizeof(dummy_payload)
    };

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control_un;
    memset(&control_un, 0, sizeof(control_un));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_un.buf;
    msg.msg_controllen = sizeof(control_un.buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &target_fd, sizeof(int));

    ssize_t sent;
    do {
        sent = sendmsg(uds_fd, &msg, MSG_NOSIGNAL);
    } while (sent < 0 && errno == EINTR);

    if (sent < 0) {
        LOGE("sendmsg(SCM_RIGHTS) failed for fd=%d: errno=%d", target_fd, errno);
        real_close(uds_fd);
        errno = saved_errno;
        return -1;
    }

    uint8_t ack = 0;
    ssize_t received;
    do {
        received = recv(uds_fd, &ack, 1, 0);
    } while (received < 0 && errno == EINTR);

    real_close(uds_fd);
    errno = saved_errno;

    if (received == 1 && ack == 1) {
        mark_fd_protected(target_fd, true);
        LOGI("Socket fd=%d protected successfully via %s", target_fd, sock_path);
        return 0;
    }

    LOGE("VpnService.protect() rejected fd=%d (received=%zd, ack=%u)", target_fd, received, ack);
    return -1;
}

static void ensure_inet_socket_protected(int sockfd) {
    if (sockfd < 0 || is_fd_marked_protected(sockfd)) return;
    int saved_errno = errno;
    int domain = -1;
    socklen_t len = sizeof(domain);
    if (getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, &domain, &len) == 0) {
        if (domain == AF_INET || domain == AF_INET6) {
            send_fd_for_protection(sockfd);
        }
    }
    errno = saved_errno;
}

__attribute__((visibility("default")))
int socket(int domain, int type, int protocol) {
    pthread_once(&init_once, resolve_real_symbols);
    int fd = real_socket(domain, type, protocol);
    if (fd >= 0) {
        mark_fd_protected(fd, false);
        if (domain == AF_INET || domain == AF_INET6) {
            send_fd_for_protection(fd);
        }
    }
    return fd;
}

__attribute__((visibility("default")))
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    pthread_once(&init_once, resolve_real_symbols);
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        if (!is_fd_marked_protected(sockfd)) {
            send_fd_for_protection(sockfd);
        }
    }
    return real_connect(sockfd, addr, addrlen);
}

__attribute__((visibility("default")))
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    pthread_once(&init_once, resolve_real_symbols);
    if (!is_fd_marked_protected(sockfd)) {
        ensure_inet_socket_protected(sockfd);
    }
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

__attribute__((visibility("default")))
int close(int fd) {
    pthread_once(&init_once, resolve_real_symbols);
    mark_fd_protected(fd, false);
    return real_close(fd);
}
