#define _GNU_SOURCE
#include "syshead.h"
#include "liblevelip.h"
#include "ipc.h"
#include "list.h"
#include "utils.h"

#define RCBUF_LEN 16384

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (*rtld_fini) (void), void (* stack_end));

static int (*_fcntl)(int fildes, int cmd, ...) = NULL;
static int (*_setsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t optlen) = NULL;
static int (*_getsockopt)(int fd, int level, int optname,
                         const void *optval, socklen_t *optlen) = NULL;
static int (*_read)(int sockfd, void *buf, size_t len) = NULL;
static int (*_write)(int sockfd, const void *buf, size_t len) = NULL;
static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int fildes) = NULL;
static int (*_poll)(struct pollfd fds[], nfds_t nfds, int timeout) = NULL;
static int (*_pollchk)(struct pollfd *__fds, nfds_t __nfds, int __timeout,
                       __SIZE_TYPE__ __fdslen) = NULL;

static int (*_ppoll)(struct pollfd *fds, nfds_t nfds,
                     const struct timespec *tmo_p, const sigset_t *sigmask) = NULL;
static int (*_select)(int nfds, fd_set *restrict readfds,
                      fd_set *restrict writefds, fd_set *restrict errorfds,
                      struct timeval *restrict timeout);
static ssize_t (*_sendto)(int sockfd, const void *message, size_t length,
                          int flags, const struct sockaddr *dest_addr,
                          socklen_t dest_len) = NULL;
static ssize_t (*_recvfrom)(int sockfd, void *buf, size_t len,
                            int flags, struct sockaddr *restrict address,
                            socklen_t *restrict addrlen) = NULL;
static int (*_getpeername)(int socket, struct sockaddr *restrict address,
                           socklen_t *restrict address_len) = NULL;
static int (*_getsockname)(int socket, struct sockaddr *restrict address,
                           socklen_t *restrict address_len) = NULL;
static int (*_ioctl)(int fd, unsigned long int request, ...) = NULL;

static int lvlip_socks_count = 0;
static LIST_HEAD(lvlip_socks);

static inline struct lvlip_sock *lvlip_get_sock(int fd) {
    struct list_head *item;
    struct lvlip_sock *sock;

    list_for_each(item, &lvlip_socks) {
        sock = list_entry(item, struct lvlip_sock, list);
        
        if (sock->fd == fd) return sock;
    };

    return NULL;
};

static int is_socket_supported(int domain, int type, int protocol)
{
    lvl_dbg("domain:%d type:%d protocol:%d\n", domain, type, protocol);
    if (domain != AF_INET) return 0;

    if (type != SOCK_DGRAM && type != SOCK_STREAM) return 0;

    if (protocol != IPPROTO_IP && protocol != IPPROTO_ICMP && protocol != IPPROTO_TCP) return 0;
    
    lvl_dbg("domain:%d type:%d protocol:%d is supported\n", domain, type, protocol);
    return 1;
}

static int init_socket(char *sockname)
{
    struct sockaddr_un addr;
    int ret;
    int data_socket;

    /* Create local socket. */

    data_socket = _socket(AF_UNIX, SOCK_STREAM, 0);
    if (data_socket == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    /*
     * For portability clear the whole structure, since some
     * implementations have additional (nonstandard) fields in
     * the structure.
     */

    memset(&addr, 0, sizeof(struct sockaddr_un));

    /* Connect socket to socket address */

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockname, sizeof(addr.sun_path) - 1);

    ret = _connect(data_socket, (const struct sockaddr *) &addr,
                   sizeof(struct sockaddr_un));
    if (ret == -1) {
        print_err("Error connecting to level-ip. Is it up?\n");
        exit(EXIT_FAILURE);
    }

    return data_socket;
}

static int free_socket(int lvlfd)
{
    return _close(lvlfd);
}

static int transmit_lvlip(int lvlfd, struct ipc_msg *msg, int msglen)
{
    static char buf[RCBUF_LEN];

    // Send mocked syscall to lvl-ip
    if (_write(lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC");
    }

    // Read return value from lvl-ip
    int recv_len = _read(lvlfd, buf, RCBUF_LEN);
    if (recv_len == -1) {
        perror("Could not read IPC response");
    }
    

    struct ipc_msg *response = (struct ipc_msg *) buf;
    lvl_dbg("IPC read result: %d", recv_len);
    if (response->type != msg->type || response->pid != msg->pid) {
        print_err("ERR: IPC msg response expected type %d, pid %d\n"
                  "                      actual type %d, pid %d\n",
               msg->type, msg->pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *err = (struct ipc_err *) response->data;

    if (err->rc == -1) errno = err->err;

    return err->rc;
}

int socket(int domain, int type, int protocol)
{
    if (!is_socket_supported(domain, type, protocol)) {
        return _socket(domain, type, protocol);
    }

    struct lvlip_sock *sock;
    
    int lvlfd = init_socket("/tmp/vip.sock");

    sock = lvlip_alloc();
    sock->lvlfd = lvlfd;
    list_add_tail(&sock->list, &lvlip_socks);
    lvlip_socks_count++;
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_socket);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SOCKET;
    msg->pid = pid;
    lvl_dbg("type:0x%X pid:%d", msg->type, msg->pid);

    struct ipc_socket usersock = {
        .domain = domain,
        .type = type,
        .protocol = protocol
    };
    
    memcpy(msg->data, &usersock, sizeof(struct ipc_socket));

    int sockfd = transmit_lvlip(sock->lvlfd, msg, msglen);

    if (sockfd == -1) {
        /* Socket alloc failed */
        lvlip_free(sock);
        return -1;
    }

    sock->fd = sockfd;

    lvl_sock_dbg("Socket called", sock);
    
    return sockfd;
}

int close(int fd)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _close(fd);
    }

    lvl_sock_dbg("Close called", sock);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_close);
    int rc = 0;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CLOSE;
    msg->pid = pid;

    struct ipc_close *payload = (struct ipc_close *)msg->data;
    payload->sockfd = fd;

    rc = transmit_lvlip(sock->lvlfd, msg, msglen);
    free_socket(sock->lvlfd);

    return rc;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _connect(sockfd, addr, addrlen);
    }

    lvl_sock_dbg("Connect called", sock);
    
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_connect);
    int pid = getpid();
    
    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_CONNECT;
    msg->pid = pid;

    struct ipc_connect payload = {
        .sockfd = sockfd,
        .addr = *addr,
        .addrlen = addrlen
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_connect));

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

ssize_t write(int sockfd, const void *buf, size_t len)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _write(sockfd, buf, len);
    }

    lvl_sock_dbg("Write called", sock);
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_write) + len;
    int pid = getpid();

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_WRITE;
    msg->pid = pid;

    struct ipc_write payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_write));
    memcpy(((struct ipc_write *)msg->data)->buf, buf, len);

    return transmit_lvlip(sock->lvlfd, msg, msglen);
}

ssize_t read(int sockfd, void *buf, size_t len)
{
    struct lvlip_sock *sock = lvlip_get_sock(sockfd);

    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        int res = -1;
        while (res < 0) {
            res = _read(sockfd, buf, len);
            //print_err("READ fd:%d res:%d\n", sockfd, res);
            //perror("_read");
	    usleep(50);
        }
        return res;
    }

    lvl_sock_dbg("Read called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_read);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_READ;
    msg->pid = pid;

    struct ipc_read payload = {
        .sockfd = sockfd,
        .len = len
    };

    memcpy(msg->data, &payload, sizeof(struct ipc_read));

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC read");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_read) + len;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC read response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_READ || response->pid != pid) {
        print_err("ERR: IPC read response expected: type %d, pid %d\n"
                  "                       actual: type %d, pid %d\n",
               IPC_READ, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc < 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_read *data = (struct ipc_read *) error->data;
    if (len < data->len) {
        print_err("IPC read received len error: %lu\n", data->len);
        return -1;
    }

    memset(buf, 0, len);
    memcpy(buf, data->buf, error->rc);
        
    return error->rc;
}

ssize_t send(int fd, const void *buf, size_t len, int flags)
{
    return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int fd, const void *buf, size_t len,
               int flags, const struct sockaddr *dest_addr,
               socklen_t dest_len)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return _sendto(fd, buf, len, flags, dest_addr, dest_len);
    }

    lvl_sock_dbg("Sendto called", sock);
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sendto) + len;
    int pid = getpid();

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SENDTO;
    msg->pid = pid;

    struct ipc_sendto payload = {
        .sockfd = fd,
        .flags = flags,
        .addrlen = dest_len,
        .len = len
    };
    if (dest_addr != NULL) {
        payload.addr = *dest_addr;
    }

    memcpy(msg->data, &payload, sizeof(struct ipc_sendto));
    memcpy(((struct ipc_sendto *)msg->data)->buf, buf, len);

    int rc = transmit_lvlip(sock->lvlfd, msg, msglen);
    return rc;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
    return recvfrom(fd, buf, len, flags, NULL, 0);
}

ssize_t recvfrom(int fd, void *restrict buf, size_t len,
                 int flags, struct sockaddr *restrict address,
                 socklen_t *restrict addrlen)
{
    if (!lvlip_get_sock(fd)) return _recvfrom(fd, buf, len,
                                          flags, address, addrlen);

    if (address == NULL) {
        return read(fd, buf, len);
    }

    return -1;
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) {
        /* No lvl-ip IPC socket associated */
        return -1;
    }

    lvl_sock_dbg("Recvmsg called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_recvmsg) + msg->msg_iovlen*sizeof(uint64_t);

    struct ipc_msg *ipc_msg = alloca(msglen);
    ipc_msg->type = IPC_RECVMSG;
    ipc_msg->pid = pid;

    struct ipc_recvmsg payload = {
        .sockfd = fd,
        .flags = flags,
        .msg_namelen = msg->msg_namelen,
        .msg_controllen = msg->msg_controllen,
        .msg_iovlen = msg->msg_iovlen,
    };

    uint64_t *msg_iovs_len = (uint64_t *) payload.data;
    lvl_dbg("flags:%d msg_namelen:%d msg_controllen:%lu msg_iovlen:%lu ", 
        payload.flags, payload.msg_namelen, payload.msg_controllen, payload.msg_iovlen);
    for (int i = 0; i < msg->msg_iovlen; i++) {
        msg_iovs_len[i] = msg->msg_iov[i].iov_len;
        lvl_dbg("msg_iov[%d].iov_len:%lu ", i, msg_iovs_len[i]);
    }

    memcpy(ipc_msg->data, &payload, sizeof(struct ipc_recvmsg) + msg->msg_iovlen*sizeof(uint64_t));

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)ipc_msg, msglen) == -1) {
        perror("Error on writing IPC read");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_recvmsg);
    rlen += msg->msg_iovlen*sizeof(uint64_t) + msg->msg_namelen + msg->msg_controllen;
    for(int i = 0; i < msg->msg_iovlen; i++)
    {
        rlen += msg->msg_iov[i].iov_len;
    }
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC read response");
    }
    lvl_dbg("ipc recv size:%d", rlen);
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_RECVMSG || response->pid != pid) {
        print_err("ERR: IPC recvmsg response expected: type %d, pid %d\n"
                  "                       actual: type %d, pid %d\n",
               IPC_RECVMSG, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc < 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_recvmsg *data = (struct ipc_recvmsg *) error->data;
    lvl_dbg("sockfd:%d flags:%d msg_flags:%d msg_namelen:%d msg_controllen:%lu msg_iovlen:%lu", 
    data->sockfd, data->flags, data->msg_flags, data->msg_namelen, data->msg_controllen, data->msg_iovlen);
    // data->data : uint64_t msg_iovs_len[]
    uint8_t *offset = data->data;

    // uint8_t msg_name
    offset += sizeof(uint64_t) * data->msg_iovlen;
    msg->msg_namelen = data->msg_namelen;
    memcpy(msg->msg_name, offset, msg->msg_namelen);

    // struct recvmsg_cmsghdr
    offset += data->msg_namelen;
    msg->msg_controllen = data->msg_controllen;
    memcpy(msg->msg_control, offset, data->msg_controllen);

    // uint8_t *iov_base[]
    offset += data->msg_controllen;
    for(int i = 0; i < msg->msg_iovlen; i++) {
        memcpy(msg->msg_iov[i].iov_base, offset, msg->msg_iov[i].iov_len);
        offset += msg->msg_iov[i].iov_len;
    }

    return error->rc;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    struct pollfd *kernel_fds[nfds];
    struct pollfd *lvlip_fds[nfds];
    int lvlip_nfds = 0;
    int kernel_nfds = 0;
    int lvlip_sock = 0;

    struct lvlip_sock *sock = NULL;

    for (int i = 0; i < nfds; i++) {
        struct pollfd *pfd = &fds[i];
        if ((sock = lvlip_get_sock(pfd->fd)) != NULL) {
            lvlip_fds[lvlip_nfds++] = pfd;
            lvlip_sock = sock->lvlfd;
        } else {
            kernel_fds[kernel_nfds++] = pfd;
        }
    }

    int blocking = 0;
    if (kernel_nfds > 0 && lvlip_nfds > 0 && timeout == -1) {
        /* Cannot sleep indefinitely when we demux poll 
           with both kernel and lvlip fds */
        timeout = 100;
        blocking = 1;
    }

    lvl_dbg("Poll called with kernel_nfds %d lvlip_nfds %d timeout %d", kernel_nfds, lvlip_nfds, timeout);

    for (;;) {
        int events = 0;
        if (kernel_nfds > 0) {
            for (int i = 0; i < kernel_nfds; i++) {
                lvl_dbg("Kernel nfd %d events %d timeout %d", kernel_fds[i]->fd, kernel_fds[i]->events, timeout);
            }
            
            events = _poll(*kernel_fds, kernel_nfds, timeout);

            if (events == -1) {
                perror("Poll kernel error");
                errno = EAGAIN;
                return -1;
            }
        }

        if (lvlip_nfds < 1) {
            return events;
        }
    
        int pid = getpid();
        int pollfd_size = sizeof(struct ipc_pollfd);
        int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_poll) + pollfd_size * lvlip_nfds;
        struct ipc_msg *msg = alloca(msglen);

        msg->type = IPC_POLL;
        msg->pid = pid;

        struct ipc_poll *data = (struct ipc_poll *)msg->data;
        data->nfds = lvlip_nfds;
        data->timeout = timeout;

        struct ipc_pollfd *pfd = NULL;
        for (int i = 0; i < lvlip_nfds; i++) {
            pfd = &data->fds[i];
            pfd->fd = lvlip_fds[i]->fd;
            pfd->events = lvlip_fds[i]->events;
            pfd->revents = lvlip_fds[i]->revents;
        }

        if (_write(lvlip_sock, (char *)msg, msglen) == -1) {
            perror("Error on writing IPC poll");
            errno = EAGAIN;
            return -1;
        }

        int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + pollfd_size * lvlip_nfds;
        char rbuf[rlen];
        memset(rbuf, 0, rlen);

        // Read return value from lvl-ip
        if (_read(lvlip_sock, rbuf, rlen) == -1) {
            perror("Could not read IPC poll response");
            errno = EAGAIN;
            return -1;
        }
    
        struct ipc_msg *response = (struct ipc_msg *) rbuf;

        if (response->type != IPC_POLL || response->pid != pid) {
            print_err("ERR: IPC poll response expected: type %d, pid %d\n"
                   "                       actual: type %d, pid %d\n",
                   IPC_POLL, pid, response->type, response->pid);
            errno = EAGAIN;
            return -1;
        }

        struct ipc_err *error = (struct ipc_err *) response->data;
        if (error->rc < 0) {
            errno = error->err;
            print_err("Error on poll %d %s\n", error->rc, strerror(errno));
            return error->rc;
        }

        struct ipc_pollfd *returned = (struct ipc_pollfd *) error->data;

        for (int i = 0; i < lvlip_nfds; i++) {
            lvlip_fds[i]->events = returned[i].events;
            lvlip_fds[i]->revents = returned[i].revents;
        }

        int result = events + error->rc;
    
        if (result > 0 || !blocking) {
            for (int i = 0; i < nfds; i++) {
                lvl_dbg("Returning counts %d nfd %d with revents %d events %d timeout %d", result, i, fds[i].revents, fds[i].events, timeout);
            }
 
            return result;
        } 
    }

    print_err("Poll returning with -1\n");
    return -1;
}

int __poll_chk (struct pollfd *__fds, nfds_t __nfds, int __timeout,
                __SIZE_TYPE__ __fdslen)
{
    return poll(__fds, __nfds, __timeout);
}

int ppoll(struct pollfd *fds, nfds_t nfds,
          const struct timespec *tmo_p, const sigset_t *sigmask)
{
    print_err("Ppoll called but not supported\n");
    return -1;
}


int select(int nfds, fd_set *restrict readfds,
           fd_set *restrict writefds, fd_set *restrict errorfds,
           struct timeval *restrict timeout)
{

    lvl_dbg("Select called");

    int kernel_fds_cnt = 0;
    int kernel_fd_max =0;

    struct pollfd lvlip_fds[10];
    int lvlip_fds_cnt = 0;
    for (int i = 0; i < nfds; i++)
    {
        if (lvlip_get_sock(i) != NULL){
            short int flag = 0;
            if (readfds != NULL && FD_ISSET(i, readfds)) {
                flag |= POLLIN;
                FD_CLR(i, readfds);
            }
            if (writefds != NULL && FD_ISSET(i, writefds)) {
                flag |= POLLOUT;
                FD_CLR(i, writefds);
            }
            if (errorfds != NULL && FD_ISSET(i, errorfds)) {
                FD_CLR(i, errorfds);
            }
            if (flag != 0){
                lvlip_fds[lvlip_fds_cnt].fd = i;
                lvlip_fds[lvlip_fds_cnt].events = flag;
                lvlip_fds_cnt += 1;
            }
        } else {
            bool is_set = false;
            if (readfds != NULL && FD_ISSET(i, readfds)) {
                is_set = true;
            }
            if (writefds != NULL && FD_ISSET(i, writefds)) {
                is_set = true;
            }
            if (errorfds != NULL && FD_ISSET(i, errorfds)) {
                is_set = true;
            }
            if (is_set) {
                kernel_fds_cnt += 1;
                kernel_fd_max = i;
            }
        }
    }

    int kernel_res = 0;
    int lvlip_res = 0;
    if (timeout != NULL) {
        if (kernel_fds_cnt > 0) {
            kernel_res = _select(kernel_fd_max+1, readfds, writefds, errorfds, timeout);
            if (kernel_res < 0) {
                perror("select kernel");
            }
        }
        if (lvlip_fds_cnt > 0) {
            poll(lvlip_fds, lvlip_fds_cnt, 0);
            for (int i=0; i < lvlip_fds_cnt; i++){
                struct pollfd lvlip_fd = lvlip_fds[i];
                if (lvlip_fd.revents & POLLIN) {
                    FD_SET(lvlip_fd.fd, readfds);
                    lvlip_res += 1;
                }
                if (lvlip_fd.revents & POLLOUT) {
                    FD_SET(lvlip_fd.fd, writefds);
                    lvlip_res += 1;
                }
            }
        }
        int rc = kernel_res + lvlip_res;
        return rc;
    }

    fd_set *kernel_read_fds = NULL;
    fd_set *kernel_write_fds = NULL;
    fd_set *kernel_error_fds = NULL;

    if (readfds != NULL) {
        kernel_read_fds = malloc(sizeof(fd_set));
        FD_ZERO(kernel_read_fds);
    }

    if (writefds != NULL) {
        kernel_write_fds = malloc(sizeof(fd_set));
        FD_ZERO(kernel_write_fds);
    } 

    if (errorfds != NULL) {
        kernel_error_fds = malloc(sizeof(fd_set));
        FD_ZERO(kernel_error_fds);
    }

    int rc = 0;
    for (;;) {
        lvl_dbg("Select infinte loop");
        if (readfds != NULL) 
            memcpy(kernel_read_fds, readfds, sizeof(fd_set));
        if (writefds != NULL)
            memcpy(kernel_write_fds, writefds, sizeof(fd_set));
        if (errorfds != NULL)
            memcpy(kernel_error_fds, errorfds, sizeof(fd_set));
        if (kernel_fds_cnt > 0) {
            struct timeval timeout_sec;
            timeout_sec.tv_sec = 0;
            timeout_sec.tv_usec = 100*1000;
            kernel_res = _select(kernel_fd_max+1, kernel_read_fds, kernel_write_fds, kernel_error_fds, &timeout_sec);
            if (kernel_res < 0) {
                perror("select kernel");
            }
        }
        if (kernel_res > 0) {
            if (readfds != NULL)
                memcpy(readfds, kernel_read_fds, sizeof(fd_set));
            if (writefds != NULL) {
                memcpy(writefds, kernel_write_fds, sizeof(fd_set));
            }
            if (errorfds != NULL)
                memcpy(errorfds, kernel_error_fds, sizeof(fd_set));

        }
        lvl_dbg("Select infinte loop2");
        if (lvlip_fds_cnt > 0) {
            poll(lvlip_fds, lvlip_fds_cnt, 100);
            for (int i=0; i < lvlip_fds_cnt; i++){
                struct pollfd lvlip_fd = lvlip_fds[i];
                if (lvlip_fd.revents & POLLIN) {
                    FD_SET(lvlip_fd.fd, readfds);
                    lvlip_res += 1;
                }
                if (lvlip_fd.revents & POLLOUT) {
                    FD_SET(lvlip_fd.fd, writefds);
                    lvlip_res += 1;
                }
            }
        }
        rc = kernel_res + lvlip_res;
        if (rc != 0) {
            break;
        }
    }

    if (kernel_read_fds != NULL) 
        free(kernel_read_fds);
    if (kernel_write_fds != NULL) 
        free(kernel_write_fds);
    if (kernel_error_fds != NULL) 
        free(kernel_error_fds);
    lvl_dbg("Select success rc:%d", rc);
    return rc;
}


int setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) return _setsockopt(fd, level, optname, optval, optlen);

    lvl_sock_dbg("Setsockopt called: level %d optname %d optval %d socklen %d",
                 sock, level, optname, *(int *)optval, optlen);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockopt) + optlen;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_SETSOCKOPT;
    msg->pid = pid;

    struct ipc_sockopt opts = {
        .fd = fd,
        .level = level,
        .optname = optname,
        .optlen = optlen,
    };

    memcpy(msg->data, &opts, sizeof(struct ipc_sockopt));
    memcpy(((struct ipc_sockopt *)msg->data)->optval, optval, optlen);
    int rc = transmit_lvlip(sock->lvlfd, msg, msglen);
    return rc;
}

int getsockopt(int fd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    struct lvlip_sock *sock = lvlip_get_sock(fd);
    if (sock == NULL) return _getsockopt(fd, level, optname, optval, optlen);

    lvl_sock_dbg("Getsockopt called: level %d optname %d optval %d socklen %d",
                 sock, level, optname, *(int *)optval, *(int *)optlen);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockopt) + *optlen;

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETSOCKOPT;
    msg->pid = pid;

    struct ipc_sockopt opts = {
        .fd = fd,
        .level = level,
        .optname = optname,
        .optlen = *optlen,
    };

    memcpy(msg->data, &opts, sizeof(struct ipc_sockopt));
    memcpy(((struct ipc_sockopt *)msg->data)->optval, optval, *optlen);

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC getsockopt");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockopt) + *optlen;
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC getsockopt response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETSOCKOPT || response->pid != pid) {
        print_err("ERR: IPC getsockopt response expected: type %d, pid %d\n"
               "                          actual: type %d, pid %d\n",
               IPC_GETSOCKOPT, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockopt *optres = (struct ipc_sockopt *) error->data;

    lvl_sock_dbg("Got getsockopt level %d optname %d optval %d socklen %d",
                 sock, optres->level, optres->optname, *(int *)optres->optval, optres->optlen);

    int val = *(int *)optres->optval;

    *(int *)optval = val;
    *optlen = optres->optlen;

    return 0;
}

int getpeername(int socket, struct sockaddr *restrict address,
                socklen_t *restrict address_len)
{
    struct lvlip_sock *sock = lvlip_get_sock(socket);
    if (sock == NULL) return _getpeername(socket, address, address_len);

    lvl_sock_dbg("Getpeername called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockname);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETPEERNAME;
    msg->pid = pid;

    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;
    name->socket = socket;

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC getpeername");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC getpeername response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETPEERNAME || response->pid != pid) {
        print_err("ERR: IPC getpeername response expected: type %d, pid %d\n"
               "                          actual: type %d, pid %d\n",
               IPC_GETPEERNAME, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockname *nameres = (struct ipc_sockname *) error->data;

    lvl_sock_dbg("Got getpeername fd %d addrlen %d sa_data %p",
                 sock, nameres->socket, nameres->address_len, nameres->sa_data);

    if (nameres->socket != socket) {
        print_err("Got socket %d but requested %d\n", nameres->socket, socket);
    }

    *address_len = nameres->address_len;
    memcpy(address, nameres->sa_data, nameres->address_len);
    
    return 0;
}

int getsockname(int socket, struct sockaddr *restrict address,
                socklen_t *restrict address_len)
{
    struct lvlip_sock *sock = lvlip_get_sock(socket);
    if (sock == NULL) return _getsockname(socket, address, address_len);

    lvl_sock_dbg("Getsockname called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_sockname);

    struct ipc_msg *msg = alloca(msglen);
    msg->type = IPC_GETSOCKNAME;
    msg->pid = pid;

    struct ipc_sockname *name = (struct ipc_sockname *)msg->data;
    name->socket = socket;

    // Send mocked syscall to lvl-ip
    if (_write(sock->lvlfd, (char *)msg, msglen) == -1) {
        perror("Error on writing IPC getsockname");
    }

    int rlen = sizeof(struct ipc_msg) + sizeof(struct ipc_err) + sizeof(struct ipc_sockname);
    char rbuf[rlen];
    memset(rbuf, 0, rlen);

    // Read return value from lvl-ip
    if (_read(sock->lvlfd, rbuf, rlen) == -1) {
        perror("Could not read IPC getsockname response");
    }
    
    struct ipc_msg *response = (struct ipc_msg *) rbuf;

    if (response->type != IPC_GETSOCKNAME || response->pid != pid) {
        print_err("ERR: IPC getsockname response expected: type %d, pid %d\n"
               "                          actual: type %d, pid %d\n",
               IPC_GETSOCKNAME, pid, response->type, response->pid);
        return -1;
    }

    struct ipc_err *error = (struct ipc_err *) response->data;
    if (error->rc != 0) {
        errno = error->err;
        return error->rc;
    }

    struct ipc_sockname *nameres = (struct ipc_sockname *) error->data;

    lvl_sock_dbg("Got getsockname fd %d addrlen %d sa_data %p",
                 sock, nameres->socket, nameres->address_len, nameres->sa_data);

    if (nameres->socket != socket) {
        print_err("Got socket %d but requested %d\n", nameres->socket, socket);
    }

    *address_len = nameres->address_len;
    memcpy(address, nameres->sa_data, nameres->address_len);

    return 0;
}

int fcntl(int fildes, int cmd, ...)
{
    int rc = -1;
    va_list ap;
    void *arg;

    struct lvlip_sock *sock = lvlip_get_sock(fildes);

    if (!sock) {
        va_start(ap, cmd);
        arg = va_arg(ap, void *);
        va_end(ap);

        return _fcntl(fildes, cmd, arg);
    }

    lvl_sock_dbg("Fcntl called", sock);

    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_fcntl) + sizeof(struct flock) + sizeof(int);
    struct ipc_msg *msg = alloca(msglen);

    msg->type = IPC_FCNTL;
    msg->pid = pid;

    struct ipc_fcntl *fc = (struct ipc_fcntl *)msg->data;
    fc->sockfd = fildes;
    fc->cmd = cmd;
    
    switch (cmd) {
    case F_GETFL:
        lvl_sock_dbg("Fcntl GETFL", sock);

        rc = transmit_lvlip(sock->lvlfd, msg, msglen);
        break;
    case F_SETFL:
        lvl_sock_dbg("Fcntl SETFL", sock);

        va_start(ap, cmd);

        int flags = va_arg(ap, int);
        memcpy(fc->data, &flags, sizeof(int));

        va_end(ap);

        rc = transmit_lvlip(sock->lvlfd, msg, msglen);
        break;
    default:
        rc = -1;
        errno = EINVAL;
        break;
    }
    
    return rc;
}

int ioctl(int fd, unsigned long int request, ...)
{
    int rc = -1;
    va_list ap;
    void *arg;

    struct lvlip_sock *sock = lvlip_get_sock(fd);

    if (!sock) {
        va_start(ap, request);
        arg = va_arg(ap, void *);
        va_end(ap);

        return _ioctl(fd, request, arg);
    }

    lvl_sock_dbg("Ioctl called", sock);
    
    int pid = getpid();
    int msglen = sizeof(struct ipc_msg) + sizeof(struct ipc_ioctl);
    struct ipc_msg *msg = alloca(msglen);

    msg->type = IPC_IOCTL;
    msg->pid = pid;

    struct ipc_ioctl *ic = (struct ipc_ioctl *)msg->data;
    ic->sockfd = fd;
    ic->request = request;
    switch (request) {
        case FIONBIO:
            lvl_sock_dbg("Ioctl FIONBIO", sock);

            va_start(ap, request);

            ic->cmd = *va_arg(ap, int*);


            va_end(ap);

            rc = transmit_lvlip(sock->lvlfd, msg, msglen);
            break; 
        default:
            print_err("ioctl %lu is not supported", request);
            rc = -1;
            errno = EINVAL;
            break;
    }

    return rc;
}

int __libc_start_main(int (*main) (int, char * *, char * *), int argc,
                      char * * ubp_av, void (*init) (void), void (*fini) (void),
                      void (*rtld_fini) (void), void (* stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    _sendto = dlsym(RTLD_NEXT, "sendto");
    _recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    _poll = dlsym(RTLD_NEXT, "poll");
    _ppoll = dlsym(RTLD_NEXT, "ppoll");
    _pollchk = dlsym(RTLD_NEXT, "__poll_chk");
    _select = dlsym(RTLD_NEXT, "select");
    _fcntl = dlsym(RTLD_NEXT, "fcntl");
    _setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    _getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    _read = dlsym(RTLD_NEXT, "read");
    _write = dlsym(RTLD_NEXT, "write");
    _connect = dlsym(RTLD_NEXT, "connect");
    _socket = dlsym(RTLD_NEXT, "socket");
    _close = dlsym(RTLD_NEXT, "close");
    _getpeername = dlsym(RTLD_NEXT, "getpeername");
    _getsockname = dlsym(RTLD_NEXT, "getsockname");
    _ioctl = dlsym(RTLD_NEXT, "ioctl");

    list_init(&lvlip_socks);

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}
