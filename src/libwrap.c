/*
 *   stunnel       Universal SSL tunnel
 *   Copyright (C) 1998-2008 Michal Trojnara <Michal.Trojnara@mirt.net>
 *
 *   This program is free software; you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by the
 *   Free Software Foundation; either version 2 of the License, or (at your
 *   option) any later version.
 * 
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *   See the GNU General Public License for more details.
 * 
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, see <http://www.gnu.org/licenses>.
 * 
 *   Linking stunnel statically or dynamically with other modules is making
 *   a combined work based on stunnel. Thus, the terms and conditions of
 *   the GNU General Public License cover the whole combination.
 * 
 *   In addition, as a special exception, the copyright holder of stunnel
 *   gives you permission to combine stunnel with free software programs or
 *   libraries that are released under the GNU LGPL and with code included
 *   in the standard release of OpenSSL under the OpenSSL License (or
 *   modified versions of such code, with unchanged license). You may copy
 *   and distribute such a system following the terms of the GNU GPL for
 *   stunnel and the licenses of the other code concerned.
 * 
 *   Note that people who make modified versions of stunnel are not obligated
 *   to grant this special exception for their modified versions; it is their
 *   choice whether to do so. The GNU General Public License gives permission
 *   to release a modified version without this exception; this exception
 *   also makes it possible to release a modified version which carries
 *   forward this exception.
 */

#include "common.h"
#include "prototypes.h"

#ifdef USE_LIBWRAP

#include <tcpd.h>

static int check_libwrap(char *, int);

int allow_severity=LOG_NOTICE, deny_severity=LOG_WARNING;

#ifdef USE_PTHREAD
static ssize_t read_fd(int, void *, size_t, int *);
static ssize_t write_fd(int, void *, size_t, int);

int num_processes=0;
static int *ipc_socket, *busy;
#endif /* USE_PTHREAD */


void libwrap_init(int num) {
#ifdef USE_PTHREAD
    int i, j, rfd, result;
    char servname[STRLEN];

    num_processes=num;
    if(!num_processes) /* no extra processes to spawn */
        return;
    ipc_socket=calloc(2*num_processes, sizeof(int));
    busy=calloc(num_processes, sizeof(int));
    if(!ipc_socket || !busy) {
        s_log(LOG_ERR, "Memory allocation failed");
        die(1);
    }
    for(i=0; i<num_processes; ++i) { /* spawn a child */
        if(socketpair(AF_UNIX, SOCK_STREAM, 0, ipc_socket+2*i)) {
            sockerror("socketpair");
            die(1);
        }
        switch(fork()) {
        case -1:    /* error */
            ioerror("fork");
            die(1);
        case  0:    /* child */
            drop_privileges(); /* libwrap processes are not chrooted */
            /* FIXME: other file descriptors are not closed */
            close(ipc_socket[2*i]); /* server-side socket */
            for(j=0; j<i; ++j) /* previously created client-side sockets */
                close(ipc_socket[2*j+1]);
            while(1) { /* main libwrap client loop */
                if(read_fd(ipc_socket[2*i+1], servname, STRLEN, &rfd)<=0)
                    _exit(0);
                result=check_libwrap(servname, rfd);
                write(ipc_socket[2*i+1], (u8 *)&result, sizeof(result));
                if(rfd>=0)
                    close(rfd);
            }
        default:    /* parent */
#ifdef FD_CLOEXEC
            fcntl(ipc_socket[2*i], F_SETFD, FD_CLOEXEC); /* server-side socket */
#endif
            close(ipc_socket[2*i+1]); /* client-side socket */
        }
    }
#endif /* USE_PTHREAD */
}

void auth_libwrap(CLI *c) {
    int result=0; /* deny by default */
#ifdef USE_PTHREAD
    volatile static int num_busy=0, roundrobin=0;
    int retval, my_process;
    static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t cond=PTHREAD_COND_INITIALIZER;

    if(num_processes) {
        s_log(LOG_DEBUG, "Waiting for a libwrap process");

        retval=pthread_mutex_lock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_lock");
            longjmp(c->err, 1);
        }
        while(num_busy==num_processes) { /* all child processes are busy */
            retval=pthread_cond_wait(&cond, &mutex);
            if(retval) {
                errno=retval;
                ioerror("pthread_cond_wait");
                longjmp(c->err, 1);
            }
        }
        while(busy[roundrobin]) /* find a free child process */
            roundrobin=(roundrobin+1)%num_processes;
        my_process=roundrobin; /* the process allocated by this thread */
        ++num_busy; /* the child process has been allocated */
        busy[my_process]=1; /* mark the child process as busy */
        retval=pthread_mutex_unlock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_unlock");
            longjmp(c->err, 1);
        }

        s_log(LOG_DEBUG, "Acquired libwrap process #%d", my_process);
        write_fd(ipc_socket[2*my_process], c->opt->servname,
            strlen(c->opt->servname)+1, c->local_rfd.fd);
        read_blocking(c, ipc_socket[2*my_process],
            (u8 *)&result, sizeof(result));
        s_log(LOG_DEBUG, "Releasing libwrap process #%d", my_process);

        retval=pthread_mutex_lock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_lock");
            longjmp(c->err, 1);
        }
        busy[my_process]=0; /* mark the child process as free */
        --num_busy; /* the child process has been released */
        if(num_busy==num_processes-1) { /* need to wake up a thread */
            retval=pthread_cond_signal(&cond); /* signal waiting threads */
            if(retval) {
                errno=retval;
                ioerror("pthread_cond_signal");
                longjmp(c->err, 1);
            }
        }
        retval=pthread_mutex_unlock(&mutex);
        if(retval) {
            errno=retval;
            ioerror("pthread_mutex_unlock");
            longjmp(c->err, 1);
        }

        s_log(LOG_DEBUG, "Released libwrap process #%d", my_process);
    } else
#endif /* USE_PTHREAD */
    { /* use original, synchronous libwrap calls */
        enter_critical_section(CRIT_LIBWRAP);
        result=check_libwrap(c->opt->servname, c->local_rfd.fd);
        leave_critical_section(CRIT_LIBWRAP);
    }
    if(!result) {
        s_log(LOG_WARNING, "%s REFUSED by libwrap from %s",
            c->opt->servname, c->accepted_address);
        s_log(LOG_DEBUG, "See hosts_access(5) manual for details");
        longjmp(c->err, 1);
    }
    s_log(LOG_DEBUG, "%s permitted by libwrap from %s",
        c->opt->servname, c->accepted_address);
}

static int check_libwrap(char *name, int fd) {
    struct request_info request;

    request_init(&request, RQ_DAEMON, name, RQ_FILE, fd, 0);
    fromhost(&request);
    return hosts_access(&request);
}

#ifdef USE_PTHREAD

static ssize_t read_fd(int fd, void *ptr, size_t nbytes, int *recvfd) {
    struct msghdr msg;
    struct iovec iov[1];
    ssize_t n;

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control=control_un.control;
    msg.msg_controllen=sizeof(control_un.control);
#else
    int newfd;

    msg.msg_accrights=(caddr_t)&newfd;
    msg.msg_accrightslen=sizeof(int);
#endif

    msg.msg_name=NULL;
    msg.msg_namelen=0;

    iov[0].iov_base=ptr;
    iov[0].iov_len=nbytes;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;

    *recvfd=-1; /* descriptor was not passed */
    n=recvmsg(fd, &msg, 0);
    if(n<=0)
        return n;

#ifdef HAVE_MSGHDR_MSG_CONTROL
    cmptr=CMSG_FIRSTHDR(&msg);
    if(!cmptr || cmptr->cmsg_len!=CMSG_LEN(sizeof(int)))
        return n;
    if(cmptr->cmsg_level!=SOL_SOCKET) {
        s_log(LOG_ERR, "control level != SOL_SOCKET");
        return -1;
    }
    if(cmptr->cmsg_type!=SCM_RIGHTS) {
        s_log(LOG_ERR, "control type != SCM_RIGHTS");
        return -1;
    }
    *recvfd=*((int *)CMSG_DATA(cmptr));
#else
    if(msg.msg_accrightslen==sizeof(int))
        *recvfd=newfd;
#endif

    return n;
}

static ssize_t write_fd(int fd, void *ptr, size_t nbytes, int sendfd) {
    struct msghdr msg;
    struct iovec iov[1];

#ifdef HAVE_MSGHDR_MSG_CONTROL
    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int))];
    } control_un;
    struct cmsghdr *cmptr;

    msg.msg_control=control_un.control;
    msg.msg_controllen=sizeof(control_un.control);

    cmptr=CMSG_FIRSTHDR(&msg);
    cmptr->cmsg_len=CMSG_LEN(sizeof(int));
    cmptr->cmsg_level=SOL_SOCKET;
    cmptr->cmsg_type=SCM_RIGHTS;
    *((int *)CMSG_DATA(cmptr))=sendfd;
#else
    msg.msg_accrights=(caddr_t)&sendfd;
    msg.msg_accrightslen=sizeof(int);
#endif

    msg.msg_name=NULL;
    msg.msg_namelen=0;

    iov[0].iov_base=ptr;
    iov[0].iov_len=nbytes;
    msg.msg_iov=iov;
    msg.msg_iovlen=1;

    return sendmsg(fd, &msg, 0);
}

#endif /* USE_PTHREAD */

#endif /* USE_LIBWRAP */

/* End of libwrap.c */
