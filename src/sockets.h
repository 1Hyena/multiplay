#include <sys/epoll.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <signal.h>
#include <queue>
#include <map>
#include <set>

class SOCKETS {
    public:
    SOCKETS()  {clear();}
    ~SOCKETS() {if (events) log("deinit not called (memory leak)");}

    static const int EPOLL_MAX_EVENTS = 64;

    inline bool init(void (*log_function)(const char *p_fmt, ...)) {
        if (log_function) log = log_function;

        if (events) {
            log("already initialized");
            return false;
        }
        events = nullptr;
        epoll_descriptor = -1;

        if (sigfillset(&sigset_all) == -1) {
            log("sigfillset failed");
            return false;
        }
        if (sigemptyset(&sigset_none) == -1) {
            log("sigemptyset failed");
            return false;
        }

        epoll_descriptor = epoll_create1(0);
        if (epoll_descriptor == -1) {
            log("epoll_create1: %s", strerror(errno));
            return false;
        }

        // Buffer where events are returned:
        events = (struct epoll_event *) calloc(EPOLL_MAX_EVENTS, sizeof event);
        if (events == nullptr) {
            log("unable to allocate memory for events");
            return false;
        }

        return true;
    }

    inline bool deinit() {
        bool success = true;
        
        if (events) {
            free(events);
            events=nullptr;
        }
        else {
            log("already deinitialized");
            success = false;
        }

        if (epoll_descriptor != -1) {
            if (!safe_close(epoll_descriptor)) success = false;
        }
        
        clear();
        
        return success;
    }

    inline int listen_ipv6(const char *port, bool exposed) {
        return listen(port, exposed, AF_INET6);
    }

    inline int listen_ipv4(const char *port, bool exposed) {
        return listen(port, exposed, AF_INET);
    }

    inline int listen_any(const char *port, bool exposed) {
        return listen(port, exposed, AF_UNSPEC);
    }

    inline int listen(const char *port, bool exposed) {
        return listen_ipv4(port, exposed);
    }

    inline int connect(const char *host, const char *port) {
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int s, sfd;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = AF_UNSPEC;   // Return IPv4 and IPv6 choices
        hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
        hints.ai_flags    = AI_PASSIVE;  // All interfaces

        s = getaddrinfo(host, port, &hints, &result);
        if (s != 0) {
            log("getaddrinfo: %s", gai_strerror(s));
            return -1;
        }

        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            bool failure = false;

            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1) continue;

            // Blocking all signals before ::connect will guarantee
            // that it will not fail having errno set to EINTR.
            if (sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig) == -1) {
                log("sigprocmask: ", strerror(errno));
                failure = true;
            }
            else {
                s = ::connect(sfd, rp->ai_addr, rp->ai_addrlen);
                int e = errno;
                if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
                    log("sigprocmask: ", strerror(errno));
                    failure = true;
                }
                else {
                    if (s == 0) {
                        if (make_socket_non_blocking(sfd)) break;
                    }
                    else log("connect(%d, ?, %d): %s", sfd, rp->ai_addrlen, strerror(e));
                }
            }

            if (failure) {
                safe_close(sfd);
                sfd = -1;
                goto CleanUp;
            }

            if (!safe_close(sfd)) {
                sfd = -1;
                goto CleanUp;
            }
        }
        
        if (rp == nullptr) sfd = -1;
        else if (sfd != -1) {
            event.data.fd = sfd;
            event.events = EPOLLIN|EPOLLET;
            s = epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, sfd, &event);
            if (s == -1) {
                log("epoll_ctl: %s", strerror(errno));
                safe_close(sfd);
                sfd = -1;
                goto CleanUp;
            }
            
            descriptors[-1].insert(sfd);
        }

        CleanUp:
        freeaddrinfo(result);
        return sfd;
    }
    
    inline bool forward(int d1, int d2) {
        if (disconnections.count(d1) > 0
        ||  disconnections.count(d2) > 0
        ||  del_descs.count(d1)      > 0
        ||  del_descs.count(d2)      > 0) return false;
        shortcuts[d1] = d2;
        return true;
    }

    inline bool close(int d) {
        if (d != -1 && descriptors.find(d) == descriptors.end()) {
            log("attempt to close an invalid descriptor %d", d);
            return false;
        }
        if (!safe_close(d)) return false;
        return true;
    }
    
    inline void disconnect() {
        for (auto a : descriptors) {
            for (auto d : descriptors[a.first]) {
                disconnect(d);
            }
        }
    }

    inline void disconnect(int d) {
        if (disconnections.count(d) > 0
        ||  del_descs.count(d) > 0) return;
        disconnections.insert(d);
        if (shutdown(d, SHUT_WR) == -1) {
            log("shutdown(%d, SHUT_WR): %s", d, strerror(errno));
        }
    }

    inline bool wait(std::map<int, std::vector<unsigned char>> *outbuf) {
        if (epoll_descriptor == -1 || !events) {
            log("sockets uninitialized");
            return false;
        }
        
        if (!new_descs.empty()) {
            // We cannot operate on existing descriptors until the user has
            // acknowledged the new descriptors added during previous wait.
            log("new descriptor set full");
            return false;
        }
        
        if (!del_descs.empty()) {
            // We cannot operate on existing descriptors until the user has
            // acknowledged the descriptors deleted during previous wait.
            log("deleted descriptor set full");
            return false;
        }

        if (outbuf) {
            for (auto v : *outbuf) {
                std::vector<unsigned char> *bytes = &((*outbuf)[v.first]);
                size_t sz = bytes->size();
                if (sz == 0) continue;
                size_t written = write(v.first, &(*bytes)[0], sz);
                if (written == sz) bytes->clear();
                else if (written == 0) continue;
                else {
                    std::vector<unsigned char> remaining;
                    for (size_t i=written; i<sz; ++i) {
                        remaining.push_back(bytes->at(i));
                    }
                    bytes->swap(remaining);
                }
            }
        }

        int n, i;
        n = epoll_pwait(epoll_descriptor, events, EPOLL_MAX_EVENTS, -1, &sigset_none);
        if (n == -1) {
            if (errno == EINTR) goto Disconnect;
            log("epoll_pwait: %s", strerror(errno));
            return false;
        }

        new_hosts.clear();
        new_ports.clear();

        for (i=0; i<n; i++) {
            if ((  events[i].events & EPOLLERR )
//          ||  (  events[i].events & EPOLLHUP ) // Commented out because disconnections are detected with ::read anyway.
            ||  (!(events[i].events & EPOLLIN) )) {
                int       socket_error  = 0;
                socklen_t socket_errlen = sizeof(socket_error);
                int d = events[i].data.fd;

                // An error has occured on this fd, or the socket is not
                // ready for reading (why were we notified then?)

                

                if (events[i].events & EPOLLERR
                &&  getsockopt(d, SOL_SOCKET, SO_ERROR, (void *) &socket_error, &socket_errlen) == 0) {
                    log("epoll error on %d: %s", d, strerror(socket_error));
                }
                else log("epoll error on descriptor %d", d);

                if (!safe_close(d)) return false;
                continue;
            }
            else if (descriptors.find(events[i].data.fd) != descriptors.end()) {
                // We have a notification on the listening socket, which means one or more incoming connections.
                while (1) {
                    struct sockaddr in_addr;
                    socklen_t in_len;
                    int infd, s;
                    char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                    in_len = sizeof in_addr;
                    infd = accept(events[i].data.fd, &in_addr, &in_len);
                    if (infd == -1) {
                        if ((errno == EAGAIN     )
                        ||  (errno == EWOULDBLOCK)) {
                            break; // We have processed all incoming connections.
                        }
                        else {
                            log("accept: %s", strerror(errno));
                            break;
                        }
                    }

                    s = getnameinfo(&in_addr, in_len, hbuf, sizeof hbuf, sbuf, sizeof sbuf, NI_NUMERICHOST|NI_NUMERICSERV);
                    if (s == 0) {
                        new_hosts[infd] = hbuf;
                        new_ports[infd] = sbuf;
                    }
                    else log("getnameinfo: %s", gai_strerror(s));

                    // Make the incoming socket non-blocking and add it to the list of fds to monitor.
                    if (!make_socket_non_blocking(infd)) return false;

                    event.data.fd = infd;
                    event.events = EPOLLIN|EPOLLET;
                    s = epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, infd, &event);
                    if (s == -1) {
                        log("epoll_ctl: ", strerror(errno));
                        return false;
                    }
                    
                    new_descs.insert(infd);
                    descriptors[events[i].data.fd].insert(infd);
                }
                continue;
            }
            else ready.insert(events[i].data.fd);
        }

        Disconnect:
        while (!disconnections.empty()) {
            int d = *disconnections.begin();
            disconnections.erase(d);
            for (auto a : descriptors) {
                if (descriptors[a.first].count(d) > 0) {
                    if (!safe_close(d)) return false;
                    break;
                }
            }
        }
        return true;
    }
    
    inline bool read(std::map<int, std::vector<unsigned char>> *inbuf, std::set<int> *ignore) {
        std::set<int> ignored;
        while (!ready.empty()) {
            int d = *ready.begin();
            ready.erase(d);
            
            if (new_descs.count(d) == 0 && (!ignore || ignore->count(d) == 0) ) {
                // We have data on the fd waiting to be read. Read and
                // display it. We must read whatever data is available
                // completely, as we are running in edge-triggered mode
                // and won't get a notification again for the same
                // data.
                int done = 0;

                while (1) {
                    ssize_t count;
                    char buf[65536];

                    count = ::read(d, buf, sizeof buf);
                    if (count == -1) {
                        // If errno == EAGAIN, that means we have read all data. So go back to the main loop.
                        if (errno != EAGAIN) {
                            log("read: ", strerror(errno));
                            done = 1;
                        }
                        break;
                    }
                    else if (count == 0) {
                        // End of file. The remote has closed the connection.
                        done = 1;
                        break;
                    }

                    if (shortcuts.count(d) > 0) {
                        int d2 = shortcuts[d];
                        // Forward the buffer to another descriptor.
                        if (write(d2, (const unsigned char *) buf, count) <= 0) {
                            done = 1;
                            break;
                        }
                    }
                    else if (inbuf != nullptr) {
                        for (ssize_t k=0; k<count; ++k) {
                            (*inbuf)[d].push_back(buf[k]);
                        }
                    }
                    
                    ignored.insert(d);
                    break;
                }

                if (done) {
                    // Closing the descriptor will make epoll remove it
                    // from the set of descriptors which are monitored.
                    if (!safe_close(d)) {
                        goto Fail;
                    }
                }
            }
            else ignored.insert(d);
        }
        ready.swap(ignored);
        return true;
        
        Fail:
        ready.insert(ignored.begin(), ignored.end());
        return false;
    }
    
    inline size_t write(int d, const unsigned char *bytes, size_t length) {
        if (length == 0) return 0;

        size_t iStart, nBlock;
        ssize_t nWrite;

        for (iStart = 0; iStart<length; iStart+=nWrite) {
            int buf = length - iStart;
            nBlock = (buf < 4096 ? buf : 4096);
            nWrite = ::write(d, bytes+iStart, nBlock);
            if (nWrite <= 0) {
                log("::write: %s", strerror(errno));
                return (nWrite > 0 ? nWrite : 0);
            }
        }

        return length;
    }

    inline bool send_to_desc(int d, const char *text) {
        size_t len = strlen(text);
        if (len == 0) return true;
        return (write(d, (const unsigned char *) text, len) > 0);
    }

    inline int get_new_desc(std::string *host, std::string *port) {
        if (new_descs.empty()) return -1;
        int d = *new_descs.begin();
        new_descs.erase(d);
        
        if (host != nullptr) {
            if (new_hosts.find(d) != new_hosts.end()) {
                host->assign(new_hosts[d]);
                new_hosts.erase(d);
            }
            else host->assign("unknown");
        }
        
        if (port != nullptr) {
            if (new_ports.find(d) != new_ports.end()) {
                port->assign(new_ports[d]);
                new_ports.erase(d);
            }
            else port->assign("unknown");
        }        
        
        return d;
    }

    inline int get_del_desc() {
        if (del_descs.empty()) return -1;
        int d = *del_descs.begin();
        del_descs.erase(d);
        return d;
    }

    private:
    int epoll_descriptor;
    struct epoll_event event;
    struct epoll_event *events;
    sigset_t sigset_all;
    sigset_t sigset_none;
    sigset_t sigset_orig;
    std::set<int> new_descs; // New descriptors.
    std::set<int> del_descs; // Deleted descriptors.
    std::map<int, std::string> new_hosts;
    std::map<int, std::string> new_ports;
    std::map<int, std::set<int>> descriptors; // Acceptor -> descriptors mapping.
    std::set<int> disconnections; // Descriptors to be disconnected.
    std::set<int> ready; // Descriptors that can be read from. 
    std::map<int, int> shortcuts; // One-way interconnections between descriptors.
    void (*log)(const char *p_fmt, ...) = drop_log;

    inline static void drop_log(const char *p_fmt, ...) {}

    inline void clear() {
        events = nullptr;
        epoll_descriptor = -1;
        new_hosts.clear();
        new_ports.clear();
        new_descs.clear();
        del_descs.clear();
        descriptors.clear();
        disconnections.clear();
        ready.clear();
        shortcuts.clear();
    }
    
    bool safe_close(int fd) {
        // Blocking all signals before ::close will guarantee
        // that it will not fail having errno set to EINTR.
        if (sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig) == -1) {
            log("sigprocmask: %s", strerror(errno));
            return false;
        }
        int c = ::close(fd);
        int e = errno;
        if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
            log("sigprocmask: %s", strerror(errno));
            return false;
        }
        if (c == -1) {
            log("close: %s", strerror(e));
            if (e != EINTR) return false;
        }
        bool success = true;
        if (descriptors.count(fd) > 0) {
            std::set<int> children;
            for (auto d : descriptors[fd]) {
                if (descriptors.count(d) != 0) {
                    log("descriptor is its own acceptor");
                    return false;
                }
                children.insert(d);
            }
            
            while (!children.empty()) {
                int child = *children.begin();
                children.erase(child);
                if (!safe_close(child)) {
                    log("failed to close %d's child descriptor %d", fd, child); 
                    success = false;
                }
            }

            descriptors.erase(fd);
        }
        else {
            for (auto a : descriptors) {
                if (descriptors[a.first].count(fd) > 0) {
                    descriptors[a.first].erase(fd);
                    del_descs.insert(fd);
                    ready.erase(fd);
                    if (shortcuts.count(fd) > 0) {
                        int sc = shortcuts[fd];
                        shortcuts.erase(fd);
                        shortcuts.erase(sc);
                    }
                }
            }
        }

        return success;
    }

    inline int listen(const char *port, bool exposed, int family) {
        int sfd = create_and_bind(port, exposed, family);
        if (sfd == -1) return -1;

        if (!make_socket_non_blocking(sfd)
        ||  ::listen(sfd, SOMAXCONN) == -1) goto Fail;

        event.data.fd = sfd;
        event.events = EPOLLIN|EPOLLET;
        if (epoll_ctl(epoll_descriptor, EPOLL_CTL_ADD, sfd, &event) == -1) {
            log("epoll_ctl: %s", strerror(errno));
            goto Fail;
        }

        if (sfd != -1) descriptors[sfd];
        return sfd;
        
        Fail:
        safe_close(sfd);
        return -1;
    }

    inline int create_and_bind(const char *port, bool exposed, int family) {
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        int s, sfd, x=1;
        
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family   = family;
        hints.ai_socktype = SOCK_STREAM; // We want a TCP socket
        hints.ai_flags    = exposed ? AI_PASSIVE : 0;  // All interfaces?

        s = getaddrinfo(nullptr, port, &hints, &result);
        if (s != 0) {
            log("getaddrinfo: ", gai_strerror(s));
            return -1;
        }

        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (sfd == -1) continue;

            if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,(char *) &x, sizeof(x)) == -1) {
                log("setsockopt: ", strerror(errno));
            }
            else {
                s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
                if (s == 0) break; // We managed to bind successfully!
                log("bind(%d, ?, %d): %s", sfd, rp->ai_addrlen, strerror(errno));
            }

            if (!safe_close(sfd)) {
                sfd = -1;
                goto Fail;
            }
        }
        
        if (rp == nullptr) sfd = -1;

        Fail:
        freeaddrinfo(result);
        return sfd;        
    }

    inline bool make_socket_non_blocking(int sfd) {
        int flags, s;

        flags = fcntl(sfd, F_GETFL, 0);
        if (flags == -1) {
            log("fcntl: %s", strerror(errno));
            return false;
        }

        flags |= O_NONBLOCK;
        s = fcntl (sfd, F_SETFL, flags);
        if (s == -1) {
            log("fcntl: %s", strerror(errno));
            return false;
        }

        return true;
    }
};

