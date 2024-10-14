// SPDX-License-Identifier: MIT
#include <iostream>
#include <stdarg.h>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <vector>

#include "options.h"
#include "program.h"
#include "signals.h"
#include "sockets.h"

volatile sig_atomic_t
    SIGNALS::sig_alarm{0},
    SIGNALS::sig_pipe {0},
    SIGNALS::sig_int  {0},
    SIGNALS::sig_term {0},
    SIGNALS::sig_quit {0};

size_t PROGRAM::log_size = 0;
bool   PROGRAM::log_time = false;

void PROGRAM::run() {
    if (!options) return bug();

    if (options->exit_flag) {
        status = EXIT_SUCCESS;
        return;
    }

    sockets->set_logger(
        [](SOCKETS::SESSION session, const char *text) noexcept {
            std::string line;
            char time[20];

            write_time(time, sizeof(time));
            line.append(time).append(" :: ");

            if (!session) {
                line.append("Sockets: ");
            }
            else {
                char buffer[20];
                std::snprintf(buffer, 20, "#%06lx: ", session.id);
                line.append(buffer);
            }

            const char *esc = "\x1B[0;31m";

            switch (session.error) {
                case SOCKETS::BAD_TIMING:    esc = "\x1B[1;33m"; break;
                case SOCKETS::LIBRARY_ERROR: esc = "\x1B[1;31m"; break;
                case SOCKETS::NO_ERROR:      esc = "\x1B[0;32m"; break;
                default: break;
            }

            line.append(esc).append(text).append("\x1B[0m").append("\n");
            print_text(stderr, line.c_str(), line.size());
        }
    );

    bool terminated = false;

    SOCKETS::SESSION session{
        sockets->listen(std::to_string(get_port()).c_str())
    };

    if (!session) {
        terminated = true;
        status = EXIT_FAILURE;
    }
    else {
        status = EXIT_SUCCESS;
        log_time = true;

        log("listening on port %d...", static_cast<int>(get_port()));
    }

    std::unordered_map<size_t, long long> timestamp_map;
    std::unordered_set<size_t> clients;

    static constexpr const size_t USEC_PER_SEC = 1000000;
    bool alarmed = false;
    set_timer(USEC_PER_SEC);

    do {
        alarmed = false;

        signals->block();
        while (int sig = signals->next()) {
            char *sig_name = strsignal(sig);

            switch (sig) {
                case SIGALRM: {
                    alarmed = true;
                    break;
                }
                case SIGINT :
                case SIGTERM:
                case SIGQUIT: {
                    terminated = true;
                    [[fallthrough]];
                }
                default     : {
                    // Since signals are blocked, we can call fprintf here.
                    fprintf(stderr, "%s", "\n");

                    log(
                        "caught signal %d (%s).", sig,
                        sig_name ? sig_name : "unknown"
                    );

                    break;
                }
            }
        }

        if (alarmed) set_timer(USEC_PER_SEC);

        signals->unblock();

        if (terminated) {
            sockets->disconnect(session.id);

            continue;
        }

        if (!alarmed && sockets->next_error() != SOCKETS::NO_ERROR) {
            log("Sockets: %s", sockets->to_string(sockets->last_error()));
            status = EXIT_FAILURE;
            terminated = true;
        }

        long long timestamp = get_timestamp();
        SOCKETS::ALERT alert;

        while ((alert = sockets->next_alert()).valid) {
            const size_t sid = alert.session;

            if (alert.event == SOCKETS::DISCONNECTION) {
                log(
                    "session #%06lx@%s:%s disconnected",
                    sid, sockets->get_host(sid), sockets->get_port(sid)
                );

                if (timestamp_map.count(sid)) {
                    timestamp_map.erase(sid);
                }

                if (clients.count(sid)) {
                    clients.erase(sid);
                    continue;
                }
            }
            else if (alert.event == SOCKETS::CONNECTION) {
                timestamp_map[sid] = timestamp;

                SOCKETS::SESSION listener = sockets->get_listener(sid);

                if (listener.id == session.id) {
                    clients.insert(sid);
                }
                else {
                    log("forbidden condition met (%s:%d)", __FILE__, __LINE__);
                }

                log(
                    "session #%06lx@%s:%s connected",
                    sid, sockets->get_host(sid), sockets->get_port(sid)
                );
            }
            else if (alert.event == SOCKETS::INCOMING) {
                log(
                    "session #%06lx@%s:%s: %s", sid, sockets->get_host(sid),
                    sockets->get_port(sid), sockets->read(sid)
                );
                timestamp_map[sid] = timestamp;
            }
        }

        if (alarmed) {
            log("%s", "alarmed");
        }

        uint32_t idle_timeout = 10;

        if (idle_timeout > 0 && alarmed) {
            for (const auto &p : timestamp_map) {
                if (timestamp - p.second >= idle_timeout) {
                    size_t sid = p.first;

                    if (is_verbose()) {
                        log(
                            "session #%06lx@%s:%s has timed out",
                            sid, sockets->get_host(sid), sockets->get_port(sid)
                        );
                    }

                    sockets->disconnect(sid);
                }
            }
        }
    }
    while (!terminated);

    return;
}

bool PROGRAM::init(int argc, char **argv) {
    signals = new (std::nothrow) SIGNALS(print_log);
    if (!signals) return false;

    if (!signals->init()) {
        return false;
    }

    options = new (std::nothrow) OPTIONS(get_version(), print_log);
    if (!options) return false;

    if (!options->init(argc, argv)) {
        return false;
    }

    sockets = new (std::nothrow) SOCKETS();
    if (!sockets) return false;

    return sockets->init();
}

int PROGRAM::deinit() {
    if (sockets) {
        if (!sockets->deinit()) {
            status = EXIT_FAILURE;
            bug();
        }

        delete sockets;
        sockets = nullptr;
    }

    if (options) {
        delete options;
        options = nullptr;
    }

    if (signals) {
        delete signals;
        signals = nullptr;
    }

    return get_status();
}

int PROGRAM::get_status() const {
    return status;
}

size_t PROGRAM::get_log_size() {
    return PROGRAM::log_size;
}

void PROGRAM::write_time(char *buffer, size_t length) {
    struct timeval timeofday;
    gettimeofday(&timeofday, nullptr);

    time_t timestamp = (time_t) timeofday.tv_sec;
    struct tm *tm_ptr = gmtime(&timestamp);

    if (!strftime(buffer, length, "%Y-%m-%d %H:%M:%S", tm_ptr)) {
        buffer[0] = '\0';
    }
}

bool PROGRAM::print_text(FILE *fp, const char *text, size_t len) {
    // Because fwrite may be interrupted by a signal, we block them.

    sigset_t sigset_all;
    sigset_t sigset_orig;

    if (sigfillset(&sigset_all) == -1) {
        return false;
    }
    else if (sigprocmask(SIG_SETMASK, &sigset_all, &sigset_orig) == -1) {
        return false;
    }

    fwrite(text , sizeof(char), len, fp);

    if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
        return false;
    }

    return true;
}

void PROGRAM::print_log(const char *origin, const char *p_fmt, ...) {
    va_list ap;
    char *buf = nullptr;
    char *newbuf = nullptr;
    int buffered = 0;
    int	size = 1024;

    if (p_fmt == nullptr) return;
    buf = (char *) malloc (size * sizeof (char));

    while (1) {
        va_start(ap, p_fmt);
        buffered = vsnprintf(buf, size, p_fmt, ap);
        va_end (ap);

        if (buffered > -1 && buffered < size) break;
        if (buffered > -1) size = buffered + 1;
        else               size *= 2;

        if ((newbuf = (char *) realloc (buf, size)) == nullptr) {
            free (buf);
            return;
        } else {
            buf = newbuf;
        }
    }

    std::string logline;
    logline.reserve(size);

    if (PROGRAM::log_time) {
        char timebuf[20];
        struct timeval timeofday;
        gettimeofday(&timeofday, nullptr);

        time_t timestamp = (time_t) timeofday.tv_sec;
        struct tm *tm_ptr = gmtime(&timestamp);

        if (!strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_ptr)) {
            timebuf[0] = '\0';
        }

        logline.append(timebuf);
        logline.append(" :: ");
    }

    if (origin && *origin) {
        logline.append(origin);
        logline.append(": ");
    }

    logline.append(buf);

    if (origin) logline.append("\n");

    PROGRAM::log_size += logline.size();
    print_text(stderr, logline.c_str(), logline.size());
    free(buf);
}

void PROGRAM::log(const char *p_fmt, ...) {
    va_list ap;
    char *buf = nullptr;
    char *newbuf = nullptr;
    int buffered = 0;
    int	size = 1024;

    if (p_fmt == nullptr) return;
    buf = (char *) malloc (size * sizeof (char));

    while (1) {
        va_start(ap, p_fmt);
        buffered = vsnprintf(buf, size, p_fmt, ap);
        va_end (ap);

        if (buffered > -1 && buffered < size) break;
        if (buffered > -1) size = buffered + 1;
        else               size *= 2;

        if ((newbuf = (char *) realloc (buf, size)) == nullptr) {
            free (buf);
            return;
        } else {
            buf = newbuf;
        }
    }

    print_log("", "%s", buf);
    free(buf);
}

void PROGRAM::bug(const char *file, int line) {
    log("bug on line %d of %s", line, file);
}

const char *PROGRAM::get_version() const {
    return VERSION;
}

uint16_t PROGRAM::get_port() const {
    return options->port;
}

bool PROGRAM::is_verbose() const {
    return options->verbose;
}

void PROGRAM::set_timer(size_t usec) {
    timer.it_value.tv_sec     = usec / 1000000;
    timer.it_value.tv_usec    = usec % 1000000;
    timer.it_interval.tv_sec  = 0;
    timer.it_interval.tv_usec = 0;

    setitimer(ITIMER_REAL, &timer, nullptr);
}

long long PROGRAM::get_timestamp() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}
