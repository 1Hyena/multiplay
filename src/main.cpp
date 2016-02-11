#include <sys/time.h>
#include <string.h>
#include <chrono>

#include "main.h"
#include "log.h"
#include "options.h"
#include "signals.h"
#include "sockets.h"
#include "manager.h"

OPTIONS options;
SIGNALS signals;
SOCKETS sockets;
MANAGER manager;

struct itimerval timer;
int tcp_listener = -1; // Descriptor for accepting and serving new connections.
bool terminate   = false;

size_t next_step_time = 1000000 / PULSE_PER_SECOND;
double cpu_usage = 0.0;

int main(int argc, char **argv) {
    if (!init(argc, argv)) {
        fprintf(stderr, "%s: failed to initialize.\n", argv[0]);
        return EXIT_FAILURE;
    }    
    if (options.exit_flag) return deinit();

    if (options.verbose) {
        log("Command line arguments loaded.");
        log("MultiPlay will listen on %s:%s for %s connections.",
            options.exposed ? "*"    : "localhost", options.port.c_str(),
            options.ipv6    ? "IPv6" : "IPv4");
    }

    if (options.ipv6) tcp_listener = sockets.listen_ipv6(options.port.c_str(), options.exposed);
    else              tcp_listener = sockets.listen     (options.port.c_str(), options.exposed);

    if (tcp_listener == -1) return deinit();

    log("\x1B[1;32mMultiPlay is ready to rock on %sport %s!\x1B[0m\x1B]0;MultiPlay\a", options.ipv6 ? "IPv6 " : "", options.port.c_str());

    setitimer(ITIMER_REAL, &timer, nullptr); // Needed to trigger the first SIGALRM for the main loop to activate.
    while (step());

    return deinit();
}

void init_timer(struct itimerval *t, size_t usec) {
    t->it_value.tv_sec     = usec / 1000000;
    t->it_value.tv_usec    = usec % 1000000;
    t->it_interval.tv_sec  = 0;
    t->it_interval.tv_usec = 0;
}

bool init(int argc, char **argv) {
    if (!options.init(argc, argv, &log_options) 
    ||  !signals.init(            &log_signals)
    ||  !sockets.init(            &log_sockets)
    ||  !manager.init(            &log_manager)) return false;

    init_timer(&timer, next_step_time);

    return true;
}

int deinit() {
    int result = EXIT_SUCCESS;
    if (!manager.deinit()) result = EXIT_FAILURE;
    if (tcp_listener != -1 && !sockets.close(tcp_listener)) result = EXIT_FAILURE;    
    if (!sockets.deinit()) result = EXIT_FAILURE;

    if (result == EXIT_FAILURE)  log("\x1B[1;31mMultiPlay closes with errors!\x1B[0m");
    else if (!options.exit_flag) log("\x1B[1;33mNormal termination of MultiPlay.\x1B[0m");
    return result;
}

bool wait(bool first, size_t max_usec) {
    bool alarmed = false;
    int user_id;

    // All non-fatal signals must be blocked before the resulting atomic
    // flags are checked because otherwise the signal could go lost if
    // it appears after atomic flag checking and before sockets.wait.
    signals.block();
    while (int sig = signals.next()) {
        char *str = strsignal(sig);
        switch (sig) {
            case SIGALRM:
                        {
                            alarmed = true; 
                            if (first && next_step_time > 1) {
                                // We ignore this block if next_step_time is equal to 1 because
                                // we do not wish to spam this line more than once in a row.
                                log("Warning! Process is lagging, CPU usage %2.1f%%.", cpu_usage);
                            }
                            if (!max_usec || first) max_usec = 1;

                            init_timer(&timer, max_usec);
                            setitimer(ITIMER_REAL, &timer, nullptr);                            
                            break;
                        }
            case SIGINT :
            case SIGTERM:
            case SIGQUIT: manager.broadcast("\n\rMultiPlay has terminated.\n\r"); terminate = true;
            default     : log("Caught signal %d (%s).", sig, str ? str : "NULL"); break;
        }
    }

    bool success = ((alarmed && !first) || sockets.wait(&manager.obuf));
    if (terminate) sockets.disconnect();
    signals.unblock(); // Signals can safely be unblocked after sockets.wait.

    if (alarmed && !first) return false;

    if (!success) {
        terminate = true;
        return true;
    }

    std::string host, port;
    int d;

    while ( (d = sockets.get_new_desc(&host, &port)) != -1 ) {
        log("New connection %d from %s:%s.", d, host.c_str(), port.c_str());

        user_id = manager.instance_create("user");
        if (user_id) {
            manager.set(user_id, "host", host.c_str());
            manager.set(user_id, "port", port.c_str());
            manager.set(user_id, "descriptor", d);
            manager.instance_activate(user_id);
            log("Created user %d (descriptor %d).", user_id, d);
        }
        else log("Unable to create a user (descriptor %d).", d);
    }

    if (!sockets.read(&manager.ibuf, &manager.ignored)) terminate = true;

    std::set<int> deleted;
    while ( (d = sockets.get_del_desc()) != -1 ) deleted.insert(d);
    
    for (auto del : deleted) {
        VARSET vs;
        log("Connection %d lost.", del);
        vs.set("descriptor", del);

        std::set<int> attached_users;
        manager.instance_find("user", &vs, &attached_users);

        for (int user_id : attached_users) {
            if (manager.instance_destroy(user_id)) log("Destroyed user %d (descriptor %d).", user_id, del);
            else {
                log("Unable to destroy user %d (descriptor %d).", user_id, del);
                break;
            }
        }
    }

    return true;
}

bool step() {
    std::chrono::duration<double> dt;
    std::chrono::time_point<std::chrono::steady_clock> t2, t1 = std::chrono::steady_clock::now();
    // Disconnect paralyzed users.
    for (auto d : manager.paralyzed) sockets.disconnect(d);

    // Perform the main update cycle.
    manager.step();

    t2 = std::chrono::steady_clock::now();
    size_t time_left, step_time = std::chrono::duration_cast<std::chrono::microseconds>(t2-t1).count();
    size_t time_debt = 0;
    size_t time_give = 0;
    cpu_usage = 100.0*step_time/next_step_time;

    // Wait until the time budget is spent.
    bool first = true;
    while (1) {
        time_left = next_step_time - std::min(step_time, next_step_time);
        if (!wait(first, time_left)) {
            // We got SIGALRM during last call to wait and it was not the first call.
            t2 = std::chrono::steady_clock::now();
            step_time = std::chrono::duration_cast<std::chrono::microseconds>(t2-t1).count();
            time_give = next_step_time - std::min(step_time, next_step_time);
            if (time_give > 0) log("Sleeping for extra %lu microseconds.", time_give);
            break;
        }
        first = false;

        t2 = std::chrono::steady_clock::now();
        step_time = std::chrono::duration_cast<std::chrono::microseconds>(t2-t1).count();

        if (step_time >= next_step_time) break; // Time limit exceeded, this is normal.
    }

    t2 = std::chrono::steady_clock::now();
    step_time = std::chrono::duration_cast<std::chrono::microseconds>(t2-t1).count();
    if (step_time < next_step_time) {
        if (step_time + time_give < next_step_time)
        log("Warning, step finished sooner than expected (%lu / %lu).", step_time, next_step_time);
    }
    else time_debt = step_time - next_step_time;

    next_step_time = 1000000/PPS + time_give;
    if (time_debt < next_step_time) next_step_time -= time_debt;
    else                            next_step_time = 1;

    signals.block();
    init_timer(&timer, next_step_time);
    setitimer(ITIMER_REAL, &timer, nullptr);
    signals.sig_alarm = 0;
    signals.unblock(); 

    return !terminate;
}

