#include <string>
#include <signal.h>

class SIGNALS {
    public:
    SIGNALS()  {}
    ~SIGNALS() {}

    inline bool init(void (*log_function)(const char *p_fmt, ...)) {
        if (log_function) log = log_function;

        if (sigfillset (&sigset_most) == -1) {
            log("sigfillset failed");
            return false;
        }
        if (sigdelset(&sigset_most, SIGSEGV) == -1
        ||  sigdelset(&sigset_most, SIGILL ) == -1
        ||  sigdelset(&sigset_most, SIGABRT) == -1
        ||  sigdelset(&sigset_most, SIGFPE ) == -1
        ||  sigdelset(&sigset_most, SIGBUS ) == -1
        ||  sigdelset(&sigset_most, SIGIOT ) == -1
        ||  sigdelset(&sigset_most, SIGTRAP) == -1
        ||  sigdelset(&sigset_most, SIGSYS ) == -1) {
            log("sigdelset failed");
            return false;
        }        
        if (sigemptyset(&sigset_none) == -1) {
            log("sigemptyset failed");
            return false;
        }
        
        if (sigprocmask(SIG_SETMASK, nullptr, &sigset_orig) == -1) {
            log("sigprocmask: %s", strerror(errno));
            return false;
        }

        if (!init_signal(SIGALRM)
        ||  !init_signal(SIGPIPE)
        ||  !init_signal(SIGINT )
        ||  !init_signal(SIGTERM)
        ||  !init_signal(SIGQUIT)
        ||  !init_signal(SIGSEGV)
        ||  !init_signal(SIGILL )
        ||  !init_signal(SIGABRT)
        ||  !init_signal(SIGFPE )
        ||  !init_signal(SIGBUS )
        ||  !init_signal(SIGIOT )
        ||  !init_signal(SIGTRAP)
        ||  !init_signal(SIGSYS )) return false;

        return true;
    }

    inline int next() {
        if (sig_int  ) {sig_int   = 0; return SIGINT; }
        if (sig_term ) {sig_term  = 0; return SIGTERM;}
        if (sig_quit ) {sig_quit  = 0; return SIGQUIT;}
        if (sig_pipe ) {sig_pipe  = 0; return SIGPIPE;}
        if (sig_alarm) {sig_alarm = 0; return SIGALRM;}
        return 0;
    }

    inline static void handle_signal(int sig) {
        switch (sig) {
            case SIGINT:  sig_int   = 1; return;
            case SIGTERM: sig_term  = 1; return;
            case SIGQUIT: sig_quit  = 1; return;
            case SIGPIPE: sig_pipe  = 1; return;
            case SIGALRM: sig_alarm = 1; return;
            default     : break;
        }

        // The only portable use of signal() is to set
        // a signal's disposition to SIG_DFL or SIG_IGN.
        signal(sig, SIG_DFL);

        // At this point the program has crashed anyway so calling unsafe
        // functions here (with respect to signals) can be tolerated.
        char *str = strsignal(sig);
        printf("Caught signal %d (%s).\n", sig, str ? str : "NULL");
        fflush(nullptr);
        
        raise(sig);
    }

    inline bool block() {
        if (sigprocmask(SIG_SETMASK, &sigset_most, nullptr) == -1) {
            log("sigprocmask: %s", strerror(errno));
            return false;
        }
        return true;
    }

    inline bool unblock() {
        if (sigprocmask(SIG_SETMASK, &sigset_orig, nullptr) == -1) {
            log("sigprocmask: %s", strerror(errno));
            return false;
        }
        return true;
    }

    static volatile sig_atomic_t sig_alarm;
    static volatile sig_atomic_t sig_pipe;
    static volatile sig_atomic_t sig_int;
    static volatile sig_atomic_t sig_term;
    static volatile sig_atomic_t sig_quit;

    sigset_t sigset_most;
    sigset_t sigset_none;
    sigset_t sigset_orig;
    
    private:
    void (*log)(const char *p_fmt, ...) = drop_log;

    inline static void drop_log(const char *p_fmt, ...) {}

    inline bool init_signal(int sig) {
        struct sigaction sa;
        sa.sa_handler = handle_signal; // Establish signal handler.
        sa.sa_flags   = 0;
        if (sigemptyset(&sa.sa_mask) == -1) {
            log("sigemptyset failed");
            return false;
        }
        if (sigaction(sig, &sa, NULL) == -1) {
            log("sigaction: %s", strerror(errno));
            return false;
        }
        return true;
    }
};

volatile sig_atomic_t SIGNALS::sig_alarm = 0;
volatile sig_atomic_t SIGNALS::sig_pipe  = 0;
volatile sig_atomic_t SIGNALS::sig_int   = 0;
volatile sig_atomic_t SIGNALS::sig_term  = 0;
volatile sig_atomic_t SIGNALS::sig_quit  = 0;

