#include <string>
#include <getopt.h>

class OPTIONS {
    public:
    OPTIONS()  {}
    ~OPTIONS() {}

    int verbose             =  0;
    int exit_flag           =  0;
    int exposed             =  0;
    int ipv6                =  0;
    std::string port        = "";
    std::string name        = "";

    inline void print_usage (FILE* stream) {
        fprintf (stream, "Usage: %s [options] port\n", name.c_str());
        fprintf (stream, "Options:\n");        
        fprintf (stream,
            "      --brief           Print brief messages (default).\n"
            "  -h  --help            Display this usage information.\n"
            "      --ipv6            Accept IPv6 connections (default is IPv4).\n"
            "      --public          Allow connections from remote hosts.\n"
            "      --verbose         Print verbose messages.\n"
            "  -v  --version         Show version information.\n"
        );
    }
    
    inline bool init(int argc, char **argv, void (*log_function)(const char *p_fmt, ...)) {
        if (log_function) log = log_function;

        int c;
        name = argv[0];
        while (1) {
            static struct option long_options[] = {
                // These options set a flag:
                {"brief",               no_argument,         &verbose,           0 },
                {"ipv6",                no_argument,         &ipv6,              1 },
                {"verbose",             no_argument,         &verbose,           1 },
                {"public",              no_argument,         &exposed,           1 },
                // These options don't set a flag. We distinguish them by their indices:
                {"help",                no_argument,              0,            'h'},
                {"version",             no_argument,              0,            'v'},
                {0,                     0,                        0,             0 }
            };
            
            // getopt_long stores the option index here.
            int option_index = 0;
            
            c = getopt_long(argc, argv, "hv", long_options, &option_index);
            
            /* Detect the end of the options. */
            if (c == -1) break;
            
            switch (c) {
                case 0:
                    {
                        // If this option sets a flag do nothing else.
                        if (long_options[option_index].flag != 0) break;
                        std::string buf="option ";
                        buf.append(long_options[option_index].name);
                        if (optarg) {
                            buf.append(" with arg ");
                            buf.append(optarg);
                        }
                        log(buf.c_str());
                        break;
                    }
                case 'h': print_usage(stdout); exit_flag = 1; break;
                case 'v':
                    printf("MultiPlay %s Copyright (C) 2016 Hyena\n", MULTIPLAY_VERSION);
                    exit_flag = 1;
                    break;
                case '?':
                    // getopt_long already printed an error message.
                    break;
                default: return false;
            }
        }

        if (exit_flag) return true;
        
        if (optind < argc) {
            port = argv[optind++];

            if (atoi(port.c_str()) <= 0) {
                log("port number invalid: %s", port.c_str());
                return false;
            }
        }
        else {
            print_usage(stderr);
            log("port number missing.");
            return false;
        }

        while (optind < argc) log("unidentified argument: %s", argv[optind++]);
        return true;
    }
    
    private:
    inline static void drop_log(const char *p_fmt, ...) {}

    void (*log)(const char *p_fmt, ...) = drop_log;    
};

