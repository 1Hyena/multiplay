// SPDX-License-Identifier: MIT
#ifndef OPTIONS_H_01_01_2021
#define OPTIONS_H_01_01_2021

#include <string>
#include <limits>
#include <getopt.h>

class OPTIONS {
    public:

    OPTIONS(
        const char *version,
        void      (*log_fun) (const char *, const char *, ...) =drop_log,
        const char *log_src ="Options"
    ) : verbose         (      0)
      , exit_flag       (      0)
      , port            (      0)
      , name            (     "")
      , version         (version)
      , logfrom         (log_src)
      , log             (log_fun) {}

    ~OPTIONS() {}

    int verbose;
    int exit_flag;
    uint16_t port;
    std::string name;

    static constexpr const char *usage{
        "Options:\n"
        "      --brief         Print brief information (default).\n"
        "  -h  --help          Display this usage information.\n"
        "      --verbose       Print verbose information.\n"
        "  -v  --version       Show version information.\n"
    };

    std::string print_usage() const {
        char line[256];

        std::snprintf(
            line, sizeof(line),
            "Usage: %s [options] port\n",
            name.c_str()
        );

        std::string result(line);

        return result.append(usage);
    }

    bool init(int argc, char **argv) {
        int c;
        name = argv[0];

        while (1) {
            static struct option long_options[] = {
                // These options set a flag:
                {"brief",       no_argument,       &verbose,   0 },
                {"verbose",     no_argument,       &verbose,   1 },
                // These options may take an argument:
                {"help",        no_argument,       0,        'h' },
                {"version",     no_argument,       0,        'v' },
                {0,             0,                 0,          0 }
            };

            int option_index = 0;
            c = getopt_long(
                argc, argv, "hv", long_options, &option_index
            );

            if (c == -1) break; // End of command line parameters?

            switch (c) {
                case 0: {
                    // If this option sets a flag do nothing else.
                    if (long_options[option_index].flag != 0) break;

                    std::string buf="option ";
                    buf.append(long_options[option_index].name);

                    if (optarg) {
                        buf.append(" with arg ");
                        buf.append(optarg);
                    }

                    log(logfrom.c_str(), buf.c_str());
                    break;
                }
                case 'h': {
                    log(nullptr, "%s\n", print_usage().c_str());
                    exit_flag = 1;
                    break;
                }
                case 'v':
                    log(nullptr, "%s\n", version.c_str());
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
            const char *port_str = argv[optind++];
            int p = atoi(port_str);

            if (p <= 0 || p > std::numeric_limits<uint16_t>::max()) {
                log(
                    logfrom.c_str(), "invalid port number: %s", port_str
                );
                return false;
            }

            port = uint16_t(p);
        }
        else {
            log(nullptr, "%s\n", print_usage().c_str());
            log(
                logfrom.c_str(), "%s", "missing argument: port"
            );

            return false;
        }

        while (optind < argc) {
            log(
                logfrom.c_str(), "unidentified argument: %s", argv[optind++]
            );
        }

        return true;
    }

    private:
    static void drop_log(const char *, const char *, ...) {}

    std::string version;
    std::string logfrom;
    void (*log)(const char *, const char *p_fmt, ...);
};

#endif
