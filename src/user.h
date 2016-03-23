#include <vector>

#include "utils.h"
#include "varset.h"

#define MAX_INPUT_LENGTH  65536 // Buffer size for incoming bytes from a single descriptor.
#define MAX_OUTPUT_LENGTH 65536 // Buffer size for outgoing bytes to a single descriptor.
#define MAX_COMMAND_LENGTH 1024

class USER {
    friend class MANAGER;

    public:
    inline const char *get_host      ()                {return host.c_str();        }
    inline void        set_host      (const char *str) {       host = str;          }
    inline const char *get_port      ()                {return port.c_str();        }    
    inline void        set_port      (const char *str) {       port = str;          }
    inline size_t      get_role      ()                {return roles;               }
    inline void        set_role      (size_t flags)    {       roles = flags;       }
    inline void        add_role      (size_t flags)    {       roles |= flags;      }
    inline void        rem_role      (size_t flags)    {       roles &= ~flags;     }
    inline bool        has_role      (size_t flags)    {return is_set(roles, flags);}
    inline void        paralyze      ()                {paralyzed = true;           }
    inline void        toggle_prompt ()                {prompt = !prompt;           }
    inline bool        has_prompt    ()                {return prompt;              }
    inline int         get_descriptor() const          {return descriptor;          }
    inline int         get_id        () const          {return id;                  }
    inline void        disable_greet ()                {greet_countdown = -1;       }
    inline bool        is_server     () const          {return server;              }
    inline void        toggle_server ()                {server = !server;           }

    void fetch_tag(std::string *to);
    void send(const char *text);
    void sendf(const char *p_fmt, ...);
    void send_bytes(const unsigned char *bytes, size_t count);
    bool process_input();

    class MANAGER *manager;

    private:
     USER() {}
    ~USER() {}

    void send_prompt();
    bool interpret(const char *command, const char *arg);

    std::vector<unsigned char> obuf;
    std::vector<unsigned char> ibuf;

    int id;
    int descriptor;
    bool paralyzed;
    size_t roles;
    bool prompt;
    int greet_countdown;
    bool server;
    
    std::string host;
    std::string port;

    static void create (class MANAGER *manager, int id, VARSET *vs);
    static void destroy(class MANAGER *manager, int id, VARSET *vs);
    static void step   (class MANAGER *manager, int id, VARSET *vs);
};

