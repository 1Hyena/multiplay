#include<cstring>

#include "main.h"
#include "log.h"
#include "manager.h"
#include "user.h"
#include "fun.h"
#include "sockets.h"

void USER::step(MANAGER *manager, int id, VARSET *vs) {
    INSTANCE *ins = manager->instance_find(id);
    if (!ins || !ins->user) return;

    USER *u = ins->user;
    int desc = u->get_descriptor();
    bool ignored = (manager->ignored.count(desc) > 0);
    manager->ignored.erase(desc);

    // First copy the incoming bytes into the user's personal buffer.
    if (manager->ibuf.count(desc) > 0) {
        auto ibd = &manager->ibuf[desc];
        u->ibuf.insert(std::end(u->ibuf), std::begin(*ibd), std::end(*ibd));
        manager->ibuf[desc].clear();
    }

    // If the user is not frozen, process its input.
    if (!ignored) {
        size_t input_before = u->ibuf.size();
        u->process_input();
        size_t input_after = u->ibuf.size();

        // Finally bust a prompt if needed and clear the higher level output buffer.
        size_t osz = u->obuf.size();
        if (osz > 0 || input_after != input_before) {
            /*
            if (input_after == input_before
            &&  u->obuf.back() != '\r'
            &&  u->obuf.back() != '\n') {
                u->obuf.push_back('\n');
                u->obuf.push_back('\r');
            }
            */
            u->send_prompt();
        }
    }

    // Finally copy the user's outgoing bytes into their lower level buffer.
    if (manager->obuf.count(desc) > 0) {
        auto obd = &manager->obuf[desc];
        if (obd->size() > 0) {
            // This descriptor's output is not empty yet, do not read from it.
            manager->ignored.insert(desc);
            if (!ignored) {
                size_t ssz = obd->size()+u->obuf.size();
                log("User %d is frozen while receiving %lu byte%s.", u->id, ssz, ssz == 1 ? "" : "s");
            }
        }
        obd->insert(std::end(*obd), std::begin(u->obuf), std::end(u->obuf));
    }
    u->obuf.clear();
    
    if (ignored && manager->ignored.count(desc) == 0) log("User %d is no longer frozen.", u->id);
    if (u->paralyzed) manager->paralyzed.insert(desc);    

    //log("%d:%d: %lu %lu", id, descriptor, ibuf.size(), obuf.size());
    if (u->greet_countdown == 0) {
        char buf[4096];
        const char *message =
        "\x1B]0;MultiPlay Client\a\n\r"
        " Welcome to MultiPlay Server v%-4s\n\r"
        " %32s\n\r"
        "\n\r";

        int cx = std::snprintf(buf, sizeof(buf), message, MULTIPLAY_VERSION, "-- Implemented by Hyena 2016");
        if (cx >= 0 && cx+1 <= (int) sizeof(buf)) u->send(buf);
        else u->send("Cannot display the greeting screen (buffer not big enough).\n\r");

        u->send("Type \x1B[1;32mhelp\x1B[0m to see the available commands.\n\r");
        u->greet_countdown = -1;
    } else u->greet_countdown--;
}

void USER::process_input() {
    std::vector<unsigned char> *bytes = &ibuf;
    size_t sz = bytes->size();

    if (sz == 0 || paralyzed) return;

    if (server) {
        VARSET vs;
        manager->get_vs(id, &vs);
        int shell_id = vs.geti("shell_id");

        VARSET find_vs; find_vs.set("shell_id", shell_id);
        std::set<int> subscribers;
        manager->instance_find(&find_vs, &subscribers);
        
        for (auto sid : subscribers) {
            if (sid == id) continue;
            INSTANCE *ins = manager->instance_find(sid);
            if (ins && ins->user) {
                ins->user->send_bytes(&ibuf[0], ibuf.size());
            }
        }
        
        bytes->clear();
        return;
    }
    
    //if (options.verbose) {
    //    log("Connection %d has sent us %lu byte%s.", v.first, sz, sz == 1 ? "" : "s");
    //}

    std::string line;
    std::vector<unsigned char> remaining;
    size_t count = get_line(bytes, &line);
    if (count == 0) {
        if (bytes->size() > MAX_INPUT_LENGTH) {
            log("User %d is kicked for flooding.", id);
            write_to_buffer(&obuf, "Put a lid on it ! ! !\n\r");
            paralyzed = true;
        }
        return;
    }

    sz = bytes->size();
    for (size_t i=0; i<sz; ++i) {
        if (i<count) continue;
        remaining.push_back(bytes->at(i));
    }

    bytes->swap(remaining);

    VARSET vs;
    manager->get_vs(id, &vs);
    int shell_id = vs.geti("shell_id");
    if (manager->instance_exists(shell_id)) {
        VARSET shell_vs;
        manager->get_vs(shell_id, &shell_vs);
        int user_id = shell_vs.geti("user_id");
        if (manager->instance_exists(user_id)) {
            // If this user is switched to another server then only interpret
            // commands that start with a dollar sign. Otherwise, forward the
            // command to the other server.
            if (line.length() > 0 && line.at(0) == '$') line.erase(0, 1);
            else {
                INSTANCE *ins = manager->instance_find(user_id);
                if (ins && ins->user) {
                    ins->user->sendf("%s\n", line.c_str());

                    std::string tag; fetch_tag(&tag);
                    VARSET find_vs; find_vs.set("shell_id", shell_id);
                    std::set<int> subscribers;
                    manager->instance_find(&find_vs, &subscribers);

                    for (auto sid : subscribers) {
                        if (sid == id || sid == user_id) continue;
                        INSTANCE *ins = manager->instance_find(sid);
                        if (!ins || !ins->user) continue;
                        ins->user->sendf("%s: %s\n\r", tag.c_str(), line.c_str());
                    }                    
                }
                return;
            }
        }
    }

    if (count+1 <= MAX_COMMAND_LENGTH) {
        char command_name[MAX_COMMAND_LENGTH];
        const char *args = first_arg(line.c_str(), command_name, sizeof(command_name));            

        if (is_logged(command_name)) {
            std::string tag;
            fetch_tag(&tag);
            char buf[32];
            size_t i;
            for (i=0; i<19 && args[i]; ++i) {
                buf[i] = args[i];
                if (buf[i] == 27) buf[i]='e';
            }
            buf[i] = '\0';
            if (i==19) strcat(buf, "...");

            if (strlen(buf) > 0) log("%s: %s '%s'", tag.c_str(), (const char *) command_name, buf);
            else                 log("%s: %s",      tag.c_str(), (const char *) command_name);        
        }
        
        interpret(command_name, args);
        greet_countdown = -1;
    }
    else send("Command line too long!\n\r");    
}

bool USER::interpret(const char* command, const char* arg) {
    for (size_t i=0; ; ++i) {
        if (fun_table[i].name == NULL) break;
        if (!is_set(roles, fun_table[i].access)) continue;
        if (str_prefix(command, fun_table[i].name)) {
            if (manager->instance_exists(id)) fun_table[i].function(this, arg);
            return true;
        }
    }

    if (prompt) send("Unknown command!\n\r");
    return false;
}

void USER::send_bytes(const unsigned char *bytes, size_t count) {
    if (paralyzed) return;

    std::vector<unsigned char> *to = &obuf;    
    if (to->size() + count > MAX_OUTPUT_LENGTH) {
        log("User %d is kicked for leeching.", id);
        paralyzed = true;
        write_to_buffer(to, "Stop leeching so many bytes ! ! !\n\r");
        return;    
    }

    for (size_t i=0; i<count; ++i) obuf.push_back(bytes[i]);
}

void USER::send(const char *text) {
    send_bytes((const unsigned char *) text, std::strlen(text));
}

void USER::sendf(const char *format, ...) {
    char buffer[1024];
    va_list args;
    va_start(args, format);
    int cx = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    if (cx >= 0 && (size_t)cx < sizeof(buffer)) send(buffer);
    else {
        std::vector<unsigned char> bytes;
        for (size_t i=0; format[i]; ++i) {
            unsigned char c = format[i];
            if (isprint(c)) bytes.push_back(c);
            if (bytes.size() >= 27) {
                bytes.push_back('.');
                bytes.push_back('.');
                bytes.push_back('.');
                break;
            }
        }
        bytes.push_back(0);
        manager->bug("String `%s` does not fit in the USER::sendf buffer.", &bytes[0]);
    }
}


void USER::send_prompt() {
    char buf[256];
    if (paralyzed || !prompt) return;

    std::string tag;
    fetch_tag(&tag);

    if (is_set(roles, ROLE_SU)) {
        sprintf(buf, "\n\r[ \x1B[1;31m%s\x1B[0m \x1B[1;34m%s \x1B[0m]\x1B[1;34m#\x1B[0m ", host.c_str(), tag.c_str());
    }
    else {
        sprintf(buf, "\n\r[ \x1B[1;32m%s@%s\x1B[0m ]\x1B[1;34m$\x1B[0m ", tag.c_str(), host.c_str());
    }

    send(buf);
}

void USER::fetch_tag(std::string *to) {
    char buf[256];
    sprintf(buf, "User %04d", id);
    to->append(buf);
}

void USER::create(class MANAGER *manager, int id, VARSET *vs) {
    INSTANCE *ins = manager->instance_find(id);
    if (!ins || ins->user) return;
    int descriptor = ins->vs.geti("descriptor");

    USER *u = new (std::nothrow) USER();
    ins->user = u;
    if (!u) {
        manager->instance_destroy(id);
        return;
    }

    u->id = id;
    u->descriptor = descriptor;
    u->paralyzed = false;
    u->roles = ROLE_NONE;
    u->prompt = true;
    u->server = false;
    u->port = ins->vs.gets("port");
    u->host = ins->vs.gets("host");
    u->greet_countdown = 1*PPS;
    u->manager = manager;

    manager->descriptors[descriptor].insert(u->id);
    if (manager->ibuf.count(descriptor) == 0) manager->ibuf[descriptor].clear();
    if (manager->obuf.count(descriptor) == 0) manager->obuf[descriptor].clear();
}

void USER::destroy(class MANAGER *manager, int id, VARSET *vs) {
    INSTANCE *ins = manager->instance_find(id);
    if (!ins || !ins->user) return;

    VARSET user_vs;
    manager->get_vs(id, &user_vs);
    const char *host = user_vs.gets("host");
    const char *port = user_vs.gets("port");
    int shell_id = user_vs.geti("shell_id");
    int new_descriptor = 0;

    if (manager->instance_exists(shell_id)) {
        manager->set(id, "shell_id", 0);

        VARSET shell_vs;
        manager->get_vs(shell_id, &shell_vs);
        if (shell_vs.geti("user_id") == id) {
            // This user represents a conneciton to the remote host.
            // Check if this connection has any clients. If it has clients,
            // reconnect immediately.
            bool destroy_shell = true;
            VARSET find_vs;
            find_vs.set("shell_id", shell_id);
            bool has_users = (manager->instance_find("user", &find_vs) > 0);
            if (has_users) {
                // Reconnect because this shell has users.
                int d = sockets.connect(host, port);
                if (d <= 0) log("Failed to connect to %s:%s.", host, port);
                else {
                    log("New connection %d to %s:%s.", d, host, port);

                    int new_user_id = manager->instance_create("user");
                    if (new_user_id) {
                        manager->set(new_user_id, "host", host);
                        manager->set(new_user_id, "port", port);
                        manager->set(new_user_id, "descriptor", d);
                        manager->instance_activate(new_user_id);
                        INSTANCE *new_ins = manager->instance_find(new_user_id);
                        if (new_ins && new_ins->user) {
                            new_ins->user->disable_greet();
                            if (new_ins->user->has_prompt()) new_ins->user->toggle_prompt();
                            if (!new_ins->user->is_server()) new_ins->user->toggle_server();
                        }
                        log("Created user %d (descriptor %d).", new_user_id, d);
                        
                        manager->set(shell_id,     "user_id", new_user_id);
                        manager->set(new_user_id, "shell_id", shell_id);
                        log("Shell %d reconnected as user %d.", shell_id, new_user_id);
                        new_descriptor = d;
                        destroy_shell = false;
                    }
                    else {
                        log("Unable to create a user (descriptor %d).", d);
                        sockets.disconnect(d);
                    }
                }
            }

            if (destroy_shell) {
                if (!manager->instance_destroy(shell_id)) manager->bug("Failed to destroy shell %d.", shell_id);
                else log("Destroyed shell %d (%s:%s).", shell_id, host, port);
            }
        }
    }

    int descriptor = ins->user->get_descriptor();
    if (manager->descriptors.count(descriptor) > 0
    && (!new_descriptor || descriptor != new_descriptor)) {
        manager->descriptors[descriptor].erase(id);
        if (manager->descriptors[descriptor].empty()) {
            manager->descriptors.erase(descriptor);
            manager->obuf.erase(descriptor);
            manager->ibuf.erase(descriptor);
            manager->paralyzed.erase(descriptor);
        }
    }

    delete ins->user;
    ins->user = nullptr;
}

