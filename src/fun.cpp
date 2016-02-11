#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <set>

#include "sockets.h"
#include "utils.h"
#include "fun.h"
#include "manager.h"
#include "user.h"

void log(const char *p_fmt, ...);

bool is_logged(const char * command) {
    for (size_t i=0; ; ++i) {
        if (fun_table[i].name == nullptr) break;
        if (str_prefix(command, fun_table[i].name)) {
            return fun_table[i].logging;
        }
    }
    return false;
}

static void do_(USER *u, const char *arg) {} // Do nothing.

static void do_alarm(USER *u, const char *arg) {
    char pulse[8];
    arg = first_arg(arg, pulse, sizeof(pulse));

    int pulse_int;
    if (!str2int(&pulse_int, pulse, 10) || pulse_int < 0) {
        u->sendf("Alarm length '%s' is neither a positive integer nor zero.\n\r", pulse);
        return;
    }

    int shift_int = 0;
    if (strlen(arg) > 0 && !str2int(&shift_int, arg, 10)) {
        u->sendf("Alarm shift '%s' is not an integer.\n\r", arg);
        return;
    }

    u->manager->set(u->get_id(), "alarm_pulse", pulse_int);
    u->manager->set(u->get_id(), "alarm_shift", shift_int);

    if (pulse_int == 0) {
        u->send("Alarm disabled.\n\r");
        return;
    }

    if (shift_int != 0) u->sendf("Alarm set for every %d. pulse (correction %d).\n\r", pulse_int, shift_int);
    else                u->sendf("Alarm set for every %d. pulse.\n\r", pulse_int);
}

static void do_connect(USER *u, const char *arg) {
    char host[256];
    char port[8];
    char comment[256];
    arg = first_arg(arg, host, sizeof(host));
    arg = first_arg(arg, port, sizeof(port));
    std::snprintf(comment, sizeof(comment), "%s", arg);

    int port_int;
    if (!str2int(&port_int, port, 10) || port_int <= 0) {
        u->sendf("Port number '%s' is not a positive integer.\n\r", port);
        return;
    }

    if (port_int > 65535) {
        u->sendf("Port number '%s' exceeds 65535.\n\r", port);
        return;
    }

    std::snprintf(port, sizeof(port), "%d", port_int);
    MANAGER *m = u->manager;

    int d = sockets.connect(host, port);
    if (d <= 0) {
        u->sendf("Failed to connect to %s:%s.\n\r", host, port);
        return;
    }

    log("New connection %d to %s:%s.", d, host, port);

    int new_user_id = m->instance_create("user");
    if (new_user_id) {
        m->set(new_user_id, "host", host);
        m->set(new_user_id, "port", port);
        m->set(new_user_id, "descriptor", d);
        m->instance_activate(new_user_id);
        INSTANCE *ins = m->instance_find(new_user_id);
        if (ins && ins->user) {
            ins->user->disable_greet();
            if (ins->user->has_prompt()) ins->user->toggle_prompt();
            if (!ins->user->is_server()) ins->user->toggle_server();
        }
        log("Created user %d (descriptor %d).", new_user_id, d);
    }
    else {
        log("Unable to create a user (descriptor %d).", d);
        sockets.disconnect(d);
        return;
    }

    int shell = m->instance_create("shell");
    m->set(shell, "host",    host);
    m->set(shell, "port",    port);
    m->set(shell, "comment", comment);
    m->set(shell, "user_id", new_user_id);

    if (!m->instance_activate(shell)) {
        u->send("Failed to create a new shell.\n\r");
        sockets.disconnect(d);
        return;
    }

    m->set(new_user_id, "shell_id", shell);
    log("Created shell %d (%s:%s).", shell, host, port);
    u->sendf("Established a new connection to %s:%s as shell %d.\n\r", host, port, shell);
}

static void do_disconnect(USER *u, const char *arg) {
    int id;
    if (!str2int(&id, arg, 10) || id <= 0) {
        u->sendf("Argument '%s' is not a positive integer.\n\r", arg);
        return;
    }

    MANAGER *m = u->manager;
    if (!m->instance_exists(id)) {
        u->send("No such instance exists.\n\r");
        return;
    }

    VARSET vs;
    m->get_vs(id, &vs);

    if (!strcmp(vs.gets("object_name"), "user")) {
        INSTANCE *ins = m->instance_find(id);
        if (ins && ins->user) {
            std::string tag;
            ins->user->fetch_tag(&tag);
            ins->user->send("You have been disconnected.\n\r");
            ins->user->paralyze();
            u->sendf("Disconnecting %s.\n\r", tag.c_str());
        }
        return;
    }

    if (strcmp(vs.gets("object_name"), "shell")) {
        u->send("Target is not a shell.\n\r");
        return;
    }

    if (!m->instance_destroy(id)) {
        u->sendf("Failed to disconnect shell %d.\n\r", id);
        return;
    }

    log("Destroyed shell %d (%s:%s).", id, vs.gets("host"), vs.gets("port"));
    u->sendf("Shell %d is now disconnected.\n\r", id);
}

static void do_exit(USER *u, const char *arg) {
    if (u->has_role(ROLE_SU)) u->rem_role(ROLE_SU);
    else {
        u->send("Alas, all good things must come to an end ...\n\r");
        u->paralyze();
    }
}

static void do_help(USER *u, const char *arg) {
    char name[12];
    char desc[61];

    u->send(" o---------------------------[ Available Commands ]---------------------------o \n\r");
    for (size_t i=0;; ++i) {
        if (fun_table[i].name == nullptr) break;
        if (!u->has_role(fun_table[i].access)) continue;
        std::snprintf(name, sizeof(name), "%-11s", fun_table[i].name);
        std::snprintf(desc, sizeof(desc), "%-60s", fun_table[i].desc);
        u->send(" | ");
        u->send(name);
        u->send(" - ");
        u->send(desc);
        u->send(" | \n\r");
    }
    u->send(" o----------------------------------------------------------------------------o \n\r");
}

static void do_list(USER *u, const char *arg) {
    char id[7];
    char host[33];
    char port[7];
    char comment[30];

    u->send("List of shells you could switch into:\n\r");

    MANAGER *m = u->manager;
    std::set<int> shells;
    m->instance_find("shell", &shells);
    size_t count = 0;
    bool first = true;
    for (auto a : shells) {
        VARSET vs;
        m->get_vs(a, &vs);

        if (first) {
            u->send(" o------o--------------------------------o------o-----------------------------o\n\r");
            u->send(" | ID   | HOST                           | PORT | COMMENT                     |\n\r");
            u->send(" o------o--------------------------------o------o-----------------------------o\n\r");
            first = false;
        }

        std::snprintf(id,      sizeof(id),      "%6d",   a);
        std::snprintf(host,    sizeof(host),    "%-32s", vs.gets("host"));
        std::snprintf(port,    sizeof(port),    "%6s",   vs.gets("port"));
        std::snprintf(comment, sizeof(comment), "%29s",  vs.gets("comment"));

        u->sendf(" |%s|%s|%s|%s|\n\r", id, host, port, comment);
        count++;
    }
    if (count == 0) u->send("No shells available.\n\r");
    else u->send(" o------o--------------------------------o------o-----------------------------o\n\r");
}

static void do_log(USER *u, const char *arg) {
    log("%s", arg);
}

static void do_login(USER *u, const char *arg) {
    if (u->has_role(ROLE_AUTH)) {
        u->send("You have already been authenticated.\n\r");
        return;
    }

    if (strcmp(arg, "surramurra")) {
        u->send("Wrong password!\n\r");
        return;
    }

    u->add_role(ROLE_AUTH);
    u->send("You are now authenticated.\n\r");

    std::string tag;
    u->fetch_tag(&tag);
    log("%s has logged in.", tag.c_str());
}

static void do_prompt(USER *u, const char *arg) {
    u->toggle_prompt();
    if (u->has_prompt()) u->send("Prompt is now enabled.\n\r");
    else                 u->send("Prompt is now disabled.\n\r");
}

static void do_return(USER *u, const char *arg) {
    int user_id = u->get_id();
    VARSET user_vs;
    u->manager->get_vs(user_id,  &user_vs);
    int shell_id = user_vs.geti("shell_id");

    if (shell_id == 0) {
        u->send("You are not switched into any shell.\n\r");
        return;
    }

    if (!u->manager->instance_exists(shell_id)) {
        std::string tag;
        u->fetch_tag(&tag);
        u->manager->bug("%s returns from a non-existent shell %d.", tag.c_str(), shell_id);
    }

    u->manager->set(user_id, "shell_id", 0);
    u->sendf("You return from shell %d.\n\r", shell_id);
    if (!u->has_prompt()) u->toggle_prompt();
}

static void do_su(USER *u, const char *arg) {
    if (!strcmp("localhost", u->get_host())
    ||  !strcmp("127.0.0.1", u->get_host())) u->add_role(ROLE_SU|ROLE_AUTH);
    else u->send("Authentication failure.\n\r");
}

static void do_switch(USER *u, const char *arg) {
    int shell_id;
    int user_id = u->get_id();
    if (!str2int(&shell_id, arg, 10) || shell_id <= 0) {
        u->sendf("Argument '%s' is not a positive integer.\n\r", arg);
        return;
    }

    if (!u->manager->instance_exists(shell_id)) {
        u->send("No such shell exists.\n\r");
        return;
    }

    VARSET shell_vs;
    VARSET user_vs;
    u->manager->get_vs(shell_id, &shell_vs);
    u->manager->get_vs(user_id,  &user_vs);

    if (strcmp(shell_vs.gets("object_name"), "shell")) {
        u->send("Target cannot be switched into.\n\r");
        return;
    }

    if (user_vs.geti("shell_id") == shell_id) {
        u->send("You are already switched into that shell.\n\r");
        return;
    }   

    u->manager->set(user_id, "shell_id", shell_id);
    u->sendf("You are now switched into shell %d.\n\r", shell_id);
    if (u->has_prompt()) u->toggle_prompt();
}

const struct fun_type fun_table[] = {
    { "",           "Bust a prompt.",                                      do_,           ROLE_NONE, false },
    { "alarm",      "Sets an alarm for the defined number of pulses.",     do_alarm,      ROLE_AUTH, false },
    { "connect",    "Connect a new shell to a remote host/port.",          do_connect,    ROLE_AUTH, true  },
    { "disconnect", "Disconnect a user or a shell by its ID.",             do_disconnect, ROLE_SU,   true  },
    { "exit",       "Close the connection.",                               do_exit,       ROLE_NONE, false },
    { "help",       "Display the list of available commands.",             do_help,       ROLE_NONE, false },
    { "list",       "Lists all the shells you could switch into.",         do_list,       ROLE_AUTH, false },
    { "log",        "Log the text given as an argument.",                  do_log,        ROLE_SU,   false },
    { "login",      "Authenticate the current session.",                   do_login,      ROLE_NONE, false },
    { "prompt",     "Toggle the prompt that is shown after each command.", do_prompt,     ROLE_NONE, false },
    { "return",     "Return from your current shell.",                     do_return,     ROLE_AUTH, false },
    { "su",         "Elevate the current user to the superuser.",          do_su,         ROLE_NONE, true  },
    { "switch",     "Switch into another shell.",                          do_switch,     ROLE_AUTH, false },
    { nullptr,      nullptr,                                               nullptr,       0,         false }
};
