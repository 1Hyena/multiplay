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
    int pulse_int = 0;
    int shift_int = 0;
    
    if (strlen(arg) > 0) {
        arg = first_arg(arg, pulse, sizeof(pulse));

        if (!str2int(pulse, &pulse_int, 10) || pulse_int < 0) {
            u->sendf("Alarm length '%s' is neither a positive integer nor zero.\n\r", pulse);
            return;
        }

        if (strlen(arg) > 0) {
            if (!str2int(arg, &shift_int, 10)) {
                u->sendf("Alarm shift '%s' is not an integer.\n\r", arg);
                return;
            }
        }
        else if (pulse_int > 0) {
            // Adjust the shift so that the alarm would go off immediately.
            shift_int = u->manager->get_pulse() % pulse_int + 1;
        }
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

static void do_broadcas(USER *u, const char *arg) {
    u->send("Do you mean to broadcast? You must type in the full command.\n\r");
}

static void do_broadcast(USER *u, const char *arg) {
    MANAGER *m = u->manager;
    INSTANCE *ins = m->instance_find(u->get_id());
    if (!ins || !ins->user) return;

    bool broadcast_before = ins->vs.getb("broadcast");
    if (*arg == 0) {
        ins->vs.set("broadcast", !broadcast_before);
        bool broadcast_after = ins->vs.getb("broadcast");

        if (broadcast_after) u->send("Broadcasting is now enabled.\n\r");
        else                 u->send("Broadcasting is now disabled.\n\r");
        return;
    }

    if (!broadcast_before) return;

    for (size_t i=0; arg[i]; ++i) {
        if (std::iscntrl(arg[i])) {
            u->sendf("'%s' contains illegal characters.\n\r", arg);
            return;
        }
    }

    if (strlen(ins->vs.gets("team")) == 0) {
        u->send("You cannot broadcast unless you are in a team.\n\r");
        return;
    }

    std::string name;
    u->fetch_tag(&name);

    VARSET find_vs;
    find_vs.set("team", ins->vs.gets("team"));
    std::set<int> members;
    m->instance_find("user", (const VARSET *) &find_vs, &members);
    for (auto member_id : members) {
        if (member_id == u->get_id()) continue;
        INSTANCE *ins_member = m->instance_find(member_id);
        if (ins_member->vs.geti("subscribed") != u->get_id()) continue;
        ins_member->user->sendf("%s: %s\n\r", name.c_str(), arg);
    }
}

static void do_chat(USER *u, const char *arg) {
    size_t i;
    MANAGER *m = u->manager;
    INSTANCE *ins = m->instance_find(u->get_id());
    if (!ins || !ins->user) return;

    for (i=0; arg[i]; ++i) {
        if (std::iscntrl(arg[i])) {
            u->sendf("'%s' contains illegal characters.\n\r", arg);
            return;
        }
    }

    if (i == 0) {
        u->send("Chat what?\n\r");
        return;
    }

    if (strlen(ins->vs.gets("team")) == 0) {
        u->send("You cannot chat unless you are in a team.\n\r");
        return;
    }

    std::string name;
    u->fetch_tag(&name);

    VARSET find_vs;
    find_vs.set("team", ins->vs.gets("team"));
    std::set<int> members;
    m->instance_find("user", (const VARSET *) &find_vs, &members);
    for (auto member_id : members) {
        INSTANCE *ins_member = m->instance_find(member_id);
        ins_member->user->sendf("%s chats: '%s'.\n\r", name.c_str(), arg);
    }
}

static void do_claim(USER *u, const char *arg) {
    size_t i;
    MANAGER *m = u->manager;
    INSTANCE *ins = m->instance_find(u->get_id());
    if (!ins || !ins->user) return;

    for (i=0; arg[i]; ++i) {
        if (!std::isalnum(arg[i])) {
            u->sendf("'%s' contains illegal characters.\n\r", arg);
            return;
        }
    }

    if (i == 1) {
        u->send("Name length must be at least two characters.\n\r");
        return;
    }

    if (i > 16) {
        u->send("Name length must not exceed 16 characters.\n\r");
        return;
    }

    std::string old_name;
    std::string new_name = capitalize(arg);
    u->fetch_tag(&old_name);

    if (!strcasecmp(old_name.c_str(), new_name.c_str())) {
        u->sendf("You are already known as %s.\n\r", old_name.c_str());
        return;
    }

    ins->vs.set("name", new_name.c_str());
    new_name.clear();
    u->fetch_tag(&new_name);
    log("%s claims a new name and becomes %s.", old_name.c_str(), new_name.c_str());
    u->sendf("You are now known as %s.\n\r", new_name.c_str());

    if (strlen(ins->vs.gets("team")) > 0) {    
        VARSET find_vs;
        find_vs.set("team", ins->vs.gets("team"));
        std::set<int> members;
        m->instance_find("user", (const VARSET *) &find_vs, &members);
        for (auto member_id : members) {
            if (member_id == u->get_id()) continue;
            INSTANCE *ins_member = m->instance_find(member_id);
            ins_member->user->sendf("%s claims a new name and becomes %s.\n\r", old_name.c_str(), new_name.c_str());
        }
    }
}

static void do_connect(USER *u, const char *arg) {
    char host[256];
    char port[8];
    char pass[32];
    char comment[256];
    arg = first_arg(arg, host, sizeof(host));
    arg = first_arg(arg, port, sizeof(port));
    arg = first_arg(arg, pass, sizeof(pass));
    std::snprintf(comment, sizeof(comment), "%s", arg);

    int port_int;
    if (!str2int(port, &port_int, 10) || port_int <= 0) {
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
    m->set(shell, "host",       host);
    m->set(shell, "port",       port);
    m->set(shell, "password",   pass);
    m->set(shell, "comment",    comment);
    m->set(shell, "user_id",    new_user_id);
    m->set(shell, "persistent", true);

    if (!m->instance_activate(shell)) {
        u->send("Failed to create a new shell.\n\r");
        sockets.disconnect(d);
        return;
    }

    m->set(new_user_id, "shell_id", shell);
    log("Created shell %d (%s:%s).", shell, host, port);
    u->sendf("Established a new %s connection to %s:%s as shell %d.\n\r", pass[0] ? "private" : "public", host, port, shell);
    if (pass[0]) u->sendf("You can only switch into this private shell by typing 'switch %s'.\n\r", pass);
}

static void do_disconnect(USER *u, const char *arg) {
    int id;
    if (!str2int(arg, &id, 10) || id <= 0) {
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
        bool pass = (vs.gets("password")[0] != '\0');
        if (pass && !u->has_role(ROLE_SU)) continue;

        if (first) {
            u->send(" o------o--------------------------------o------o-----------------------------o\n\r");
            u->send(" | ID   | HOST                           | PORT | COMMENT                     |\n\r");
            u->send(" o------o--------------------------------o------o-----------------------------o\n\r");
            first = false;
        }

        std::snprintf(id,   sizeof(id),   "%6d",   a);
        std::snprintf(host, sizeof(host), "%-32s", vs.gets("host"));
        std::snprintf(port, sizeof(port), "%6s",   vs.gets("port"));
        if (pass) {
            std::string combuf = vs.gets("comment");
            combuf.resize(19);
            std::snprintf(comment, sizeof(comment), "%-19s (PRIVATE)", combuf.c_str());
        }
        else std::snprintf(comment, sizeof(comment), "%-29s", vs.gets("comment"));

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

static void do_provide(USER *u, const char *arg) {
    char pass[32];
    char comment[256];
    MANAGER *m = u->manager;

    int user_id = u->get_id();
    VARSET user_vs;
    u->manager->get_vs(user_id,  &user_vs);

    if (u->manager->instance_exists(user_vs.geti("shell_id"))) {
        u->send("You cannot provide a shell while being switched into another shell.\n\r");
        return;
    }

    arg = first_arg(arg, pass, sizeof(pass));
    std::snprintf(comment, sizeof(comment), "%s", arg);

    std::string host = u->get_host();
    std::string port = u->get_port();

    int shell = m->instance_create("shell");
    m->set(shell, "host",       host.c_str());
    m->set(shell, "port",       port.c_str());
    m->set(shell, "password",   pass);
    m->set(shell, "comment",    comment);
    m->set(shell, "user_id",    user_id);
    if (!m->instance_activate(shell)) {
        u->send("Failed to create a new shell.\n\r");
        return;
    }

    INSTANCE *ins = m->instance_find(user_id);
    if (ins && ins->user) {
        if (ins->user->has_prompt()) ins->user->toggle_prompt();
        if (!ins->user->is_server()) ins->user->toggle_server();
    }

    m->set(user_id, "shell_id", shell);
    log("User %d becomes a shell %d (%s:%s).", user_id, shell, host.c_str(), port.c_str());
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

static void do_subscribe(USER *u, const char *arg) {
    MANAGER *m = u->manager;
    INSTANCE *ins = m->instance_find(u->get_id());
    if (!ins || !ins->user) return;

    std::string name;
    u->fetch_tag(&name);
    int subscribed = ins->vs.geti("subscribed");

    if (*arg == 0) {
        ins->vs.set("subscribed", 0);

        INSTANCE *subscribed_ins;
        if ( (subscribed_ins = m->instance_find(subscribed)) ) {
            std::string subscribed_tag;
            subscribed_ins->user->fetch_tag(&subscribed_tag);
            u->sendf("You are no longer subscribed to %s's broadcast.\n\r", subscribed_tag.c_str());
            subscribed_ins->user->sendf("%s is no longer subscribed to your broadcast.\n\r", name.c_str());
        }
        else u->send("Subscribe to whose broadcast?\n\r");
        return;
    }

    if (strlen(ins->vs.gets("team")) == 0) {
        u->send("You cannot subscribe unless you are in a team.\n\r");
        return;
    }

    bool found = false;
    VARSET find_vs;
    find_vs.set("team", ins->vs.gets("team"));
    std::set<int> members;
    m->instance_find("user", (const VARSET *) &find_vs, &members);
    for (auto member_id : members) {
        if (member_id == u->get_id()) continue;
        INSTANCE *ins_member = m->instance_find(member_id);
        std::string member_name;
        ins_member->user->fetch_tag(&member_name);
        if (str_prefix(arg, member_name.c_str())) {
            if (member_id == subscribed) {
                u->sendf("You have already subscribed to %s's broadcast.\n\r", member_name.c_str());
            }
            else {
                ins_member->user->sendf("%s subscribed to your broadcast.\n\r", name.c_str());
                u->sendf("You are now subscribed to %s's broadcast.\n\r", member_name.c_str());
                ins->vs.set("subscribed", member_id);
                INSTANCE *old_subscribe = m->instance_find(subscribed);
                if (old_subscribe) old_subscribe->user->sendf("%s is no longer subscribed to your broadcast.\n\r", name.c_str());
            }
            found = true;
            break;
        }
    }

    if (!found) {
        u->send("No such user is in a team with you.\n\r");
    }
}

static void do_switch(USER *u, const char *arg) {
    int shell_id = 0;
    int user_id = u->get_id();
    bool authenticated = false;

    if (strlen(arg) > 0) {
        VARSET find_vs;
        find_vs.set("password", arg);
        shell_id = u->manager->instance_find("shell", &find_vs);
        if (shell_id) authenticated = true;
    }

    if (!shell_id) {
        if (!str2int(arg, &shell_id, 10) || shell_id <= 0) {
            u->sendf("Argument '%s' is not a positive integer nor a valid shell password.\n\r", arg);
            return;
        }
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

    if (shell_vs.gets("password")[0] && !authenticated && !u->has_role(ROLE_SU)) {
        u->sendf("Shell %d is password protected.\n\r", shell_id);
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

void do_team(USER *u, const char *arg) {
    size_t i;
    MANAGER *m = u->manager;
    INSTANCE *ins = m->instance_find(u->get_id());
    if (!ins || !ins->user) return;

    for (i=0; arg[i]; ++i) {
        if (std::iscntrl(arg[i])) {
            u->sendf("Team password contains illegal characters.\n\r", arg);
            return;
        }
    }

    if (i > 32) {
        u->send("Team passwords's length must not exceed 32 characters.\n\r");
        return;
    }

    std::string old_team = ins->vs.gets("team");
    std::string tag;
    VARSET find_vs;
    std::set<int> members;

    if (i == 0) {
        if (old_team.length() > 0) {
            find_vs.set("team", old_team.c_str());
            m->instance_find("user", (const VARSET *) &find_vs, &members);
            u->sendf("There %s %lu member%s in your team:\n\r", members.size() == 1 ? "is" : "are", members.size(), members.size() == 1 ? "" : "s");

            for (auto member_id : members) {
                INSTANCE *ins_member = m->instance_find(member_id);
                tag.clear();
                ins_member->user->fetch_tag(&tag);
                u->sendf(" - %-16s (%s:%s)\n\r", tag.c_str(), ins_member->user->get_host(), ins_member->user->get_port());
            }

            u->sendf("\n\rTeam password: %s\n\r", ins->vs.gets("team"));
            u->send("To leave your team, provide its password as an argument.\n\r");
        }
        else {
            u->send("You are currently not part of any team.\n\r");
            u->send("To create or join a team, execute this command with a password.\n\r");
        }
        return;
    }

    u->fetch_tag(&tag);

    if (old_team.length() > 0) {
        find_vs.set("team", old_team.c_str());
        m->instance_find("user", (const VARSET *) &find_vs, &members);
        for (auto member_id : members) {
            if (member_id == u->get_id()) continue;
            INSTANCE *ins_member = m->instance_find(member_id);
            ins_member->user->sendf("%s has left the team.\n\r", tag.c_str());
        }
    }

    if (!strcmp(arg, old_team.c_str())) {
        // Leaving a team.
        ins->vs.set("team", "");
        u->send("You leave your team.\n\r");
        return;
    }

    members.clear();
    find_vs.clear();
    find_vs.set("team", arg);
    m->instance_find("user", (const VARSET *) &find_vs, &members);

    for (auto member_id : members) {
        INSTANCE *ins_member = m->instance_find(member_id);
        ins_member->user->sendf("%s has joined the team.\n\r", tag.c_str());
    }

    ins->vs.set("team", arg);
    u->sendf("Your team password is now set to '%s'.\n\r", arg);
}

const struct fun_type fun_table[] = {
    { "",           "Bust a prompt.",                                      do_,           ROLE_NONE, false },
    { "alarm",      "Set an alarm for the defined number of pulses.",      do_alarm,      ROLE_NONE, false },
    { "broadcas",   "Broadcast without having typed the full command.",    do_broadcas,   ROLE_NONE, false },
    { "broadcast",  "Toggle broadcasting or send a message to your team.", do_broadcast,  ROLE_NONE, false },
    { "chat",       "Send a message to your team.",                        do_chat,       ROLE_NONE, false },
    { "claim",      "Claim a temporary username.",                         do_claim,      ROLE_NONE, false },
    { "connect",    "Connect a new shell to a remote host/port.",          do_connect,    ROLE_AUTH, true  },
    { "disconnect", "Disconnect a user or a shell by its ID.",             do_disconnect, ROLE_SU,   true  },
    { "exit",       "Close the connection.",                               do_exit,       ROLE_NONE, false },
    { "help",       "Display the list of available commands.",             do_help,       ROLE_NONE, false },
    { "list",       "Lists all the shells you could switch into.",         do_list,       ROLE_NONE, false },
    { "log",        "Log the text given as an argument.",                  do_log,        ROLE_SU,   false },
    { "login",      "Authenticate the current session.",                   do_login,      ROLE_NONE, false },
    { "prompt",     "Toggle the prompt that is shown after each command.", do_prompt,     ROLE_NONE, false },
    { "provide",    "Provide your connection as a shell to others.",       do_provide,    ROLE_NONE, false },
    { "return",     "Return from your current shell.",                     do_return,     ROLE_NONE, false },
    { "su",         "Elevate the current user to the superuser.",          do_su,         ROLE_AUTH, true  },
    { "subscribe",  "Subscribe to the specified user's broadcast.",        do_subscribe,  ROLE_NONE, false },
    { "switch",     "Switch into another shell.",                          do_switch,     ROLE_NONE, false },
    { "team",       "Join a specified team by its password.",              do_team,       ROLE_NONE, false },
    { nullptr,      nullptr,                                               nullptr,       0,         false }
};

