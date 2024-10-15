// SPDX-License-Identifier: MIT

#include "fun.h"
#include "sockets.h"

void do_create(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    if (program.has_channel(sid)) {
        sockets->write(sid, "You have already created a channel.\n\r");
        return;
    }

    std::string arg1;
    argument = PROGRAM::first_arg(argument, &arg1);

    if (arg1.empty()) {
        sockets->write(sid, "Please provide the name for your channel.\n\r");
        return;
    }

    if (program.find_channel(arg1.c_str())) {
        sockets->writef(sid, "Channel '%s' already exists.\n\r", arg1.c_str());
        return;
    }

    program.set_channel(sid, arg1.c_str(), argument);
    sockets->writef(sid, "Created channel '%s'.\n\r", arg1.c_str());
}

void do_join(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    if (program.has_channel(sid)) {
        sockets->write(sid, "As a channel host you cannot join channels.\n\r");
        return;
    }

    if (*argument == '\0') {
        sockets->write(sid, "Which channel do you wish to join?\n\r");
        return;
    }

    std::string arg1;
    argument = PROGRAM::first_arg(argument, &arg1);

    size_t host_id = program.find_channel(arg1.c_str());

    if (!host_id) {
        sockets->write(sid, "No such channel found.\n\r");
        return;
    }

    if (program.has_guest(host_id, sid)) {
        sockets->write(sid, "You have already joined this channel.\n\r");
        return;
    }

    if (program.has_password(host_id)) {
        if (*argument == '\0') {
            sockets->write(sid, "Channel requires a password.\n\r");
            return;
        }

        if (!program.has_password(host_id, argument)) {
            sockets->write(sid, "You provided a wrong password.\n\r");
            return;
        }
    }

    program.set_guest(host_id, sid);
    sockets->writef(sid, "Joined channel '%s'.\n\r", arg1.c_str());
}

void do_leave(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    if (program.has_channel(sid)) {
        sockets->write(sid, "As a channel host you cannot leave channels.\n\r");
        return;
    }

    if (*argument == '\0') {
        if (!program.has_guest(sid)) {
            sockets->write(sid, "You have not joined any channels.\n\r");
            return;
        }

        program.rem_guest(sid);
        sockets->write(sid, "You left all channels.\n\r");

        return;
    }

    size_t host_id = program.find_channel(argument);

    if (!host_id) {
        sockets->write(sid, "No such channel found.\n\r");
        return;
    }

    if (!program.has_guest(host_id, sid)) {
        sockets->write(sid, "You have not joined this channel.\n\r");
        return;
    }

    program.rem_guest(host_id, sid);
    sockets->writef(sid, "You left channel '%s'.\n\r", argument);
}

void do_allow(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    if (*argument == '\0') {
        sockets->write(
            sid, "Which commands do you wish to allow in your channel?\n\r"
        );

        return;
    }

    std::string command;
    size_t allowed = 0;
    size_t disallowed = 0;

    for (argument = PROGRAM::first_arg(argument, &command); !command.empty();) {
        if (!command.empty()) {
            if (program.set_whitelist(sid, command.c_str())) {
                sockets->writef(
                    sid, "Allowed the '%s' command in your channel.\n\r",
                    command.c_str()
                );

                ++allowed;
            }
            else if (program.rem_whitelist(sid, command.c_str())) {
                sockets->writef(
                    sid, "Disallowed the '%s' command in your channel.\n\r",
                    command.c_str()
                );

                ++disallowed;
            }
        }

        command.clear();
        argument = PROGRAM::first_arg(argument, &command);
    }

    if (!allowed && !disallowed) {
        sockets->write(
            sid, "No changes occurred in your channel command whitelist.\n\r"
        );
    }
}

void do_exit(PROGRAM &program, size_t sid, const char *argument) {
    program.get_sockets()->write(
        sid, "Alas, all good things come to an end.\n\r"
    );

    program.get_sockets()->disconnect(sid);
}

void do_list(PROGRAM &program, size_t sid, const char *argument) {
    const auto list{program.get_channels()};
    SOCKETS *sockets = program.get_sockets();

    if (list.empty()) {
        sockets->write(sid, "No channels found.\n\r");
        return;
    }

    sockets->write(sid, "Channels:\n\r");

    for (const auto &p : list) {
        sockets->writef(
            sid, "    %s (%s:%s)\n\r", p.first.c_str(),
            sockets->get_host(p.second), sockets->get_port(p.second)
        );
    }

    sockets->write(sid, "\n\r");
}

void do_help(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    sockets->write(
        sid,
        "Available commands:\n\r"
        "    $create <channel name> [password]\n\r"
        "    $join   <channel name> [password]\n\r"
        "    $leave  [channel name]\n\r"
        "    $allow  <command> [command] ...\n\r"
        "    $list\n\r"
        "    $help\n\r"
        "    $exit\n\r"
        "\n\r"
    );
}
