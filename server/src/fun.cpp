// SPDX-License-Identifier: MIT

#include "fun.h"
#include "sockets.h"

void do_create(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    if (program.has_channel(sid)) {
        sockets->write(sid, "You have already created a channel.\n\r");
        return;
    }

    if (*argument == '\0') {
        sockets->write(sid, "Please provide the name for your channel.\n\r");
        return;
    }

    if (program.find_channel(argument)) {
        sockets->writef(sid, "Channel '%s' already exists.\n\r", argument);
        return;
    }

    program.set_channel(sid, argument);
    sockets->writef(sid, "Created channel '%s'.\n\r", argument);
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

    size_t host_id = program.find_channel(argument);

    if (!host_id) {
        sockets->write(sid, "No such channel found.\n\r");
        return;
    }

    if (program.has_guest(host_id, sid)) {
        sockets->write(sid, "You have already joined this channel.\n\r");
        return;
    }

    program.set_guest(host_id, sid);
    sockets->writef(sid, "Joined channel '%s'.\n\r", argument);
}

void do_leave(PROGRAM &program, size_t sid, const char *argument) {
    SOCKETS *sockets = program.get_sockets();

    if (program.has_channel(sid)) {
        sockets->write(sid, "As a channel host you cannot leave channels.\n\r");
        return;
    }

    if (*argument == '\0') {
        sockets->write(sid, "Which channel do you wish to leave?\n\r");
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
        "    $create <channel name>\n\r"
        "    $join   <channel name>\n\r"
        "    $leave  <channel name>\n\r"
        "    $list\n\r"
        "    $help\n\r"
        "    $exit\n\r"
        "\n\r"
    );
}
