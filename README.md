# MultiPlay v2.0 ###############################################################

MultiPlay is a special purpose TCP server-client system that allows players of
multi user dungeons (MUDs) to share their active gaming sessions with each other
in real time.

What is more, MultiPlay allows multiple players to control the same character or
characters simultaneously. For example, if you join multiple shared gaming
sessions (referred to as channels), then your input will be duplicated to every
host. This makes it especially convenient to multiplay (play as multiple game
characters simultaneously).


# Client #######################################################################

The MultiPlay Client (MPC) is a light weight Java program that manages three
required TCP connections: the player, the MUD and the MultiPlay Server (MPS). It
takes an optional command line parameter that specifies the TCP port where to
start listening on.

If the mentioned parameter is absent, then port 4000 will be used. However, if
0 is provides as an argument, then MPC will listen on any available TCP port.
The player has to start their own personal MPC instance locally and then connect
to it using their favourite MUD client.

After connecting to the MPC, it will ask the player for the host and port of the
MUD and MPS. It will also ask for the name and password for the channel to be
created. If valid answers are given to these questions, the MPC will establish
a TCP connection to the MUD and MPS, creating the specified channel in MPS.

In order to join the created channel, one needs to directly connect to the MPS
with a different TCP/MUD client. They are then provided with a list of available
commands, among which there is the _$join_ command. This command has to be
called with the channel name and password as its arguments. Upon success, this
new connection will mirror everything that the MUD sends to the channel host.

```sh
[hyena@Courage client]$ java -jar mpc.jar 5000
Tue Oct 15 14:28:50 2024 :: Starting MultiPlay Client v2.0.
Tue Oct 15 14:28:50 2024 :: Started listening on port 5000.
^CTue Oct 15 14:28:52 2024 :: Shutdown sequence initiated.
Tue Oct 15 14:28:52 2024 :: Stopped listening on port 5000.
Tue Oct 15 14:28:52 2024 :: MultiPlay Client has finished.
[hyena@Courage client]$ java -jar mpc.jar 0
Tue Oct 15 14:28:55 2024 :: Starting MultiPlay Client v2.0.
Tue Oct 15 14:28:55 2024 :: Started listening on port 38747.
^CTue Oct 15 14:28:58 2024 :: Shutdown sequence initiated.
Tue Oct 15 14:28:58 2024 :: Stopped listening on port 38747.
Tue Oct 15 14:28:58 2024 :: MultiPlay Client has finished.
[hyena@Courage client]$ java -jar mpc.jar
Tue Oct 15 14:29:11 2024 :: Starting MultiPlay Client v2.0.
Tue Oct 15 14:29:11 2024 :: Started listening on port 4000.
^CTue Oct 15 14:29:14 2024 :: Shutdown sequence initiated.
Tue Oct 15 14:29:15 2024 :: Stopped listening on port 4000.
Tue Oct 15 14:29:15 2024 :: MultiPlay Client has finished.
```


## Build Instructions ##########################################################

MultiPlay Client is written in the Java language and should be trivial to
compile on most systems that have Java development kit installed. Just go to the
_client_ directory and execute the _compile.sh_ script (if you are on Linux).
Example build process is shown below.

```sh
[hyena@Courage client]$ ./compile.sh
Tue Oct 15 14:54:30 2024 :: MultiPlayClient.java compiled.
```


# Server #######################################################################

The MultiPlay Server is a C++ application that listens on a specified TCP port
and allows its users to either create new channels or join the existing ones.

If a user creates a new channel, then all of its input will be sent to the
channel guests. Similarly, if a user joins a channel, then all of its input will
be sent to the channel host. However, with the dollar sign _$_ (a special escape
character), the user can still execute the MPS commands.

```sh
[hyena@Courage server]$ ./multiplay
Usage: ./multiplay [options] port
Options:
      --brief         Print brief information (default).
  -h  --help          Display this usage information.
      --verbose       Print verbose information.
  -v  --version       Show version information.

Options: missing argument: port
Process exits with errors.
[hyena@Courage server]$ ./multiplay 4000
2024-10-15 11:34:18 :: #000002: new socket: 0.0.0.0:4000
2024-10-15 11:34:18 :: listening on port 4000...
2024-10-15 11:34:18 :: Sockets: top memory usage is 5.754 KiB
2024-10-15 11:34:19 :: Sockets: top memory usage is 6.270 KiB
^C
2024-10-15 11:34:21 :: caught signal 2 (Interrupt).
```


## Commands ####################################################################

When connected to the MPS, the user will gain access to a list of commands that
start with the dollar sign prefix _$_. If the user has not created or joined any
channels, then the prefix is not required. The list of available commands is
shown below.

```sh
[hyena@Courage ~]$ nc localhost 4000
Available commands:
    $create <channel name> [password]
    $join   <channel name> [password]
    $leave  [channel name]
    $allow  <command> [command] ...
    $list
    $help
    $exit

ex
Alas, all good things come to an end.
```


## Build Instructions ##########################################################

MultiPlay Server is written follwing the C++17 version of the C++ language and
should be trivial to compile on most Linux based systems. Go to the _server_
directory and type _make_. Example debug and production build processes are
shown below.

```sh
[hyena@Courage server]$ make debug
Compiling .... fun.cpp             	   129 lines
Compiling .... main.cpp            	    25 lines
Compiling .... program.cpp         	   622 lines
Making    .... Debug multiplay done!
[hyena@Courage server]$ make clean
Cleaning  .... Binaries of multiplay cleaned!
[hyena@Courage server]$ make
Compiling .... fun.cpp             	   129 lines
Compiling .... main.cpp            	    25 lines
Compiling .... program.cpp         	   622 lines
Making    .... Optimized multiplay done!
```
