import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.util.*;

public class MultiPlayClient {
    public static String version      = "2.0";
    private static boolean doexit     = false;
    private static boolean canexit    = false;
    private static boolean longsleep  = false;
    private static int client_nr      = 0;
    private static int question       = 0;
    private static String questions[] = {
        "What is the host of the MUD you wish to play?",
        "What is the port of that MUD?",
        "What is the host of the MultiPlay server?",
        "What is the port of the MultiPlay server?",
        "What name do you want to use in the team chat?",
        "What is the password of your team?"
    };
    private static String answers[] = null;
    private static int MUD_HOST = 0;
    private static int MUD_PORT = 1;
    private static int MPS_HOST = 2;
    private static int MPS_PORT = 3;
    private static int MPC_NAME = 4;
    private static int MPC_PASS = 5;

    private static ServerSocket acceptor = null;
    private static Socket client    = null;
    private static Socket server    = null;
    private static Socket multiplay = null;

    private static int                   socket_timeout  = 1;
    private static ByteArrayOutputStream client_command  = null;
    private static ByteArrayOutputStream server_message  = null;
    private static ByteArrayOutputStream multiplay_text  = null;
    private static int                   client_port     = 4000;
    private static boolean               initializing    = false;
    private static int                   telnet_command  = 0;
    private static boolean               broadcasting    = false;
    private static boolean               trigger_start   = true;
    private static String                trigger_buffer  = "";
    private static String                triggers[] = {
        "Broadcasting is now enabled.",
        "Broadcasting is now disabled."
    };

    public static void main(String[] args) throws IOException {
        if (args.length > 0) {
            try {
                int port = Integer.parseInt(args[0]);
                client_port = port;
            }
            catch (NumberFormatException e) {
                log("Invalid port number: "+args[0]);
            }
        }

        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                log("Shutdown sequence initiated.");
                doexit = true;
                while (!canexit) Thread.yield();
                log("MultiPlay Client has finished.");
            }
        });

        try {
            log("Starting MultiPlay Client v"+version+".");
            runServer();
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            bug(sw.toString());
            canexit = true; // Emergency shutdown...
        }
        close_all();
    }

    public static void runServer() throws IOException {
        client_command = new ByteArrayOutputStream(256);
        server_message = new ByteArrayOutputStream(1024);
        multiplay_text = new ByteArrayOutputStream(1024);
        acceptor = create_acceptor(client_port);

        while (!doexit && acceptor != null) {
            while (step_multiplay());
            while (step_server());
            while (step_client());

            try {
                Thread.sleep(longsleep ? 1000 : socket_timeout);
                longsleep = false;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        close_all();
        canexit = true;
    }

    public static void greet(Socket client) {
        question = 0;
        String message = new String(
            "\n\r"+
            "Welcome to MultiPlay Client v"+version+"!\n\r"+
            "\n\r"
        );

        message+=questions[question]+(
            answers[question].length() > 0 ? (
                " (default: "+answers[question]+")"
            ) : ""
        )+"\n\r";

        try {
            client.getOutputStream().write(
                message.getBytes(Charset.forName("UTF-8"))
            );
        } catch (IOException e) {
            bug(e.toString());
        }
    }

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static void interpret(Socket client, byte[] command) {
        if (question < questions.length) {
            if (command.length > 0) {
                answers[question] = new String(command);
            }
            else {
                send(client, answers[question]+"\n\r");
            }

            question++;

            if (question < questions.length) {
                send(client, "\n\r"+questions[question]);

                if (answers[question].length() > 0) {
                    send(client, " (default: "+answers[question]+")");
                }

                send(client, "\n\r");
            }
            else {
                initializing = false;
            }

            return;
        }

        if (command.length > 0 && command[0] == '$') {
            int sz = command.length;
            int i;
            for (i=0; i+1<sz; i++) command[i] = command[i+1];
            command[i] = '\n';

            if (multiplay != null) {
                send_bytes(multiplay, command);
            }
            else {
                send(
                    client, "You are not connected to the MultiPlay server.\n\r"
                );
            }
        }
        else {
            if (server != null) {
                send_bytes(server, command);
                send_byte(server, '\n');

                if (multiplay != null
                && broadcasting
                && (new String(command)).trim().length() > 0) {
                    send(multiplay, "broadcast ");
                    send_bytes(multiplay, command);
                    send_byte(multiplay, '\n');
                }
            }
            else {
                send(client, "You are not connected to the MUD server.\n\r");
            }
        }
    }

    public static void send(Socket to, String message) {
        try {
            to.getOutputStream().write(
                message.getBytes(Charset.forName("UTF-8"))
            );
        } catch (IOException e) {
            bug(e.toString());
        }
    }

    public static void send_bytes(Socket to, byte[] bytes) {
        try {
            to.getOutputStream().write(bytes);
        } catch (IOException e) {
            bug(e.toString());
        }
    }

    public static void send_byte(Socket to, int b) {
        try {
            to.getOutputStream().write(b);
        } catch (IOException e) {
            bug(e.toString());
        }
    }

    public static boolean step_client() {
        if (client == null) {
            client = wait_client(acceptor);
            return false;
        }

        // Write client output.
        if (server_message.size() > 0) {
            try {
                client.getOutputStream().write(server_message.toByteArray());
                client.getOutputStream().flush();
            } catch (IOException e) {
                bug(e.toString());
                return false;
            }
            server_message.reset();
        }

        if (multiplay_text.size() > 0) {
            try {
                client.getOutputStream().write(multiplay_text.toByteArray());
                client.getOutputStream().flush();
            } catch (IOException e) {
                bug(e.toString());
                return false;
            }

            multiplay_text.reset();
        }

        // Read client input.
        int next_byte = -1;

        try {
            next_byte = client.getInputStream().read();

            if (next_byte == -1) {
                log("Connection #"+client_nr+" lost.");
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            log(
                "An error occurred while reading from connection #"+
                client_nr+"."
            );

            bug(e.toString());
        }

        if (next_byte != -1) {
            if (telnet_command > 0) {
                telnet_command--;
                if (server != null) send_byte(server, next_byte);
                return true;
            }
            else {
                if (next_byte == '\n') {
                    interpret(client, client_command.toByteArray());
                    client_command.reset();
                    return false;
                }
                else if (next_byte == 0xff) {
                    telnet_command = 2;

                    if (server != null) {
                        send_byte(server, next_byte);
                    }

                    return true;
                }
                else if (client_command.size() < 1024) {
                    client_command.write(next_byte);
                    return true;
                }
                else {
                    log("Command too long, closing!");
                }
            }
        }

        close_multiplay();
        close_server();
        close_client();
        return false;
    }

    public static boolean step_multiplay() {
        if (client == null || initializing) {
            return false;
        }

        if (multiplay == null) {
            send(
                client,
                "Connecting to "+answers[MPS_HOST]+":"+answers[MPS_PORT]+".\n\r"
            );

            multiplay = connect_to(answers[MPS_HOST], answers[MPS_PORT]);

            if (multiplay == null) {
                send(
                    client,
                    "Failed to connect to "+answers[MPS_HOST]+":"+
                    answers[MPS_PORT]+" (multiplay).\n\r"
                );

                longsleep=true;

                try {
                    client.getOutputStream().flush();
                } catch (IOException e) {
                    bug(e.toString());
                }
            }
            else {
                send(
                    multiplay, "$channel "+answers[MPC_NAME]+"\n"
                );
            }

            return false;
        }

        int next_byte = -1;

        try {
            next_byte = multiplay.getInputStream().read();

            if (next_byte == -1) {
                log("MultiPlay server disconnected us.");
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            log("An error occurred while reading from the MultiPlay server.");
            bug(e.toString());
        }

        if (next_byte != -1) {
            if (next_byte >= 0 && next_byte <= 255) {
                boolean persist_trigger = (next_byte == '\r' && trigger_start);

                if (trigger_start) {
                    byte[] bs = new byte[] {(byte) next_byte};

                    int len = trigger_buffer.length();
                    boolean found = false;

                    for (int i=0; i<triggers.length; i++) {
                        if (triggers[i].length() <= len) continue;
                        if ((byte) triggers[i].charAt(len) == next_byte) {
                            trigger_buffer+=new String(bs);
                            found = true;
                            break;
                        }
                    }
                    if (found) {
                        for (int i=0; i<triggers.length; i++) {
                            if (trigger_buffer.equals(triggers[i])) {
                                log("TRIGGER: "+trigger_buffer);
                                trigger(trigger_buffer);
                                found = false;
                                break;
                            }
                        }
                    }

                    if (!found) {
                        trigger_buffer = "";
                        trigger_start  = false;
                    }
                }

                if (!trigger_start) {
                    if (next_byte == '\n' || persist_trigger) {
                        trigger_start = true;
                    }
                }
            }

            multiplay_text.write(next_byte);

            return true;
        }

        longsleep = true;
        close_multiplay();

        return false;
    }

    private static void trigger(String event) {
        if (event.equals("Broadcasting is now enabled.")) {
            broadcasting = true;
        }
        else if (event.equals("Broadcasting is now disabled.")) {
            broadcasting = false;
        }
    }

    public static boolean step_server() {
        if (client == null || initializing) {
            return false;
        }

        if (server == null) {
            if (question >= questions.length) {
                send(
                    client, "Connecting to "+answers[MUD_HOST]+":"+
                    answers[MUD_PORT]+".\n\r"
                );

                server = connect_to(answers[MUD_HOST], answers[MUD_PORT]);

                if (server == null) {
                    send(
                        client, "Failed to connect to "+answers[MUD_HOST]+
                        ":"+answers[MUD_PORT]+" (server).\n\r"
                    );

                    longsleep = true;

                    try {
                        client.getOutputStream().flush();
                    } catch (IOException e) {
                        bug(e.toString());
                    }
                }
                else {
                    send(
                        client,
                        "\n\r"+
                        "You are now multiplaying like a boss!\n\r"+
                        "\n\r"+
                        "Type $help to see the list of commands.\n\r"+
                        "\n\r"
                    );
                }
            }

            return false;
        }

        int next_byte = -1;
        try {
            next_byte = server.getInputStream().read();

            if (next_byte == -1) {
                log("MUD server disconnected us.");
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            log("An error occurred while reading from the MUD server.");
            bug(e.toString());
        }

        if (next_byte != -1) {
            server_message.write(next_byte);

            return true;
        }

        longsleep = true;
        close_server();

        return false;
    }

    public static ServerSocket create_acceptor(int port) {
        ServerSocket acceptor = null;

        try {
            acceptor = new ServerSocket(port);
            acceptor.setSoTimeout(1000);
            log("Started listening on port "+acceptor.getLocalPort()+".");
        } catch (IOException e) {
            log("Failed to start listening on port "+port+".");
            bug(e.toString());
        }

        return acceptor;
    }

    public static Socket wait_client(ServerSocket acceptor) {
        Socket client = null;

        try {
            client = acceptor.accept();
            client_nr++;
            question = 0;
            initializing = true;
            telnet_command = 0;
            broadcasting = false;
            trigger_buffer = "";
            trigger_start = true;
            answers = new String[questions.length];

            for (int i=0; i<questions.length; i++) {
                answers[i] = "";
            }

            answers[MUD_HOST] = "stonia.ttu.ee";
            answers[MUD_PORT] = "4000";

            log(
                "New connection #"+client_nr+" from "+
                client.getInetAddress().getHostAddress()+":"+client.getPort()+
                "."
            );

            client.setSoTimeout(socket_timeout);
            greet(client);
        } catch (SocketTimeoutException e) {
            //log("No one connected.");
        } catch (IOException e) {
            log("An error occurred while waiting for a connection.");
            bug(e.toString());
        }

        return client;
    }

    public static Socket connect_to(String host, String port) {
        Socket s = null;

        try {
            s = new Socket(host, Integer.parseInt(port));
            s.setSoTimeout(socket_timeout);
            log(
                "Connected to "+s.getInetAddress().getHostName()+":"+
                s.getPort()+"."
            );
        } catch (ConnectException e) {
            return null;
        } catch (IOException | IllegalArgumentException e) {
            bug(e.toString());
        }
        return s;
    }

    public static void close_client() {
        if (client == null) {
            return;
        }

        try {
            client.close();
            log(
                "Disconnected client #"+client_nr+" ("+
                client.getInetAddress().getHostAddress()+":"+client.getPort()+
                ")."
            );
        }
        catch (IOException e) {
            log("An error occurred while disconnecting client #"+client_nr+".");
            bug(e.toString());
        }

        client = null;
    }

    public static void close_server() {
        if (server == null) {
            return;
        }

        String place = new String(
            server.getInetAddress().getHostName()+":"+server.getPort()
        );

        try {
            server.close();
            log("Disconnected from "+place+".");
        }
        catch (IOException e) {
            log("An error occurred while disconnecting from "+place+".");
            bug(e.toString());
        }

        server = null;
    }

    public static void close_multiplay() {
        if (multiplay == null) {
            return;
        }

        String place = new String(
            multiplay.getInetAddress().getHostName()+":"+multiplay.getPort()
        );

        try {
            multiplay.close();
            log("Disconnected from "+place+" (multiplay).");
        }
        catch (IOException e) {
            log("An error occurred while disconnecting from "+place+".");
            bug(e.toString());
        }

        multiplay = null;
    }

    public static void close_acceptor() {
        if (acceptor == null) {
            return;
        }

        String place = ""+acceptor.getLocalPort();

        try {
            acceptor.close();
            log("Stopped listening on port "+place+".");
        }
        catch (IOException e) {
            log("An error occurred while closing port "+place+".");
            bug(e.toString());
        }

        acceptor = null;
    }

    public static void close_all() {
        close_multiplay();
        close_server();
        close_client();
        close_acceptor();
    }

    public static void log(String text) {
        Date date = Calendar.getInstance().getTime();
        System.out.printf(
            "%1$ta %1$tb %1$td %1$tH:%1$tM:%1$tS %1$tY :: %2$s\n", date, text
        );
    }

    public static void bug(String text) {
        String methodName = new String(
            Thread.currentThread().getStackTrace()[2].getMethodName()
        );

        int line = Thread.currentThread().getStackTrace()[2].getLineNumber();
        text = methodName+" (line "+line+"): "+text;

        longsleep = true;
        Date date = Calendar.getInstance().getTime();
        System.err.printf(
            "\u001B[1;31m%1$ta %1$tb %1$td %1$tH:%1$tM:%1$tS %1$tY ::"+
            "\u001B[0m %2$s\n", date, text
        );
    }
}
