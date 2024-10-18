import java.io.*;
import java.net.*;
import java.nio.charset.Charset;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.sound.sampled.*;
import javax.sound.sampled.LineEvent.Type;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

public class MultiPlayClient {
    public static String version     = "2.0";
    private static boolean canexit   = false;
    private static boolean doexit    = false;
    private static boolean longsleep = false;
    private static int client_nr     = 0;
    private static int question      = 0;
    private static String questions[] = {
        "What is the host of the MUD you wish to play?",
        "What is the port of that MUD?",
        "What is the host of the MultiPlay server?",
        "What is the port of the MultiPlay server?",
        "What name do you wish to give to your channel?",
        "What is the password of your channel?"
    };
    private static String answers[] = null;
    private static int MUD_HOST = 0;
    private static int MUD_PORT = 1;
    private static int MPS_HOST = 2;
    private static int MPS_PORT = 3;
    private static int MPC_NAME = 4;
    private static int MPC_PASS = 5;

    private static AtomicBoolean exiting = null;
    private static ServerSocket acceptor = null;
    private static Socket client    = null;
    private static Socket server    = null;
    private static Socket multiplay = null;

    private static int                      socket_timeout     = 1;
    private static ByteArrayOutputStream    client_command     = null;
    private static ByteArrayOutputStream    server_message     = null;
    private static ByteArrayOutputStream    filter_message     = null;
    private static ByteArrayOutputStream    multiplay_text     = null;
    private static int                      client_port        = 4000;
    private static boolean                  initializing       = false;
    private static int                      telnet_command     = 0;
    private static int                      multiplay_telnet   = 0;
    private static Queue<String>            playlist           = null;
    private static Map<String, Set<String>> patterns           = null;
    private static Map<String, Clip>        soundclips         = null;
    private static long                     patterns_crc32     = 0;
    private static long                     patterns_timestamp = 0;
    private static String                   patterns_filepath  = null;

    public static void main(String[] args) throws IOException {
        if (args.length > 0) {
            try {
                int port = Integer.parseInt(args[0]);
                client_port = port;
            }
            catch (NumberFormatException e) {
                log("invalid port number: "+args[0]);
            }
        }

        if (args.length > 1) {
            load_patterns(args[1]);
        }

        exiting = new AtomicBoolean(false);
        playlist = new ConcurrentLinkedQueue<>();

        Runtime.getRuntime().addShutdownHook(
            new Thread() {
                @Override
                public void run() {
                    log("shutdown sequence initiated");
                    doexit = true;
                    while (!canexit) Thread.yield();
                    log("MultiPlay Client has finished");
                }
            }
        );

        Thread soundplayer = new Thread() {
            public void run() {
                while (!exiting.get()) {
                    if (!playlist.isEmpty() && soundclips != null) {
                        while (playlist.size() > 4) {
                            playlist.poll();
                        }

                        String filename = playlist.poll();

                        if (soundclips.containsKey(filename)) {
                            Clip clip = soundclips.get(filename);

                            try {
                                playClip(clip);
                            } catch (UnsupportedAudioFileException e) {
                                bug(e.toString());
                            } catch (LineUnavailableException e) {
                                bug(e.toString());
                            } catch (InterruptedException e) {
                                bug(e.toString());
                            }
                        }
                        else bug("sound clip not loaded: "+filename);
                    }

                    try {
                        Thread.sleep(10);
                    }
                    catch (InterruptedException e){
                        bug(e.toString());
                    }
                }
            }
        };
        soundplayer.start();

        try {
            log("starting MultiPlay Client v"+version);
            runServer();
        } catch (Exception e) {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            e.printStackTrace(pw);
            bug(sw.toString());
        }

        close_all();
        exiting.set(true);

        try {
            soundplayer.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        if (soundclips != null) {
            for (Map.Entry<String, Clip> entry : soundclips.entrySet()) {
                entry.getValue().close();
            }
        }

        canexit = true;
    }

    public static void runServer() throws IOException {
        client_command = new ByteArrayOutputStream(256);
        server_message = new ByteArrayOutputStream(1024);
        filter_message = new ByteArrayOutputStream(1024);
        multiplay_text = new ByteArrayOutputStream(1024);
        acceptor = create_acceptor(client_port);

        while (!doexit && acceptor != null) {
            while (step_multiplay());
            while (step_server());
            while (step_client());

            if (System.nanoTime() / 1000000000 - patterns_timestamp > 10
            && patterns_filepath != null) {
                long crc32 = crc32(patterns_filepath);

                if (crc32 != patterns_crc32
                && !load_patterns(patterns_filepath)) {
                    log("failed to reload patterns from "+patterns_filepath);
                }

                patterns_timestamp = System.nanoTime() / 1000000000;
            }

            try {
                Thread.sleep(longsleep ? 1000 : socket_timeout);
                longsleep = false;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
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

    public static void interpret_client(Socket client, byte[] command) {
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

                if (patterns == null) {
                    if (!load_patterns(answers[0]+".txt")) {
                        load_patterns("patterns.txt");
                    }
                }
            }

            return;
        }

        if (command.length > 0 && command[0] == '$') {
            if (multiplay != null) {
                send_bytes(multiplay, command);
                send_byte(multiplay, '\n');
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
            }
            else {
                send(client, "You are not connected to the MUD server.\n\r");
            }
        }
    }

    public static void interpret_multiplay(Socket multiplay, byte[] command) {
        if (command.length > 0 && command[0] == '$') {
            if (server != null) {
                for (int i = 1; i < command.length; i++) {
                    command[i-1] = command[i];
                }

                command[command.length - 1] = '\n';

                send_bytes(server, command);
            }
        }
        else {
            String cmdstr = new String(command, Charset.forName("US-ASCII"));

            if (client != null) {
                send_bytes(client, command);
                send_byte(client, '\n');
                send_byte(client, '\r');

                interpret_filter_line(cmdstr);
            }

            String cmpstr = new String(
                "Channel '"+answers[MPC_NAME]+"' already exists."
            );

            if (cmdstr.equals(cmpstr)) {
                longsleep = true;
                close_multiplay();
                close_server();
                close_client();
            }
        }
    }

    public static ByteArrayOutputStream interpret_filter(
        ByteArrayOutputStream filter
    ) {
        byte[] bytes = filter.toByteArray();

        int pos = 0;

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] == '\n') {
                interpret_filter_line(
                    new String(
                        bytes, pos, i - pos, Charset.forName("US-ASCII")
                    )
                );

                pos = i+1;
            }
        }

        ByteArrayOutputStream remaining = new ByteArrayOutputStream(
            bytes.length - pos
        );

        remaining.write(bytes, pos, bytes.length - pos);

        return remaining;
    }

    public static void interpret_filter_line(String line) {
        if (patterns == null) {
            return;
        }

        for (Map.Entry<String, Set<String>> entry : patterns.entrySet()) {
            String trimmed = line.replaceAll("\u001B\\[[;\\d]*m", "").trim();
            Pattern pattern = Pattern.compile(entry.getKey());
            Matcher matcher = pattern.matcher(trimmed);

            if (!matcher.find()) {
                continue;
            }

            for (String param : entry.getValue()) {
                if (param.equals("log")) {
                    log(trimmed);
                }
                else if (param.startsWith("sfx:")) {
                    String sfx = param.substring(param.indexOf(":") + 1);

                    if (!sfx.isEmpty()) {
                        playlist.add(sfx);
                    }
                }
            }

            break;
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

        if (server_message.size() > 0) {
            try {
                client.getOutputStream().write(server_message.toByteArray());
                client.getOutputStream().flush();
            } catch (IOException e) {
                bug(e.toString());
                return false;
            }

            try {
                send(multiplay, "$hexmsg ");
                multiplay.getOutputStream().write(
                    bytesToHex(server_message.toByteArray()).getBytes(
                        Charset.forName("UTF-8")
                    )
                );
                send(multiplay, "\n");
                multiplay.getOutputStream().flush();
            } catch (IOException e) {
                bug(e.toString());
                return false;
            }

            try {
                server_message.writeTo(filter_message);
            } catch (IOException e) {
                bug(e.toString());
                return false;
            }

            filter_message = interpret_filter(filter_message);

            server_message.reset();
        }

        // Read client input.
        int next_byte = -1;

        try {
            next_byte = client.getInputStream().read();

            if (next_byte == -1) {
                log("connection #"+client_nr+" lost");
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            log(
                "an error occurred while reading from connection #"+client_nr
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
                    interpret_client(client, client_command.toByteArray());
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
                    log("command too long, closing");
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
                    multiplay,
                    "$create '"+answers[MPC_NAME]+"' "+answers[MPC_PASS]+"\n"
                );
            }

            return false;
        }

        int next_byte = -1;

        try {
            next_byte = multiplay.getInputStream().read();

            if (next_byte == -1) {
                log("MultiPlay server disconnected us");
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            log("an error occurred while reading from the MultiPlay server");
            bug(e.toString());
        }

        if (next_byte != -1) {
            if (multiplay_telnet > 0) {
                multiplay_telnet--;
                return true;
            }
            else {
                if (next_byte == '\n') {
                    interpret_multiplay(
                        multiplay, multiplay_text.toByteArray()
                    );

                    multiplay_text.reset();

                    return false;
                }
                else if (next_byte == 0xff) {
                    multiplay_telnet = 2;

                    return true;
                }
                else if (multiplay_text.size() < 1024) {
                    if (next_byte != '\r') {
                        multiplay_text.write(next_byte);
                    }

                    return true;
                }
                else {
                    log("message from MultiPlay too long, closing");
                }
            }
        }

        longsleep = true;
        close_multiplay();

        return false;
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
                log("MUD server disconnected us");
            }
        } catch (SocketTimeoutException e) {
            return false;
        } catch (IOException e) {
            log("an error occurred while reading from the MUD server");
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
            log("started listening on port "+acceptor.getLocalPort());
        } catch (IOException e) {
            log("failed to start listening on port "+port);
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
            answers = new String[questions.length];

            for (int i=0; i<questions.length; i++) {
                answers[i] = "";
            }

            answers[MUD_HOST] = "stonia.ttu.ee";
            answers[MUD_PORT] = "4000";
            answers[MPS_HOST] = "uvn-79-50.tll01.zonevs.eu";
            answers[MPS_PORT] = "4000";

            log(
                "new connection #"+client_nr+" from "+
                client.getInetAddress().getHostAddress()+":"+client.getPort()
            );

            client.setSoTimeout(socket_timeout);
            greet(client);
        } catch (SocketTimeoutException e) {
            //log("No one connected.");
        } catch (IOException e) {
            log("an error occurred while waiting for a connection");
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
                "connected to "+s.getInetAddress().getHostName()+":"+s.getPort()
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
                "disconnected client #"+client_nr+" ("+
                client.getInetAddress().getHostAddress()+":"+client.getPort()+
                ")"
            );
        }
        catch (IOException e) {
            log("an error occurred while disconnecting client #"+client_nr);
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
            log("disconnected from "+place);
        }
        catch (IOException e) {
            log("an error occurred while disconnecting from "+place);
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
            log("disconnected from "+place+" (MultiPlay)");
        }
        catch (IOException e) {
            log("an error occurred while disconnecting from "+place);
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
            log("stopped listening on port "+place);
        }
        catch (IOException e) {
            log("an error occurred while closing port "+place);
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

    synchronized public static void log(String text) {
        Date date = Calendar.getInstance().getTime();
        System.out.printf(
            "%1$ta %1$tb %1$td %1$tH:%1$tM:%1$tS %1$tY :: %2$s\n", date, text
        );
    }

    synchronized public static void bug(String text) {
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

    public static boolean load_patterns(String filepath) {
        File file = new File(filepath);

        if (!file.exists() || !file.canRead()) {
            return false;
        }

        if (soundclips != null) {
            for (Map.Entry<String, Clip> entry : soundclips.entrySet()) {
                entry.getValue().close();
            }
        }

        patterns = new LinkedHashMap<String, Set<String>>();
        soundclips = new LinkedHashMap<String, Clip>();

        try {
            List<String> lines = Files.readAllLines(
                Paths.get(filepath)
            );

            String pattern = "";

            for (String line : lines) {
                if (line.startsWith("^")) {
                    pattern = line;

                    if (!patterns.containsKey(line)) {
                        patterns.put(line, new LinkedHashSet<>());
                    }
                }
                else if (!pattern.isEmpty() && !line.isEmpty()) {
                    String[] parts = line.trim().split(" ", 0);

                    for (String part : parts) {
                        if (!part.startsWith("sfx:")) {
                            patterns.get(pattern).add(part.trim());

                            continue;
                        }

                        String sfx = part.substring(part.indexOf(":") + 1);

                        if (sfx.isEmpty()) {
                            continue;
                        }

                        File soundfile = new File(sfx);

                        if (soundfile.exists() && soundfile.canRead()) {
                            Clip clip = load_clip(soundfile);

                            if (clip != null) {
                                patterns.get(pattern).add(part.trim());
                                soundclips.put(sfx, clip);
                            }
                        }
                        else log("failed to read audio file: "+sfx);
                    }
                }
            }

            if (patterns.size() == 0) {
                patterns = null;
                soundclips = null;
            }
        } catch (IOException e) {
            bug(e.toString());
            patterns = null;
            soundclips = null;
        }

        if (patterns != null) {
            patterns_filepath = filepath;
            patterns_timestamp = System.nanoTime() / 1000000000;
            patterns_crc32 = crc32(filepath);

            log("loaded patterns from '"+filepath+"'");
        }

        return patterns != null;
    }

    private static Clip load_clip(File clipFile) {
        AudioInputStream audioInputStream = null;
        Clip clip = null;

        try {
            audioInputStream = AudioSystem.getAudioInputStream(clipFile);

            clip = AudioSystem.getClip();
        } catch (UnsupportedAudioFileException e) {
            bug(e.toString());
        } catch (IOException e) {
            bug(e.toString());
        } catch (LineUnavailableException e) {
            bug(e.toString());
        }

        if (audioInputStream != null) {
            if (clip != null) {
                try {
                    clip.open(audioInputStream);
                } catch (IOException e) {
                    bug(e.toString());
                } catch (LineUnavailableException e) {
                    bug(e.toString());
                }
            }

            try {
                audioInputStream.close();
            } catch (IOException e) {
                bug(e.toString());
            }
        }

        return clip;
    }

    private static void playClip(Clip clip) throws
    UnsupportedAudioFileException, LineUnavailableException,
    InterruptedException {
        class AudioListener implements LineListener {
            private boolean done = false;
            @Override public synchronized void update(LineEvent event) {
                Type eventType = event.getType();

                if (eventType == Type.STOP || eventType == Type.CLOSE) {
                    done = true;
                    notifyAll();
                }
            }
            public synchronized boolean waitUntilDone(
                long milliseconds
            ) throws InterruptedException {
                wait(milliseconds);

                return !done;
            }
        }

        AudioListener listener = new AudioListener();
        clip.addLineListener(listener);

        boolean stopping = false;
        long nanotime = System.nanoTime();
        long duration = clip.getMicrosecondLength() / 1000;

        while (clip.getFramePosition() < clip.getFrameLength()) {
            if (stopping) {
                break;
            }

            clip.start();

            long time_spent = (System.nanoTime() - nanotime) / 1000000;
            long wait_time_ms = Math.min(
                Math.max(duration - time_spent + 10, 1), 250
            );

            while (listener.waitUntilDone(wait_time_ms)) {
                if (!stopping
                && (!playlist.isEmpty() || wait_time_ms == 1)) {
                    stopping = true;
                    clip.stop();
                    break;
                }

                time_spent = (System.nanoTime() - nanotime) / 1000000;
                wait_time_ms = Math.min(
                    Math.max(duration - time_spent + 10, 1), 250
                );
            }
        }

        clip.setFramePosition(0);
        clip.removeLineListener(listener);
    }

    public static long crc32(String fpath) {
        Checksum checksum = new CRC32();

        try {
            BufferedInputStream is = new BufferedInputStream(
                new FileInputStream(fpath)
            );

            byte[] bytes = new byte[1024];
            int len = 0;

            while ((len = is.read(bytes)) >= 0) {
                checksum.update(bytes, 0, len);
            }

            is.close();
        }
        catch (IOException e) {
            bug(e.toString());
        }

        return checksum.getValue();
    }
}
