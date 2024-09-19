package test;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Main
{
    private static final Path JAVA_HOME_CACERTS;
    private static final Path MACOS_PERMANENT_ENV_PATH = Path.of(System.getProperty("user.home"))
        .toAbsolutePath()
        .normalize()
        .resolve(Path.of("Library", "LaunchAgents", "cacerts_replacement.plist"));

    private static final StandardOpenOption[] WRITE_REPLACE_FILE =
        {StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE, StandardOpenOption.WRITE};

    static
    {
        final Path newCacerts = Path.of(System.getenv("JAVA_HOME"), "lib", "security", "cacerts").toAbsolutePath().normalize();

        final Path oldCacerts = Path.of(System.getenv("JAVA_HOME"), "jre", "lib", "security", "cacerts").toAbsolutePath().normalize();

        if (Files.isRegularFile(newCacerts))
        {
            JAVA_HOME_CACERTS = newCacerts;
        }
        else if (Files.isRegularFile(oldCacerts))
        {
            JAVA_HOME_CACERTS = oldCacerts;
        }
        else
        {
            throw new RuntimeException("Where JAVA_HOME cacerts?");
        }
    }

    private static final char[] DEFAULT_PASSWORD = "changeit".toCharArray();
    private static final Set<Certificate> certificates = new HashSet<>();

    public static void main(final String[] args) throws Exception
    {
        final Console cli = System.console();

        System.out.println("Simple Java trustStore tool");
        System.out.println("(action names are case insensitive)");

        Phase phase = Phase.INPUT;

        while (phase != Phase.EXIT)
        {
            System.out.println();
            System.out.println("Current mode %s, you can switch to %s".formatted(phase, phase.otherValues()));
            System.out.println(phase + " actions: ");
            phase.actions.keySet().forEach(act -> System.out.println("\t[" + act.shortKey() + ", " + act.key() + "] - " + act.desc()));
            System.out.println("Current cert count: " + certificates.size());
            System.out.print("Input: ");

            final String line = cli.readLine().trim();

            System.out.println();

            { // try parsing phase
                final Phase parsedPhase = Phase.valueOfOptional(line);
                if (parsedPhase != null)
                {
                    phase = parsedPhase;
                    continue;
                }
            }

            { // try parsing action
                final String key = line.toLowerCase(Locale.ROOT);
                final ActionKey actionKey = phase.actions.keySet()
                    .stream()
                    .filter(actKey -> actKey.key.equals(key) || actKey.shortKey.equals(key))
                    .findAny()
                    .orElse(null);
                if (actionKey != null)
                {
                    phase.actions.get(actionKey).run(cli);
                    continue;
                }
            }

            System.out.println("Incorrect input");
        }
    }

    public enum Phase
    {
        INPUT(Map.of("java_home_cacerts - JAVA_HOME/lib/security/cacerts",
            Main::readJavaHomeCacerts,
            "apple_keychain - Apple 'KeychainStore' without 'System Roots'",
            Main::readAppleKeychain,
            "cer_file - .cer/.crt file (can parse multiple certificates in one file)",
            Main::readCerFile)),
        OUTPUT(Map.of("java_home_cacerts - JAVA_HOME/lib/security/cacerts",
            Main::writeJavaHomeCacerts,
            "java_tool_options_permanent - set env var JAVA_TOOL_OPTIONS for all apps in " + MACOS_PERMANENT_ENV_PATH,
            Main::writeMacosPermanentEnvVar,
            "unset_java_tool_options_permanent - undo java_tool_options_permanent",
            Main::disableMacosPermanentEnvVar,
            "cer_file - .cer/.crt file with list of base64 encoded certificates",
            Main::writeCerFile)),
        EXIT(Map.of());

        private final Map<ActionKey, Action> actions = new TreeMap<>();

        private Phase(Map<String, Action> actions)
        {
            actions.forEach((k, v) -> {
                final String[] splitKey = k.split(" - ");
                this.actions.put(new ActionKey(splitKey[0], splitKey[1]), v);
            });
        }

        public List<Phase> otherValues()
        {
            final List<Phase> values = new ArrayList<>(List.of(Phase.values()));
            values.remove(this);
            return values;
        }

        public static Phase valueOfOptional(final String name)
        {
            try
            {
                return Phase.valueOf(name.toUpperCase(Locale.ROOT));
            }
            catch (IllegalArgumentException e)
            {}
            return null;
        }

        @FunctionalInterface
        private static interface Action
        {
            void run(Console cli) throws Exception;
        }
    }

    private static void readJavaHomeCacerts(final Console cli) throws Exception
    {
        final KeyStore cacertsStore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (var is = new BufferedInputStream(Files.newInputStream(JAVA_HOME_CACERTS)))
        {
            cacertsStore.load(is, DEFAULT_PASSWORD);
        }

        for (final String alias : Collections.list(cacertsStore.aliases()))
        {
            if (cacertsStore.isCertificateEntry(alias))
            {
                certificates.add(cacertsStore.getCertificate(alias));
            }
        }
    }

    private static void writeJavaHomeCacerts(final Console cli) throws Exception
    {
        {
            final Path originalBackup = JAVA_HOME_CACERTS.resolveSibling(JAVA_HOME_CACERTS.getFileName().toString() + ".original");
            if (!Files.exists(originalBackup))
            {
                System.out.println("Backing up original file to: " + originalBackup);
                Files.copy(JAVA_HOME_CACERTS, originalBackup);
            }
        }

        final KeyStore cacertsStore = KeyStore.getInstance(KeyStore.getDefaultType());
        cacertsStore.load(null, null);

        int unnamedCerts = 0;
        for (final Certificate cert : certificates)
        {
            final String alias = cert instanceof final X509Certificate x509Cert ? x509Cert.getSubjectX500Principal().getName() :
                "unnamed" + unnamedCerts++;
            cacertsStore.setCertificateEntry(alias, cert);
        }

        if (cacertsStore.size() != certificates.size())
        {
            throw new RuntimeException("Cannot create keystore - count differ");
        }

        try (var os = new BufferedOutputStream(Files.newOutputStream(JAVA_HOME_CACERTS, WRITE_REPLACE_FILE)))
        {
            cacertsStore.store(os, DEFAULT_PASSWORD);
        }
    }

    private static void readAppleKeychain(final Console cli) throws Exception
    {
        final KeyStore macStore = KeyStore.getInstance("KeychainStore");
        macStore.load(null, null);

        for (final String alias : Collections.list(macStore.aliases()))
        {
            if (macStore.isCertificateEntry(alias))
            {
                certificates.add(macStore.getCertificate(alias));
            }
        }
    }

    private static void writeMacosPermanentEnvVar(final Console cli) throws Exception
    {
        final KeyStore cacertsStore = KeyStore.getInstance(KeyStore.getDefaultType());
        cacertsStore.load(null, null);

        int unnamedCerts = 0;
        for (final Certificate cert : certificates)
        {
            final String alias = cert instanceof final X509Certificate x509Cert ? x509Cert.getSubjectX500Principal().getName() :
                "unnamed" + unnamedCerts++;
            cacertsStore.setCertificateEntry(alias, cert);
        }

        if (cacertsStore.size() != certificates.size())
        {
            throw new RuntimeException("Cannot create keystore - count differ");
        }

        final Path cacertsPath =
            MACOS_PERMANENT_ENV_PATH.resolveSibling(MACOS_PERMANENT_ENV_PATH.getFileName().toString().split("\\.")[0] + ".cacerts");
        try (var os = new BufferedOutputStream(Files.newOutputStream(cacertsPath, WRITE_REPLACE_FILE)))
        {
            cacertsStore.store(os, DEFAULT_PASSWORD);
        }

        final String[] setEnvCommand = {"launchctl",
            "setenv",
            "JAVA_TOOL_OPTIONS",
            "-Djavax.net.ssl.trustStore=$$CACERTS_PATH$$ -Djavax.net.ssl.trustStorePassword=changeit".replace("$$CACERTS_PATH$$",
                cacertsPath.toString())};

        if (!Files.exists(MACOS_PERMANENT_ENV_PATH))
        {
            System.out.println("After first installation you might need to restart the application (or even OS)");

            final String pList = """
                    <?xml version="1.0" encoding="UTF-8"?>
                    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                    <plist version="1.0">
                    <dict>
                      <key>Label</key>
                      <string>my.startup</string>
                      <key>ProgramArguments</key>
                      <array>
                        <string>sh</string>
                        <string>-c</string>
                        <string>
                        $$ENV_COMMAND$$
                        </string>
                      </array>
                      <key>RunAtLoad</key>
                      <true/>
                    </dict>
                    </plist>
                    """.replace("$$ENV_COMMAND$$",
                Stream.of(setEnvCommand[0], setEnvCommand[1], setEnvCommand[2], "\"" + setEnvCommand[3] + "\"")
                    .collect(Collectors.joining(" ")));
            Files.writeString(MACOS_PERMANENT_ENV_PATH,
                pList,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.CREATE,
                StandardOpenOption.WRITE);
        }

        System.out.println("Running command for almost immediate effect: " + Arrays.toString(setEnvCommand));
        new ProcessBuilder(setEnvCommand).start().waitFor();
    }

    private static void disableMacosPermanentEnvVar(final Console cli) throws Exception
    {
        Files.deleteIfExists(MACOS_PERMANENT_ENV_PATH);

        final String[] unsetEnvCommand = {"launchctl", "unsetenv", "JAVA_TOOL_OPTIONS"};

        System.out.println("Running command for almost immediate effect: " + Arrays.toString(unsetEnvCommand));
        new ProcessBuilder(unsetEnvCommand).start().waitFor();
    }

    private static void readCerFile(final Console cli) throws Exception
    {
        final Path cerPath = askUserForPath(cli, true, "cer", "crt");
        if (cerPath == null) return;

        try (var is = new BufferedInputStream(Files.newInputStream(cerPath)))
        {
            for (final Certificate cert : CertificateFactory.getInstance("X.509").generateCertificates(is))
            {
                certificates.add(cert);
            }
        }
    }

    private static void writeCerFile(final Console cli) throws Exception
    {
        final Path cerPath = askUserForPath(cli, false, "cer", "crt");
        if (cerPath == null) return;

        final Base64.Encoder base64enc = Base64.getMimeEncoder(64, System.getProperty("line.separator").getBytes());

        try (var writer = Files.newBufferedWriter(cerPath, WRITE_REPLACE_FILE))
        {
            for (final Certificate cert : certificates)
            {
                writer.write("-----BEGIN CERTIFICATE-----");
                writer.newLine();

                writer.write(base64enc.encodeToString(cert.getEncoded()));
                writer.newLine();

                writer.write("-----END CERTIFICATE-----");
                writer.newLine();
            }
        }
    }

    private static Path askUserForPath(final Console cli, final boolean mustExist, final String... extension)
    {
        final List<String> extensions = List.of(extension);
        final String allExtensions = extensions.stream().map(s -> "." + s).reduce("", (l, r) -> l + "/" + r).substring(1);

        Path path = null;
        while (path == null)
        {
            System.out.print("Input " + allExtensions + " file path (or exit): ");
            try
            {
                final String line = cli.readLine().trim();
                if ("exit".equalsIgnoreCase(line))
                {
                    return path;
                }

                final Path input = Path.of(line);
                if (((mustExist && Files.isRegularFile(input)) ||
                    (!mustExist && (!Files.exists(input) || Files.isWritable(input)) && !Files.isDirectory(input))) &&
                    extensions.stream().anyMatch(e -> input.toString().endsWith("." + e)))
                {
                    path = input;
                }
                else
                {
                    System.out.println("Not a " + allExtensions + " file");
                }
            }
            catch (Exception e)
            {
                System.out.println(e.getMessage());
            }
        }

        return path;
    }

    public record ActionKey(String key, String shortKey, String desc) implements Comparable<ActionKey>
    {
        public ActionKey(String key, String desc)
        {
            this(key, makeShortKey(key), desc);
        }

        public static String makeShortKey(final String key)
        {
            final String[] parts = key.split("_");
            final StringBuilder shortKey = new StringBuilder(parts.length);
            for (final String part : parts)
            {
                shortKey.append(part.charAt(0));
            }
            return shortKey.toString();
        }

        @Override
        public int compareTo(ActionKey o)
        {
            return this.shortKey.compareTo(o.shortKey);
        }
    }
}
