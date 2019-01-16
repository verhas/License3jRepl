package javax0.license3jrepl;

import javax0.license3j.Feature;
import javax0.license3j.License;
import javax0.license3j.crypto.LicenseKeyPair;
import javax0.license3j.io.*;
import javax0.repl.CommandEnvironment;
import javax0.repl.ParameterParser;
import javax0.repl.Repl;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static javax0.repl.CommandDefinitionBuilder.kw;

/**
 * The main class of the REPL application
 */
public class App {
    public static final String PUBLIC_KEY_FILE = "publicKeyFile";
    public static final String PRIVATE_KEY_FILE = "privateKeyFile";
    public static final String ALGORITHM = "algorithm";
    public static final String PRIVATE = "private";
    public static final String PUBLIC = "public";
    public static final String DIGEST = "digest";
    public static final String SIZE = "size";
    public static final String FORMAT = "format";
    public static final String TEXT = "TEXT";
    public static final String BINARY = "BINARY";
    public static final String BASE_64 = "BASE64";
    private List<String> errors = new ArrayList<>();
    private List<String> messages = new ArrayList<>();
    private License license;
    private LicenseKeyPair keyPair;
    private final Repl application = new Repl().command(
            kw("feature").noParameters().executor(this::feature).usage("name:TYPE=value")
    ).command(
            kw("licenseLoad").parameter(FORMAT).executor(this::loadLicense).usage("[format=TEXT*|BINARY|BASE64] fileName")
    ).command(
            kw("saveLicense").parameter(FORMAT).executor(this::saveLicense).usage("[format=TEXT*|BINARY|BASE64] fileName")
    ).command(
            kw("loadPrivateKey").parameter(FORMAT).executor(this::loadPrivateKey).usage("[format=BINARY*|BASE64] keyFile")
    ).command(
            kw("loadPublicKey").parameter(FORMAT).executor(this::loadPublicKey).usage("[format=BINARY*|BASE64] keyFile")
    ).command(
            kw("sign").parameter(DIGEST).executor(this::sign).usage("[digest=SHA-512]")
    ).command(
            kw("generateKeys").parameters(Set.of(ALGORITHM, SIZE, FORMAT, PUBLIC, PRIVATE)).executor(this::generate).usage("[algorithm=RSA] [size=2048] [format=BINARY|BASE64] public=xxx private=xxx")
    ).command(
            kw("verify").noParameters().executor(this::verify).usage(">>no argument<<")
    ).command(
            kw("newLicense").noParameters().executor(this::newLicense).usage(">>no argument<<")
    ).command(
            kw("dumpLicense").noParameters().executor(this::dumpLicense).usage(">>no argument<<")
    ).command(
            kw("dumpPublicKey").noParameters().executor(this::digestPublicKey).usage(">>no argument<<")
    )
            .alias("ll", "licenseload")
            .alias("lprk", "loadprivatekey")
            .alias("lpuk", "loadpublickey")
            .alias("dpk", "dumppublickey")
            .alias("dl", "dumplicense")
            .prompt("L3j> $ ")
            .startup(".license3j")
            .title("License3j REPL application");

    public static void main(String[] args) {
        new App().application.args(args).run();
    }

    public void dumpLicense(CommandEnvironment env) {
        if (license == null) {
            env.message().error("There is no license to show.");
            return;
        }
        try {
            final var baos = new ByteArrayOutputStream();
            final var reader = new LicenseWriter(baos);
            reader.write(license, IOFormat.STRING);
            env.message().info("License:\n" + new String(baos.toByteArray(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            env.message().error("Error writing license file " + e);
        }

    }

    public void saveLicense(CommandEnvironment env) {
        if (license == null) {
            error("There is no license to save.");
            return;
        }
        try {
            final var reader = new LicenseWriter(getLicenseFileName(env));
            final var format = env.parser().getOrDefault(FORMAT, TEXT, Set.of(TEXT, BINARY, BASE_64));
            switch (format) {
                case TEXT:
                    reader.write(license, IOFormat.STRING);
                    break;
                case BINARY:
                    reader.write(license, IOFormat.BINARY);
                    break;
                case BASE_64:
                    reader.write(license, IOFormat.BASE64);
                    break;
                default:
                    error("Invalid format to write the license: " + format);
                    return;
            }
            message("License was saved into the file " + new File(env.line()).getAbsolutePath());
        } catch (IOException e) {
            error("Error writing license file " + e);
        }
    }

    public void loadPrivateKey(CommandEnvironment env) {
        if (keyPair != null && keyPair.getPair() != null && keyPair.getPair().getPrivate() != null) {
            message("Overriding old key from file");
        }
        final var pars = ParameterParser.parse(env.line(), Set.of(FORMAT));
        final var keyFile = pars.get(0);
        if (keyFile == null) {
            messages = new ArrayList<>();
            error("keyFile has to be specified from where the key is loaded");
            return;
        }
        final var format = IOFormat.valueOf(pars.getOrDefault(FORMAT, BINARY, Set.of(TEXT, BINARY)));
        try (final var reader = new KeyPairReader(keyFile)) {
            keyPair = merge(keyPair, reader.readPrivate(format));
            final var keyPath = new File(keyFile).getAbsolutePath();
            message("Private key loaded from" + keyPath);
        } catch (Exception e) {
            error("An exception occurred loading the key: " + e);
            e.printStackTrace();
        }
    }

    public void loadPublicKey(CommandEnvironment env) {
        if (keyPair != null && keyPair.getPair() != null && keyPair.getPair().getPrivate() != null) {
            message("Overriding old key from file");
        }
        final var pars = ParameterParser.parse(env.line(), Set.of(FORMAT));
        final var keyFile = pars.get(0);
        if (keyFile == null) {
            messages = new ArrayList<>();
            error("keyFile has to be specified from where the key is loaded");
            return;
        }
        final var format = IOFormat.valueOf(pars.getOrDefault(FORMAT, BINARY, Set.of(TEXT, BINARY)).toUpperCase());
        try (final var reader = new KeyPairReader(keyFile)) {
            keyPair = merge(keyPair, reader.readPublic(format));
            final var keyPath = new File(keyFile).getAbsolutePath();
            message("Public key loaded from" + keyPath);
        } catch (Exception e) {
            error("An exception occurred loading the keys: " + e);
            e.printStackTrace();
        }
    }

    private LicenseKeyPair merge(LicenseKeyPair oldKp, LicenseKeyPair newKp) {
        if (oldKp == null) {
            return newKp;
        }
        if (newKp.getPair().getPublic() != null) {
            return LicenseKeyPair.Create.from(newKp.getPair().getPublic(), oldKp.getPair().getPrivate());
        }
        if (newKp.getPair().getPrivate() != null) {
            return LicenseKeyPair.Create.from(oldKp.getPair().getPublic(), newKp.getPair().getPrivate());
        }
        return oldKp;
    }

    public void digestPublicKey(CommandEnvironment env) {
        try {
            if (keyPair == null) {
                error("There is no public key loaded");
                return;
            }
            final var key = keyPair.getPublic();
            final var md = MessageDigest.getInstance("SHA-512");
            final var calculatedDigest = md.digest(key);
            final var javaCode = new StringBuilder("--KEY DIGEST START\nbyte [] digest = new byte[] {\n");
            for (int i = 0; i < calculatedDigest.length; i++) {
                int intVal = ((int) calculatedDigest[i]) & 0xff;
                javaCode.append(String.format("(byte)0x%02X, ", intVal));
                if (i % 8 == 0) {
                    javaCode.append("\n");
                }
            }
            javaCode.append("\n};\n---KEY DIGEST END\n");

            javaCode.append("--KEY START\nbyte [] key = new byte[] {\n");
            for (int i = 0; i < key.length; i++) {
                int intVal = ((int) key[i]) & 0xff;
                javaCode.append(String.format("(byte)0x%02X, ", intVal));
                if (i % 8 == 0) {
                    javaCode.append("\n");
                }
            }
            javaCode.append("\n};\n---KEY END\n");

            message("\n" + javaCode.toString());
        } catch (NoSuchAlgorithmException e) {
            error("" + e);
        }
    }

    public void generate(CommandEnvironment env) {
        final var pars = ParameterParser.parse(env.line(),
                Set.of(ALGORITHM, SIZE, FORMAT, PUBLIC_KEY_FILE, PRIVATE_KEY_FILE));
        final var algorithm = pars.getOrDefault(ALGORITHM, "RSA");
        final var sizeString = pars.getOrDefault(SIZE, "2048");
        final var format = IOFormat.valueOf(pars.getOrDefault(FORMAT, BINARY));
        final var publicKeyFile = pars.get(PUBLIC_KEY_FILE);
        final var privateKeyFile = pars.get(PRIVATE_KEY_FILE);
        if (publicKeyFile == null || privateKeyFile == null) {
            error("Keypair generation needs output files specified where keys are to be saved. " +
                    "Use options 'publicKeyFile' and 'privateKeyFile'");
            return;
        }
        final int size;
        try {
            size = Integer.parseInt(sizeString);
        } catch (NumberFormatException e) {
            error("Option size has to be a positive decimal integer value. " +
                    sizeString + " does not qualify as such.");
            return;
        }
        generateKeys(algorithm, size);
        try (final var writer = new KeyPairWriter(privateKeyFile, publicKeyFile)) {
            writer.write(keyPair, format);
            final var privateKeyPath = new File(privateKeyFile).getAbsolutePath();
            message("Private key saved to " + privateKeyPath);
            message("Public key saved to " + new File(publicKeyFile).getAbsolutePath());
        } catch (IOException e) {
            error("An exception occurred saving the keys: " + e);
        }
    }

    public void verify(CommandEnvironment env) {
        if (license.isOK(keyPair.getPair().getPublic())) {
            message("License is properly signed.");
        } else {
            error("License is not signed properly.");
        }
    }

    public void sign(CommandEnvironment env) {
        try {
            final var digest = env.parser().getOrDefault("digest", "SHA-512");
            if (license == null) {
                error("There is no license loaded to be signed");
                return;
            } else {
                license.sign(keyPair.getPair().getPrivate(), digest);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void feature(CommandEnvironment env) {
        if (license == null) {
            error("Feature can not be added when there is no license loaded. Use 'loadLicense' or 'newLicense'");
            return;
        }
        license.add(Feature.Create.from(env.line()));
    }

    public void newLicense(CommandEnvironment env) {
        license = new License();
    }

    public void loadLicense(CommandEnvironment env) {
        try (final var reader = new LicenseReader(getLicenseFileName(env))) {
            final String format = env.parser().getOrDefault(FORMAT, TEXT, Set.of(TEXT, BINARY, BASE_64));
            switch (format) {
                case TEXT:
                    license = reader.read(IOFormat.STRING);
                    break;
                case BINARY:
                    license = reader.read();
                    break;
                case BASE_64:
                    license = reader.read(IOFormat.BASE64);
                    break;
                default:
                    error("Invalid format to read the license: " + format);
            }
        } catch (IOException e) {
            error("Error reading license file " + e);
        }
    }

    private String getLicenseFileName(CommandEnvironment env) {
        return env.parser().get(0);
    }

    private void generateKeys(String algorithm, int size) {
        try {
            keyPair = LicenseKeyPair.Create.from(algorithm, size);
        } catch (NoSuchAlgorithmException e) {
            error("Algorithm " + algorithm + " is not handled by current version of this application.");
        }
    }

    public List<String> getErrors() {
        return errors;
    }

    private void error(String s) {
        errors.add(s);
    }

    public List<String> getMessages() {
        return messages;
    }

    private void message(String s) {
        messages.add(s);
    }
}
