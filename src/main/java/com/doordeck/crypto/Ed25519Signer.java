package com.doordeck.crypto;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class Ed25519Signer {

    public static void main(String[] args) {
        ArgumentParser parser = ArgumentParsers.newFor("Ed25519Signer").build()
                .defaultHelp(true)
                .description("Calculates signatures using EdDSA and Ed25519");
        parser.addArgument("-k", "--key")
                .type(Arguments.fileType().verifyCanRead())
                .dest("key")
                .help("Key file");
        parser.addArgument("-i", "--in")
                .nargs("?")
                .help("Input data file, defaults to stdin")
                .type(FileInputStream.class)
                .dest("in")
                .setDefault(System.in);
        Namespace ns = null;

        try {
            ns = parser.parseArgs(args);
        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());

        File keyFile = ns.get("key");
        BufferedInputStream dataIn = ns.get("in");

        new Ed25519Signer(keyFile, dataIn);
    }

    public Ed25519Signer(File keyFile, InputStream dataIn) {
        // Attempt to read key
        PrivateKey key = null;
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Files.readAllBytes(keyFile.toPath()));
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            key = keyFactory.generatePrivate(keySpec);
        } catch (GeneralSecurityException | IOException e) {
            System.err.println("Unable to read private key");
            e.printStackTrace();
            System.exit(2);
        }

        // Attempt to calculate signature
        try {
            byte[] data = readStream(dataIn);

            Signature sign = Signature.getInstance("EdDSA");
            sign.initSign(key);
            sign.update(data);
            byte[] signature = sign.sign();

            System.out.println(Base64.getUrlEncoder().withoutPadding().encodeToString(signature));
        } catch (IOException | GeneralSecurityException e) {
            System.err.println("Unable to calculate signature");
            e.printStackTrace();
            System.exit(3);
        }
    }

    /**
     * Fully read an input stream to byte[]
     * @param is input stream
     * @return byte[] of the fully read byte stream
     * @throws IOException if unable to read input stream
     */
    private static byte[] readStream(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        int nRead;
        byte[] data = new byte[1024];
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        buffer.flush();
        return buffer.toByteArray();
    }

}
