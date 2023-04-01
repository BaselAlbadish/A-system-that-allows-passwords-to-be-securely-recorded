import Asymmetric.AES;
import Asymmetric.RSA;
import Asymmetric.RSAkeysWithFiles;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class ClientConnector {
    static AES aes;
    static PublicKey serverPublicKey;
    static byte[] sessionKey;

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        connectToServer();
    }

    public static void connectToServer() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        createAndSavePublicAndPrivateKeys();
        //0123456789101112
        try (Socket socket = new Socket("127.0.0.1", 11111)) {
            Scanner scanner = new Scanner(System.in);
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

//..............................................................................................

            serverPublicKey = (PublicKey) in.readObject();
            //Create Session Key
            SecureRandom secureRandom = new SecureRandom();
            sessionKey = new byte[32];
            secureRandom.nextBytes(sessionKey);

            byte[] sessionKeyArray = RSA.encrypt(sessionKey, serverPublicKey);
            out.writeObject(sessionKeyArray);
            out.flush();

            byte[] iv = (byte[]) in.readObject();
            String cypher = (String) in.readObject();
            aes = new AES(sessionKey,iv);
            System.out.println(aes.decryptAES(cypher));

//..............................................................................................


            while (true) {
                String input = aes.decryptAES((String) in.readObject());
                if (input.charAt(0) == '$') {
                    System.out.println(input);
                    out.writeObject(aes.encryptAsAES(toHexString(getSHA(scanner.nextLine()))));
                    out.flush();
                    continue;
                }
                System.out.println(input);
                out.writeObject(aes.encryptAsAES(scanner.nextLine()));
                out.flush();
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
    public static byte[] getSHA(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(input.getBytes(StandardCharsets.UTF_8));
    }

    public static String toHexString(byte[] hash) {
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString());

        // Pad with leading zeros
        while (hexString.length() < 32) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }
    public static void createAndSavePublicAndPrivateKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        RSAkeysWithFiles rsAkeysWithFiles = new RSAkeysWithFiles();
        KeyPair keyPair = rsAkeysWithFiles.keyPairGenerator();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
        RSAkeysWithFiles.saveKeyToFile("public.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
        RSAkeysWithFiles.saveKeyToFile("private.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
    }
}
