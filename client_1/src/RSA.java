import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSA {
    public static String convertKeyToString(Key secretKey){
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static PublicKey convertArrayToPubKey(byte[] encoded) throws Exception {
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(pubKeySpec);
    }

    public static void main(String[] args) throws Exception {
        byte[] Key = {88, 81, 28, 38, 48, 58, 68, 78,88, 81, 28, 38, 48, 58, 68, 78};
        byte[] iv = {1,2,5,6,8,3,7,3,7,8,3,7,3,7,8,3};
        AES aes = new AES(Key,iv);

        String password = "123456789";
        createAndSavePublicAndPrivateKeys();

        PublicKey clientPublicKey = (PublicKey) RSAkeysWithFiles.readKeyFromFile("public.key");
        PrivateKey clientPrivateKey = (PrivateKey) RSAkeysWithFiles.readKeyFromFile("private.key");


        String string = convertKeyToString(clientPublicKey);

        PublicKey publicKey = convertArrayToPubKey(Base64.getDecoder().decode(string.getBytes()));
        if (clientPublicKey.equals(publicKey)){
            System.out.println("2");
        }

//
//        byte[] s = aes.encryptAsAES(password).getBytes();
//        //................................................................................
//
//        Signature signature = Signature.getInstance("SHA256WithRSA");
//        SecureRandom random = new SecureRandom();
//        signature.initSign(clientPrivateKey,random);
//        signature.update(s);
//
//        byte[] signed = signature.sign();
//
//        //................................................................................
//        Signature signature1 = Signature.getInstance("SHA256WithRSA");
//        signature1.initVerify(clientPublicKey);
//        signature1.update(s);
//        boolean verifies = signature1.verify(signed); //returns true if the signature matches
//        System.out.println("signature verifies: " + verifies);
//
//        byte[] d = RSA.encrypt(password.getBytes(), clientPublicKey);
//        byte[] d1 = RSA.decrypt(d,clientPrivateKey);
//        System.out.println("signature verifies: " +new String (d1, StandardCharsets.UTF_8));

    }

    public static byte[] encrypt(byte[] plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText);
    }

    public static byte[] decrypt(byte[] cipherTextArray, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(cipherTextArray);
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