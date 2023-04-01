package Asymmetric;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class AES {
    private static byte[] key;
    private static byte[] initVector ;

    public AES(byte[] sessionKey,byte[] iv){
        initVector = iv;
        key = sessionKey;
    }

    public String encryptAsAES(String data) throws InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException {

        //prepare encrypted cipher
        IvParameterSpec iv = new IvParameterSpec(initVector);
        byte[] sessionKey = key;
        SecretKeySpec skeySpec = new SecretKeySpec(sessionKey, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv); // or Cipher.DECRYPT_MODE
        byte[] encrypted = cipher.doFinal(data.getBytes());
        String s = Base64.getEncoder().encodeToString(encrypted);

        //prepare the MAC
        SecretKey macKey = new SecretKeySpec(sessionKey, "HmacSHA256");
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(macKey);
        hmac.update(encrypted);
        byte[] mac = hmac.doFinal(encrypted);
        String sWithMac = Base64.getEncoder().encodeToString(mac);

        return sWithMac+s;
    }

    public String decryptAES(String data) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        //separating DATA FROM MAC
        //mac
        String incomingMac = data.substring(0,44);
        byte[] encryptedMac = Base64.getDecoder().decode(incomingMac);
        String originalData = data.substring(44);
        byte[] encryptedData = Base64.getDecoder().decode(originalData);

        //decrypt data
        IvParameterSpec iv = new IvParameterSpec(initVector);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] decryptedData = cipher.doFinal(encryptedData);

        //Mac computing
        SecretKey macKey = new SecretKeySpec(key, "HmacSHA256");
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(macKey);
        hmac.update(encryptedData);
        byte[] mac = hmac.doFinal(encryptedData);

        //checking the right MAC
        if (!MessageDigest.isEqual(mac, encryptedMac)) {
            throw new SecurityException("could not authenticate");
        }
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}
