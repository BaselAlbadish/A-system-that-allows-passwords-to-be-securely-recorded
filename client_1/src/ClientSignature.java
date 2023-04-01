import java.security.*;

public class ClientSignature {


    byte[] initSignature(byte[] encryptedData, PrivateKey clientPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        SecureRandom random = new SecureRandom();
        signature.initSign(clientPrivateKey, random);
        signature.update(encryptedData);
        return signature.sign();
    }

    boolean VerifySignature(byte[] encryptedData, byte[] signed, PublicKey clientPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature1 = Signature.getInstance("SHA256WithRSA");
        signature1.initVerify(clientPublicKey);
        signature1.update(encryptedData);
        return signature1.verify(signed);
    }
}
