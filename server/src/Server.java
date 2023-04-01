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
import java.util.Arrays;

// nc localhost 11111
public class Server implements Runnable {
    Socket socket;
    DataBase dataBase;
    Authentication authentication;
    AES aes;

    Server(DataBase dataBase, Socket socket) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        createAndSavePublicAndPrivateKeys();
        this.socket = socket;
        this.dataBase = dataBase;
    }

    @Override
    public void run() {
        System.out.println("Connected: " + socket);
        ClientInfo clientInfo = new ClientInfo();
        authentication = new Authentication(socket, dataBase);

        try {
            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

//..............................................................................................

            PublicKey publicKey = (PublicKey) RSAkeysWithFiles.readKeyFromFile("public.key");
            output.writeObject(publicKey);
            output.flush();

            //Receive the sessionKey and decrypt it
            byte[] encryptedSessionKey = (byte[]) input.readObject();
            PrivateKey privateKey = (PrivateKey) RSAkeysWithFiles.readKeyFromFile("private.key");
            byte[] AESKey = RSA.decrypt(encryptedSessionKey,privateKey);

            SecureRandom random = new SecureRandom();
            byte[] iv = new byte[16];
            random.nextBytes(iv);
            output.writeObject(iv);

            String cypher;
            aes = new AES(AESKey,iv);
            cypher = aes.encryptAsAES("DONE");
            output.writeObject(cypher);
            output.flush();

//..............................................................................................

            boolean valid = authentication.loginOrSignUpProcess(aes,output,input,clientInfo);
            if (!valid) {
                output.writeObject(this.aes.encryptAsAES("failed in authentication : << connection will stop >>"));
                output.flush();
                socket.close();
                return;
            }
            output.writeObject(this.aes.encryptAsAES("Please enter *** 1 *** for addAccount or *** 2 *** for showAccount or *** 3 *** for editAccount or *** 4 *** for deleteAccount"));
            output.flush();

            String userChoice = this.aes.decryptAES((String) input.readObject());
            switch (userChoice) {
                case "1":
                    Account account = new Account();
                    output.writeObject(this.aes.encryptAsAES("Enter Account Title"));
                    output.flush();

                    account.title = this.aes.decryptAES((String) input.readObject());
                    output.writeObject(this.aes.encryptAsAES("Enter Account UserName"));
                    output.flush();

                    account.userName = this.aes.decryptAES((String) input.readObject());
                    output.writeObject(this.aes.encryptAsAES("Enter Account Email"));
                    output.flush();

                    account.setEmail(this.aes.decryptAES((String) input.readObject()));
                    output.writeObject(this.aes.encryptAsAES("Enter Account Description"));
                    output.flush();

                    account.description = this.aes.decryptAES((String) input.readObject());
                    output.writeObject(this.aes.encryptAsAES("Enter Account password"));
                    output.flush();

                    String value = this.aes.decryptAES((String) input.readObject());
                    account.setPassword(value);
                    output.writeObject(this.aes.encryptAsAES("Enter attachment file to your account"));
                    output.flush();
                    account.file = this.aes.decryptAES((String) input.readObject());
                    clientInfo.setAccount(account);
                    System.out.println(".........................1");
                    clientInfo.ID = dataBase.executeQuery(clientInfo, "getID");
                    System.out.println(".........................2");

                    dataBase.executeQuery(clientInfo, "addAccount");
                    System.out.println(".........................3");

                    break;
                case "2":
                    output.writeObject(this.aes.encryptAsAES("Enter Account Title you want to show"));
                    output.flush();
                    clientInfo.getAccount().title = this.aes.decryptAES((String) input.readObject());
                    String data = dataBase.executeQuery(clientInfo, "showAccount");
                    output.writeObject(this.aes.encryptAsAES(data));
                    output.flush();
                    break;
                case "3":
                    String result;
                    output.writeObject(this.aes.encryptAsAES("Enter what the title you want to edit"));
                    output.flush();
                    clientInfo.getAccount().title = this.aes.decryptAES((String) input.readObject());
                    output.writeObject(this.aes.encryptAsAES("enter the new password -- if not enter 0"));
                    output.flush();
                    result = this.aes.decryptAES((String) input.readObject());
                    if (!result.equals("0")) {
                        clientInfo.getAccount().setPassword(result);
                    }
                    output.writeObject(this.aes.encryptAsAES("enter the new userName -- if not enter 0"));
                    output.flush();
                    result = this.aes.decryptAES((String) input.readObject());
                    if (!result.equals("0")) {
                        clientInfo.getAccount().userName = result;
                    }
                    output.writeObject(this.aes.encryptAsAES("enter the new email -- if not enter 0"));
                    output.flush();
                    result = this.aes.decryptAES((String) input.readObject());
                    if (!result.equals("0")) {
                        clientInfo.getAccount().setEmail(result);
                    }
                    output.writeObject(this.aes.encryptAsAES("enter the new description -- if not enter 0"));
                    output.flush();
                    result = this.aes.decryptAES((String) input.readObject());
                    if (!result.equals("0")) {
                        clientInfo.getAccount().description = result;
                    }
                    dataBase.executeQuery(clientInfo, "editAccount");
                    break;
                case "4":
                    output.writeObject(this.aes.encryptAsAES("enter the account title you want to delete"));
                    output.flush();
                    clientInfo.getAccount().title = this.aes.decryptAES((String) input.readObject());
                    dataBase.executeQuery(clientInfo, "deleteAccount");
                    break;
                default:
                    output.writeObject(this.aes.encryptAsAES("Wrong Input"));
                    output.flush();
                    break;
            }
            output.writeObject(this.aes.encryptAsAES("****  ..<<  Done >>..  ****"));
            output.flush();

        } catch (Exception e) {
            System.out.println("Error:" + socket);
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
            System.out.println("Closed: " + socket);
        }
    }

    public void createAndSavePublicAndPrivateKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        RSAkeysWithFiles rsAkeysWithFiles = new RSAkeysWithFiles();
        KeyPair keyPair = rsAkeysWithFiles.keyPairGenerator();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);
        RSAkeysWithFiles.saveKeyToFile("public.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
        RSAkeysWithFiles.saveKeyToFile("private.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
    }
}
