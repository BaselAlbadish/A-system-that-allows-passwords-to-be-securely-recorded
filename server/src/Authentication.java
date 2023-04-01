import Asymmetric.AES;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;

public class Authentication {
    Socket socket;
    DataBase dataBase;

    public Authentication(Socket socket, DataBase dataBase) {
        this.socket = socket;
        this.dataBase = dataBase;
    }

    public Boolean verifyPassword(ClientInfo clientInfo, String userName, String passWord) {
        clientInfo.userName = userName;
        String password = dataBase.executeQuery(clientInfo, "login");
        clientInfo.setPassword(password);
        return passWord.equals(password);
    }

    public Boolean signUpUser(ClientInfo clientInfo, String userName, String passWord) {
        clientInfo.userName = userName;
        clientInfo.setPassword(passWord);
        clientInfo.ID = dataBase.executeQuery(clientInfo,"getLastID")+1;
        String result = dataBase.executeQuery(clientInfo, "addUser");
        return !result.equals("error");
    }

    public Boolean loginOrSignUpProcess(AES aes,ObjectOutputStream output,ObjectInputStream input,ClientInfo clientInfo) {

        boolean readyToGo = false;
        try {
            output.writeObject(aes.encryptAsAES("Please enter *** 1 *** if you would like to LOGIN  or *** 2 *** if you would like to SIGN UP"));
            output.flush();
            String userChoice =  aes.decryptAES((String) input.readObject());

            switch (userChoice) {
                case "1":
                    output.writeObject(aes.encryptAsAES("Please enter your username: "));
                    output.flush();
                    String userUsername = aes.decryptAES((String) input.readObject());
                    output.writeObject(aes.encryptAsAES("Please enter your password: "));
                    output.flush();
                    String userPassword = aes.decryptAES((String) input.readObject());
                    readyToGo = verifyPassword(clientInfo, userUsername, userPassword);
                    break;
                case "2":
                    output.writeObject(aes.encryptAsAES("Please enter A username: "));
                    output.flush();
                    String userUsername1 = aes.decryptAES((String) input.readObject());
                    output.writeObject(aes.encryptAsAES("$Please enter your password: "));
                    output.flush();
                    String userPassword1 = aes.decryptAES((String) input.readObject());
                    readyToGo = signUpUser(clientInfo, userUsername1, userPassword1);
                    break;
            }
            return readyToGo;

        } catch (Exception e) {
            System.out.println("Error:" + socket);
            return false;
        }
    }
}
