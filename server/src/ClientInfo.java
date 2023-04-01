public class ClientInfo {
    public String userName;
    private String password;
    private String privateKey;
    private String publicKey;
    private Account account ;
    public String ID;

    ClientInfo(){
        userName = "";
        password = "";
        privateKey = "";
        publicKey = "";
        account = new Account();
    }
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Account getAccount() {
        return account;
    }

    public void setAccount(Account account) {
        this.account = account;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

}
