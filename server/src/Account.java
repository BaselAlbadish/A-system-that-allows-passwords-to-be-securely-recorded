import java.io.File;

public class Account {
    public String title;
    public String userName;
    public String description;
    public String file;
    private String password;
    private String email;

    Account() {
        title = "";
        userName = "";
        description = "";
        file = "";
        password = "";
        email = "";
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean addNewAcct(Account acct) {
        return true;
    }

    public Account viewAcct(String title) {
        return new Account();
    }

    public boolean editAcct(String title) {
        Account acct = new Account();
        return true;
    }

    public boolean deleteAcct(String title) {
        return true;
    }

}
