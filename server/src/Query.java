import java.util.HashMap;
import java.util.Map;

public class Query {
    ClientInfo clientInfo;
    Map<String, String> queryList = new HashMap<>();

    Query(ClientInfo clientInfo) {
        this.clientInfo = clientInfo;
        initQueryMap();
    }

    void initQueryMap() {
        queryList.put("addUser",
                "INSERT INTO `passwordsdb`.`users`\n" +
                        "(`id`,\n" +
                        "`userName`,\n" +
                        "`password`,\n" +
                        "`privateKey`,\n" +
                        "`publicKey`)\n" +
                        "VALUES(\n" +
                        "'"+clientInfo.ID + "',\n" +
                        "'"+clientInfo.userName + "',\n" +
                        "'"+clientInfo.getPassword() + "',\n" +
                        "'"+clientInfo.getPrivateKey() + "',\n" +
                        "'"+clientInfo.getPublicKey() + "'\n" +
                        ");\n");

        queryList.put("login",
                "select `users`.`password` from `passwordsdb`.`users` where `userName`='"+clientInfo.userName+"'");

        queryList.put("addAccount",
                "INSERT INTO `passwordsdb`.`accounts`\n" +
                        "(`id`,\n" +
                        "`title`,\n" +
                        "`userName`,\n" +
                        "`email`,\n" +
                        "`description`,\n" +
                        "`password`,\n" +
                        "`attachmentsFile`)\n" +
                        "VALUES(\n" +
                        "'" + clientInfo.ID + "',\n" +
                        "'" + clientInfo.getAccount().title + "',\n" +
                        "'" + clientInfo.getAccount().userName + "',\n" +
                        "'" + clientInfo.getAccount().getEmail() + "',\n" +
                        "'" + clientInfo.getAccount().description + "',\n" +
                        "'" + clientInfo.getAccount().getPassword() + "',\n" +
                        "'" + clientInfo.getAccount().file + "'\n" +
                        ")\n");

        queryList.put("showAccount",
                "SELECT *\n" +
                        "FROM `passwordsdb`.`accounts`\n" +
                        "WHERE `accounts`.`id`=(\n" +
                        "\t\tselect `users`.`id` \n" +
                        "\t\tfrom `passwordsdb`.`users`\n" +
                        "\t\twhere `users`.`userName`='" + clientInfo.userName + "'\n" +
                        "\t\t) and `accounts`.`title` ='" + clientInfo.getAccount().title+"'");

        queryList.put("editAccount",
                "UPDATE `passwordsdb`.`accounts`\n" +
                        "SET\n" +
                        "`password` = '" + clientInfo.getAccount().getPassword() + "'\n" +
                        "`userName` = '" + clientInfo.getAccount().userName + "'\n" +
                        "`email` = '" + clientInfo.getAccount().getEmail() + "'\n" +
                        "`description` = '" + clientInfo.getAccount().description + "'\n" +
                        "WHERE  `accounts`.`id`=(\n" +
                        "select `users`.`id`\n" +
                        "from `passwordsdb`.`users`\n" +
                        "where `users`.`userName`='" + clientInfo.userName + "'\n" +
                        ") and `accounts`.`title` ='" + clientInfo.getAccount().title+"'");

        queryList.put("deleteAccount",
                "DELETE FROM `passwordsdb`.`accounts`\n" +
                        "WHERE `accounts`.`id`=(\n" +
                        "select `users`.`id`\n" +
                        "from `passwordsdb`.`users`\n" +
                        "where `users`.`userName`= '" + clientInfo.userName + "'\n" +
                        ") and `accounts`.`title` = '" + clientInfo.getAccount().title+"'");

        queryList.put("getID",
                "SELECT `users`.`id`\n" +
                        "FROM `passwordsdb`.`users`\n" +
                        "where `users`.`userName` = '"+ clientInfo.userName +"'");
        queryList.put("getLastID",
                "SELECT `users`.`id` FROM `passwordsdb`.`users` WHERE id=(SELECT MAX(id) FROM `passwordsdb`.`users`);");
    }
}
