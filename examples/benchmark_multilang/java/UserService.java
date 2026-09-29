package app;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class UserService {
    private static final String DB_PASSWORD = "Pr0d-Passw0rd-2024!";
    private final Connection conn;

    public UserService(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findUser(String name) throws SQLException {
        Statement st = conn.createStatement();
        return st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public String hashPassword(String pw) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(pw.getBytes()));
    }

    public Object loadSession(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    public void ping(String host) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    public org.w3c.dom.Document parse(InputStream xml) throws Exception {
        DocumentBuilder b = DocumentBuilderFactory.newInstance().newDocumentBuilder();
        return b.parse(xml);
    }

    public byte[] readFile(String base, String name) throws IOException {
        return java.nio.file.Files.readAllBytes(new File(base + "/" + name).toPath());
    }
}
