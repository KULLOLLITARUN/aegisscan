package app;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.regex.Pattern;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class SafeUserService {
    private static final Pattern HOST = Pattern.compile("^[A-Za-z0-9.-]{1,253}$");
    private final Connection conn;
    private final String dbPassword = System.getenv("DB_PASSWORD");

    public SafeUserService(Connection conn) {
        this.conn = conn;
    }

    public ResultSet findUser(String name) throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }

    public byte[] hashPassword(char[] pw) throws Exception {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return f.generateSecret(new PBEKeySpec(pw, salt, 210_000, 256)).getEncoded();
    }

    public void ping(String host) throws IOException {
        if (!HOST.matcher(host).matches()) {
            throw new IllegalArgumentException("bad host");
        }
        new ProcessBuilder(List.of("ping", "-c", "1", host)).start();
    }

    public org.w3c.dom.Document parse(InputStream xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder b = dbf.newDocumentBuilder();
        return b.parse(xml);
    }

    public byte[] readFile(String base, String name) throws IOException {
        Path root = Paths.get(base).toRealPath();
        Path target = root.resolve(name).normalize();
        if (!target.startsWith(root)) {
            throw new SecurityException("path escapes base directory");
        }
        return Files.readAllBytes(target);
    }
}
