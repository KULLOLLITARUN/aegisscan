package app;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;

// Safe look-alikes for MoreSinks.java: nothing here may be flagged.
public class SafeMoreSinks {
    private static final Set<String> ALLOWED = Set.of("/home", "/account");

    public void unpack(String archive) throws IOException {
        new ProcessBuilder("tar", "xf", archive).start();
        new ProcessBuilder("sh", "-c", "echo done").start();
    }

    public void redirect(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String next = req.getParameter("next");
        resp.sendRedirect(ALLOWED.contains(next) ? next : "/home");
        resp.sendRedirect("/account");
    }

    public byte[] download(HttpServletRequest req) throws IOException {
        Path root = Paths.get("/srv/files").toRealPath();
        Path target = root.resolve(req.getParameter("name")).normalize();
        if (!target.startsWith(root)) {
            throw new SecurityException("path escapes base directory");
        }
        return Files.readAllBytes(target);
    }

    public Cipher modernCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    public Cipher streamCipher() throws Exception {
        return Cipher.getInstance("ChaCha20-Poly1305");
    }

    public void parseXml(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        DocumentBuilder b = dbf.newDocumentBuilder();
        b.parse(in);
    }

    public void saxParse(InputStream in, DefaultHandler h) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.newSAXParser().parse(in, h);
    }
}
