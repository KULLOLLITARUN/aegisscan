package app;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.crypto.Cipher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.helpers.DefaultHandler;

// INTENTIONALLY VULNERABLE benchmark fixture. Do not deploy.
public class MoreSinks {
    public void unpack(String archive) throws IOException {
        new ProcessBuilder("sh", "-c", "tar xf " + archive).start();
    }

    public void redirect(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendRedirect(req.getParameter("next"));
    }

    public byte[] download(HttpServletRequest req) throws IOException {
        FileInputStream in = new FileInputStream(new File("/srv/files", req.getParameter("name")));
        return in.readAllBytes();
    }

    public Cipher legacyCipher() throws Exception {
        return Cipher.getInstance("DES/ECB/PKCS5Padding");
    }

    public Cipher defaultAes() throws Exception {
        return Cipher.getInstance("AES");
    }

    public void parseXml(InputStream in) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = dbf.newDocumentBuilder();
        b.parse(in);
    }

    public void saxParse(InputStream in, DefaultHandler h) throws Exception {
        SAXParserFactory.newInstance().newSAXParser().parse(in, h);
    }
}
