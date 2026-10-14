// Intentionally vulnerable Java used to exercise the SASTGuard Tree-sitter Java
// scanner. DO NOT use these patterns in real code.
package samples;

import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class Vulnerable {

    // SG-JAVA005: hardcoded credential.
    private String dbPassword = "P@ssw0rd_Prod_2024!";

    public Process runCommand(String userInput) throws Exception {
        // SG-JAVA001: Runtime.exec with concatenated input -> command injection.
        return Runtime.getRuntime().exec("sh -c " + userInput);
    }

    public ResultSet findUser(Connection conn, String name) throws Exception {
        // SG-JAVA002: SQL built by concatenation -> SQL injection.
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
    }

    public Object load(ObjectInputStream ois) throws Exception {
        // SG-JAVA003: insecure deserialization of untrusted data.
        return ois.readObject();
    }

    public byte[] hash(String data) throws Exception {
        // SG-JAVA004: weak hash algorithm (MD5).
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(data.getBytes());
    }
}
