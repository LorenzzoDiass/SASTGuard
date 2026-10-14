// Safe Java equivalents. The SASTGuard Java scanner must NOT raise
// SG-JAVA001..SG-JAVA005 for any of these patterns.
package samples.safe;

import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class Safe {

    // Safe: secret read from the environment, not hardcoded.
    private String dbPassword = System.getenv("DB_PASSWORD");

    public Process runCommand(String userInput) throws Exception {
        // Safe: argument array via ProcessBuilder, no shell string building.
        ProcessBuilder pb = new ProcessBuilder("echo", userInput);
        return pb.start();
    }

    public ResultSet findUser(Connection conn, String name) throws Exception {
        // Safe: PreparedStatement with a bound parameter.
        PreparedStatement ps = conn.prepareStatement(
            "SELECT * FROM users WHERE name = ?");
        ps.setString(1, name);
        return ps.executeQuery();
    }

    public byte[] hash(String data) throws Exception {
        // Safe: strong hash algorithm.
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data.getBytes());
    }
}
