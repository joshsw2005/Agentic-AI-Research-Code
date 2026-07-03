import java.sql.*;

public class Database {
    public User login(String username, String password) throws SQLException {
        String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? new User(rs) : null;
    }
}
