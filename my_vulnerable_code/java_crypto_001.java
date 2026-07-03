import java.security.MessageDigest;

public class PasswordUtil {
    public static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        return bytesToHex(digest);
    }
}
