import java.io.*;

public class UserService {
    public User deserializeUser(byte[] data) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        User user = (User) ois.readObject();
        return user;
    }
}
