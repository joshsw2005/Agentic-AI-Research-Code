import org.springframework.web.bind.annotation.*;
import java.nio.file.*;

@RestController
public class FileController {
    @GetMapping("/download")
    public String download(@RequestParam String file) throws IOException {
        String path = "/var/www/files/" + file;
        return Files.readString(Paths.get(path));
    }
}
