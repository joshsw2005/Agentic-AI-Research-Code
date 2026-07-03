import org.springframework.web.bind.annotation.*;

@RestController
public class SearchController {
    @GetMapping("/search")
    public String search(@RequestParam String q) {
        return "<h1>Results for: " + q + "</h1>";
    }
}
