import javax.xml.parsers.*;
import org.w3c.dom.*;

public class XMLParser {
    public Document parseXML(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new StringInputStream(xmlData));
    }
}
