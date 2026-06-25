// Fixture 19: resolve(). Reviewer should flag CWE-74 / CWE-917.
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.servlet.http.HttpServletRequest;

public class DirectoryService {

    public Object resolve(HttpServletRequest req) throws Exception {
        String name = req.getParameter("ref");
        Context ctx = new InitialContext();
        return ctx.lookup(name);
    }
}
