// Fixture 08: lookup(). Reviewer should flag CWE-89.
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserLookup {
    private final Connection conn;

    public UserLookup(Connection conn) {
        this.conn = conn;
    }

    public String lookup(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        Statement st = conn.createStatement();
        ResultSet rs = st.executeQuery("SELECT email FROM users WHERE name = '" + name + "'");
        if (rs.next()) {
            return rs.getString(1);
        }
        return null;
    }
}
