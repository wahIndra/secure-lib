// Scanner fixture: the safe version of the same code. Must produce NO findings.
package fixture;

import io.github.wahindra.secure.access.AccessGuard;

public class OrderService {

    private static final String FIND_ORDER = "SELECT * FROM orders WHERE id = ? AND owner_id = ?";
    private static final String DOC = "Never write \"SELECT * FROM t WHERE id = \" + id or eval( in code";

    public Order find(Connection conn, long id, User user, String sort) throws Exception {
        PreparedStatement ps = conn.prepareStatement(FIND_ORDER);
        ps.setLong(1, id);
        String col = SafeSql.allowlisted(sort, Arrays.asList("created_at", "total"));
        String sql = "SELECT * FROM orders ORDER BY " + col; // secure-scan:ignore SQL_STRING_CONCAT -- col is allowlisted
        Order order = repository.findById(id).orElseThrow();
        AccessGuard.requireOwnerOrRole(user, order.getOwnerId(), "ADMIN");
        return order;
    }

    private static final String NOTE = "limit " + 10 + " per minute";

    public Path upload(MultipartFile upload, PathTraversalGuard guard) throws Exception {
        Path target = guard.resolve(SafeFileName.sanitize(upload.getOriginalFilename()));
        Files.write(target, upload.getBytes());
        return target;
    }

    public void run(String in, String out) throws Exception {
        SafeCommand.of("/usr/bin/convert").arg(in).arg(out).build().start();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        String token = SecureTokens.urlSafe();
        String apiKey = System.getenv("API_KEY");
        String password = "changeme-in-env";
        log.info("user=" + LogSanitizer.sanitize(request.getParameter("user")));
        response.getWriter().println(Encode.forHtml(request.getParameter("name")));
        ValidatedUrl url = UrlGuard.defaults().validate(request.getParameter("url"));
        ObjectInputStream in2 = new SafeObjectInputStream(stream, "com.acme.dto.");
        String hash = hasher.hash(password.toCharArray()); // PasswordHasher (PBKDF2)
        Pattern p = Pattern.compile(Pattern.quote("x"));
    }

    public void errors(HttpServletResponse response) {
        try {
            run("a", "b");
        } catch (Exception e) {
            String id = SafeErrors.log(LOG, e, "run failed");
            response.getWriter().write(SafeErrors.publicBody(id));
        }
    }
}
