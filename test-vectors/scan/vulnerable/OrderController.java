// Scanner fixture: intentionally vulnerable code. Not compiled.
// An "expect-next" comment lists the rule ids the following line must produce, and no others.
package fixture;

public class OrderController {

    public void sql(HttpServletRequest request, Connection conn, String sort) throws Exception {
        String id = request.getParameter("id");
        // expect-next: SQL_STRING_CONCAT
        String sql = "SELECT * FROM orders WHERE id = " + id;
        // expect-next: SQL_EXECUTE_CONCAT, SQL_STRING_CONCAT
        conn.createStatement().executeQuery("select * from users where name = '" + name + "'");
        // expect-next: SQL_CLAUSE_CONCAT
        String q = base + " ORDER BY " + sort;
        // expect-next: SQL_STRING_CONCAT
        String page = "SELECT * FROM orders ORDER BY id LIMIT " + size;
        // expect-next: SQL_FORMAT
        String f = String.format("SELECT * FROM t WHERE a = '%s'", id);
        // expect-next: SQL_STRING_CONCAT, SQL_EXECUTE_CONCAT
        jdbcTemplate.queryForList("DELETE FROM sessions WHERE user_id = " + userId);
    }

    public void commands(String file) throws Exception {
        // expect-next: CMD_RUNTIME_EXEC
        Runtime.getRuntime().exec("convert " + file + " out.png");
        // expect-next: CMD_SHELL_PROCESS
        new ProcessBuilder("sh", "-c", "tar xf " + file).start();
        // expect-next: CODE_SCRIPT_ENGINE
        Object r = new ScriptEngineManager().getEngineByName("js");
    }

    public void files(HttpServletRequest request, MultipartFile upload, ZipEntry entry) throws Exception {
        // expect-next: PATH_TRAVERSAL_JAVA
        File f = new File("/srv/uploads/", request.getParameter("name"));
        // expect-next: PATH_TRAVERSAL_JAVA
        Files.write(Paths.get("/srv/uploads", upload.getOriginalFilename()), upload.getBytes());
        // expect-next: PATH_CONCAT_JAVA
        FileInputStream in = new FileInputStream(baseDir + name);
        // expect-next: ZIP_SLIP
        File out = new File(target, entry.getName());
    }

    public void web(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // expect-next: XSS_SERVLET_WRITE
        response.getWriter().println("<p>Hello " + request.getParameter("name") + "</p>");
        // expect-next: OPEN_REDIRECT
        response.sendRedirect(request.getParameter("next"));
        // expect-next: SSRF_JAVA
        String body = restTemplate.getForObject(request.getParameter("url"), String.class);
        // expect-next: REGEX_INJECTION
        Pattern p = Pattern.compile(request.getParameter("filter"));
        // expect-next: LOG_INJECTION
        log.info("search for " + request.getParameter("q"));
        // expect-next: LOG_SECRET
        log.debug("login attempt user={} password={}", user, password);
    }

    public void crypto(String password) throws Exception {
        // expect-next: WEAK_HASH
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        // expect-next: PASSWORD_FAST_HASH
        byte[] h = MessageDigest.getInstance("SHA-256").digest(password.getBytes());
        // expect-next: WEAK_CIPHER
        Cipher c = Cipher.getInstance("AES");
        // expect-next: INSECURE_RANDOM
        String resetToken = Long.toHexString(new Random().nextLong());
        // expect-next: HARDCODED_SECRET
        private static final String API_KEY = "sk_test_51HfakeFAKEfake";
        // expect-next: TLS_VALIDATION_DISABLED
        HttpClients.custom().setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE).build();
        // expect-next: COOKIE_FLAGS
        cookie.setHttpOnly(false);
        // expect-next: JWT_UNVERIFIED
        Claims claims = Jwts.parser().build().parseUnsecuredClaims(token).getPayload();
    }

    public void deserialize(InputStream body) throws Exception {
        // expect-next: UNSAFE_DESERIALIZATION
        Object o = new ObjectInputStream(body).readObject();
        // expect-next: UNSAFE_DESERIALIZATION
        mapper.activateDefaultTyping(ptv, ObjectMapper.DefaultTyping.EVERYTHING);
        // expect-next: XXE
        DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();
    }

    public void errors(HttpServletResponse response) throws Exception {
        try {
            run();
        } catch (Exception e) {
            // expect-next: ERROR_DETAIL_LEAK
            response.getWriter().write(e.getMessage());
            // expect-next: PRINT_STACK_TRACE
            e.printStackTrace();
        }
        // expect-next: EMPTY_CATCH
        try { run(); } catch (IOException ignored) {}
    }

    public Order idor(Long orderId) {
        // expect-next: IDOR_LOOKUP
        return repository.findById(orderId).orElseThrow();
    }

    // The login check passes for every user, then the caller chooses whose orders to read.
    @GetMapping("/api/orders")
    // expect-next: IDOR_IDENTITY_FROM_REQUEST
    public List<Order> orders(@RequestParam("userId") String userId) {
        return repository.findByOwnerId(userId);
    }

    public Account account(HttpServletRequest request) {
        // expect-next: IDOR_IDENTITY_FROM_REQUEST
        return accounts.load(request.getHeader("X-User-Id"));
    }

    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        // expect-next: SPRING_CSRF_DISABLED
        http.csrf(AbstractHttpConfigurer::disable)
            // expect-next: SPRING_PERMIT_ALL
            .authorizeHttpRequests(a -> a.anyRequest().permitAll());
        // expect-next: CORS_WILDCARD
        config.setAllowedOrigins(List.of("*")); config.addAllowedOrigin("*");
        return http.build();
    }

    public void suppressed(String id) {
        // A reviewed finding can be silenced; the scanner must honour this.
        // secure-scan:ignore SQL_STRING_CONCAT -- id is a validated Long
        String sql = "SELECT * FROM orders WHERE id = " + id;
        String other = "SELECT * FROM t WHERE a = " + id; // secure-scan:ignore
    }
}
