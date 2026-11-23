// Scanner fixture: intentionally vulnerable code. Not executed.
// An "expect-next" comment lists the rule ids the following line must produce, and no others.
import { exec } from 'node:child_process';

app.get('/orders', async (req, res) => {
  // expect-next: SQL_TEMPLATE_LITERAL
  const rows = await db.query(`SELECT * FROM orders WHERE id = ${req.query.id}`);
  // expect-next: SQL_STRING_CONCAT, SQL_EXECUTE_CONCAT
  await db.query("DELETE FROM carts WHERE user_id = " + userId);
  // expect-next: SQL_RAW_UNSAFE
  await prisma.$queryRawUnsafe(sql);
  // expect-next: NOSQL_INJECTION
  const user = await User.findOne(req.body);
  // expect-next: XSS_EXPRESS_SEND
  res.send('<h1>' + req.query.name + '</h1>');
});

app.post('/convert', (req, res) => {
  // expect-next: UNSAFE_DESERIALIZATION_JS
  const job = serialize.unserialize(req.body.data);
  // expect-next: CMD_EXEC_JS
  exec(`convert ${req.body.file} out.png`);
  // expect-next: CMD_SHELL_OPTION
  spawn('convert', [file], { shell: true });
  // expect-next: CODE_EVAL
  const result = eval(req.body.expression);
  // expect-next: REGEX_INJECTION
  const re = new RegExp(req.query.pattern);
});

app.get('/files/:name', (req, res) => {
  // expect-next: PATH_TRAVERSAL_JS
  res.sendFile(path.join(__dirname, 'uploads', req.params.name));
  // expect-next: PATH_TRAVERSAL_JS
  fs.readFile(`./data/${req.query.file}`, 'utf8', cb);
});

app.get('/go', (req, res) => {
  // expect-next: OPEN_REDIRECT
  res.redirect(req.query.next);
  // expect-next: SSRF_JS
  const r = await fetch(req.query.url);
  // expect-next: LOG_INJECTION
  console.log('search', req.query.q);
  // expect-next: MASS_ASSIGNMENT_JS
  Object.assign(user, req.body);
  // expect-next: IDOR_LOOKUP
  const order = await Order.findById(req.params.id);
});

export function ui(el, html) {
  // expect-next: XSS_DOM_SINK
  el.innerHTML = html;
  // expect-next: WEAK_HASH
  const h = crypto.createHash('md5');
  // expect-next: WEAK_CIPHER
  const c = crypto.createCipheriv('aes-128-ecb', key, null);
  // expect-next: INSECURE_RANDOM
  const sessionToken = Math.random().toString(36);
  // expect-next: HARDCODED_SECRET
  const clientSecret = 'f3c9a1b2c3d4e5f6a7b8';
  // expect-next: TLS_VALIDATION_DISABLED
  const agent = new https.Agent({ rejectUnauthorized: false });
  // expect-next: COOKIE_FLAGS
  res.cookie('sid', id, { httpOnly: false });
  // expect-next: JWT_UNVERIFIED
  const claims = jwt.decode(token);
  // expect-next: CORS_WILDCARD
  app.use(cors({ origin: '*' }));
  // expect-next: ERROR_DETAIL_LEAK
  res.status(500).json({ error: err.stack });
  // expect-next: EMPTY_CATCH
  try { run(); } catch (e) {}
}
