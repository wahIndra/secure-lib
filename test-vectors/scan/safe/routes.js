// Scanner fixture: the safe version of the same code. Must produce NO findings.
import { execFile } from 'node:child_process';
import { PathTraversalGuard, UrlGuard, forHtml, sanitizeForLog, AccessGuard, randomToken } from '@wahindra/secure';

const uploads = PathTraversalGuard.forBaseDirectory('/srv/uploads');
const pattern = /select .* from/i;
const m = pattern.exec(text);

app.get('/api/orders', async (req, res) => {
  const user = principalFromVerifiedClaims(req.auth, ClaimMappings.keycloak({ clientId: 'orders-api' }));
  res.json(await Order.find({ ownerId: user.id }));
});

app.get('/orders/:id', async (req, res) => {
  const rows = await db.query('SELECT * FROM orders WHERE id = $1 AND owner_id = $2', [req.params.id, req.user.id]);
  const tagged = await sql`SELECT * FROM orders WHERE id = ${req.params.id}`;
  const order = await Order.findById(req.params.id);
  AccessGuard.requireOwner(req.user, order.ownerId);
  res.json(rows);
});

app.get('/files/:name', (req, res) => {
  res.sendFile(uploads.resolve(req.params.name));
});

app.post('/hook', async (req, res) => {
  const { addresses } = await new UrlGuard().validate(req.body.url);
  console.log('hook', sanitizeForLog(req.body.url));
  execFile('/usr/bin/convert', [input, output], { shell: false });
  el.textContent = name;
  el.innerHTML = forHtml(name);
  const token = randomToken();
  const h = crypto.createHash('sha256');
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const secret = process.env.CLIENT_SECRET;
  res.cookie('sid', id, { httpOnly: true, secure: true, sameSite: 'lax' });
  const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  app.use(cors({ origin: ['https://app.example.com'] }));
  try { run(); } catch (e) { logger.error(e); }
});
