import express, { Request, Response, NextFunction } from 'express';
import { createServer as createViteServer } from 'vite';
import { spawn, ChildProcess } from 'child_process';
import http from 'http';
import path from 'path';

const app = express();
app.set('trust proxy', 1); // correct client IPs behind Render/Railway/Fly proxies
const PORT = Number(process.env.PORT || 3000);
const PYTHON_PORT = Number(process.env.API_PORT || 8001);
const PYTHON_BIN = process.env.PYTHON_BIN || (process.platform === 'win32' ? 'python' : 'python3');
const IS_PROD = process.env.NODE_ENV === 'production';
const LANDING = path.resolve('landing', 'index.html');

// ---- Python FastAPI backend (spawned unless you run it yourself: SKIP_PYTHON=1) -----------------
let pyProcess: ChildProcess | null = null;
function startPython() {
  if (process.env.SKIP_PYTHON === '1') return;
  pyProcess = spawn(PYTHON_BIN, ['-m', 'backend.main'], {
    stdio: 'inherit',
    env: { ...process.env, API_PORT: String(PYTHON_PORT) },
  });
  pyProcess.on('error', (err) => console.error(`[FastAPI] could not start "${PYTHON_BIN}": ${err.message}`));
  pyProcess.on('exit', (code, signal) => console.log(`[FastAPI] exited (code ${code}, signal ${signal})`));
}
function stopPython() {
  try {
    pyProcess?.kill();
  } catch {
    /* ignore */
  }
}
startPython();
process.on('exit', stopPython);
process.on('SIGINT', () => { stopPython(); process.exit(0); });
process.on('SIGTERM', () => { stopPython(); process.exit(0); });

// ---- Per-IP rate limits on the endpoints that cost money or rewrite the shared graph ------------
const buckets = new Map<string, number[]>();
function limit(name: string, max: number, windowMs: number) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = `${name}:${req.ip}`;
    const now = Date.now();
    const hits = (buckets.get(key) || []).filter((t) => now - t < windowMs);
    if (hits.length >= max) {
      const wait = Math.ceil((windowMs - (now - hits[0])) / 1000);
      res.status(429).json({ error: 'rate_limited', detail: `Too many requests. Try again in ${wait}s.` });
      return;
    }
    hits.push(now);
    buckets.set(key, hits);
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (!v.some((t) => now - t < 120_000)) buckets.delete(k);
}, 60_000).unref();

app.use('/api/agent/stream', limit('agent', 10, 60_000));
app.use('/api/scan', limit('scan', 3, 60_000));
app.use('/api/load-preset', limit('preset', 20, 60_000));
app.use('/api/cypher', limit('cypher', 30, 60_000));
app.use('/api/tools/execute', limit('tools', 60, 60_000));

// Optional: set DISABLE_SCAN=1 on a public demo so visitors cannot rewrite the shared graph.
if (process.env.DISABLE_SCAN === '1') {
  app.post('/api/scan', (_req, res) =>
    res.status(403).json({ error: 'scan_disabled', detail: 'Custom scans are turned off on this public demo. Use the preset projects.' })
  );
}

// ---- Host health check ---------------------------------------------------------------------------
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// ---- /api -> FastAPI. Streams request and response untouched (works for POST bodies and SSE) -----
// There is deliberately NO canned fallback data here: if the backend is down the UI must say so.
app.use('/api', (req, res) => {
  const proxyReq = http.request(
    {
      hostname: '127.0.0.1',
      port: PYTHON_PORT,
      path: req.originalUrl,
      method: req.method,
      headers: { ...req.headers, host: `127.0.0.1:${PYTHON_PORT}` },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on('error', () => {
    if (!res.headersSent) res.status(503).json({ error: 'backend_unavailable', detail: 'FastAPI backend is not reachable (still starting?)' });
    else res.end();
  });
  res.on('close', () => proxyReq.destroy()); // client went away (e.g. closed an SSE stream)
  req.pipe(proxyReq);
});

// ---- Pages: landing page at /, the React app at /app/ -------------------------------------------
app.get('/', (_req, res) => res.sendFile(LANDING));

async function start() {
  if (IS_PROD) {
    app.use('/app', express.static('dist'));
    app.get('/app/*', (_req, res) => res.sendFile(path.resolve('dist', 'index.html')));
  } else {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: 'spa', base: '/app/' });
    app.use(vite.middlewares);
  }
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Blast Radius] landing http://localhost:${PORT}/  app http://localhost:${PORT}/app/  (backend :${PYTHON_PORT})`);
  });
}
start();
