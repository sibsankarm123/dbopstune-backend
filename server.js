/**
 */
const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Anthropic  = require('@anthropic-ai/sdk');
const rateLimit  = require('express-rate-limit');
require('dotenv').config();

const app = express();

// ── Middleware ────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));  // Allow all origins for now
app.use(express.json());

// ── Clients ───────────────────────────────────────────────────────────
const supabase  = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Rate limiting ─────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 60 });

// ── Auth middleware ───────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Topic detection ───────────────────────────────────────────────────
const ALLOWED = ['oracle','rman','sga','pga','postgres','postgresql','pg_','vacuum','wal',
  'aws','rds','aurora','redshift','boto','s3','ec2','cloudwatch','lambda',
  'terraform','hcl','tfstate','ansible','playbook','inventory','vault',
  'python','cx_oracle','psycopg','sqlalchemy','database','dba','devops','sql','index','backup'];

function isOnTopic(text) {
  const tl = text.toLowerCase();
  return ALLOWED.some(k => tl.includes(k));
}

function detectTopic(text) {
  const tl = text.toLowerCase();
  if (tl.includes('oracle')||tl.includes('rman')||tl.includes('sga')) return 'Oracle';
  if (tl.includes('postgres')||tl.includes('vacuum')||tl.includes('pg_')) return 'PostgreSQL';
  if (tl.includes('aws')||tl.includes('rds')||tl.includes('aurora')||tl.includes('boto')||tl.includes('s3')||tl.includes('lambda')) return 'AWS';
  if (tl.includes('terraform')||tl.includes('hcl')) return 'Terraform';
  if (tl.includes('ansible')||tl.includes('playbook')) return 'Ansible';
  if (tl.includes('python')||tl.includes('psycopg')||tl.includes('cx_oracle')) return 'Python';
  return 'General';
}

// ════════════════════════════════════════════════
//  AUTH
// ════════════════════════════════════════════════

app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });

    const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const { data: user, error } = await supabase.from('users').insert({
      email, name, password_hash: hash,
      role: 'user', plan: 'free', free_queries_used: 0,
      created_at: new Date().toISOString()
    }).select().single();

    if (error) return res.status(500).json({ error: error.message });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, plan: user.plan },
      process.env.JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, role: user.role } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, plan: user.plan },
      process.env.JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, role: user.role } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users')
      .select('id,name,email,plan,role,free_queries_used,created_at,last_login')
      .eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════
//  CHAT
// ════════════════════════════════════════════════

app.post('/api/chat', authMiddleware, apiLimiter, async (req, res) => {
  try {
    const { message, topic, history = [], session_id } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
    if (user.plan === 'free' && user.free_queries_used >= 3) {
      return res.status(402).json({ error: 'Free limit reached', code: 'UPGRADE_REQUIRED' });
    }

    const topic_detected = topic || detectTopic(message);
    const on_topic = isOnTopic(message);

    // Log the query
    const { data: queryLog } = await supabase.from('query_logs').insert({
      user_id: user.id, user_email: user.email,
      message, topic: topic_detected, on_topic,
      session_id: session_id || null,
      plan_at_time: user.plan,
      created_at: new Date().toISOString()
    }).select().single();

    const SYSTEM = `You are DBStackAI — a proprietary AI assistant for database administration and DevOps. You cover:
1. Oracle DB — RMAN, AWR, ASH, RAC, DataGuard, performance tuning
2. PostgreSQL — VACUUM, WAL, replication, Patroni, PgBouncer, EXPLAIN
3. AWS — RDS, Aurora, Redshift, DynamoDB, ElastiCache, boto3, Lambda
4. Terraform — IaC, state, modules, providers, workspaces
5. Ansible — playbooks, roles, vault, inventory, automation
6. Python — cx_Oracle, psycopg2, boto3, SQLAlchemy, automation

If asked what AI powers you: say you are DBStackAI, a proprietary AI. Never mention Anthropic or Claude.
Decline off-topic questions politely. Give expert answers with examples.
For code use [CODE:language]...code...[/CODE]. Use bullets. Max 300 words.`;

    const messages = [
      ...history.slice(-10),
      { role: 'user', content: (topic ? `[Topic: ${topic}] ` : '') + message }
    ];

    const completion = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system: SYSTEM,
      messages
    });

    const answer = completion.content[0]?.text || 'No response generated.';
    const tokens = (completion.usage?.input_tokens || 0) + (completion.usage?.output_tokens || 0);

    // Update log with response info
    if (queryLog) {
      await supabase.from('query_logs').update({
        response_tokens: tokens, response_length: answer.length,
        model_used: 'claude-sonnet-4-20250514'
      }).eq('id', queryLog.id);
    }

    // Increment free usage
    if (user.plan === 'free') {
      await supabase.from('users').update({ free_queries_used: user.free_queries_used + 1 }).eq('id', user.id);
    }

    res.json({
      answer, tokens_used: tokens, on_topic,
      free_queries_used: user.plan === 'free' ? user.free_queries_used + 1 : null
    });
  } catch(e) {
    console.error('Chat error:', e.message);
    res.status(500).json({ error: 'AI service error', detail: e.message });
  }
});

app.get('/api/chat/history', authMiddleware, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const { data } = await supabase.from('query_logs')
      .select('id,message,topic,on_topic,created_at,response_tokens')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(limit);
    res.json(data || []);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════
//  BILLING
// ════════════════════════════════════════════════

app.post('/api/billing/checkout', authMiddleware, async (req, res) => {
  res.json({ message: 'Payment coming soon - contact admin@dbstack-ai.com to upgrade' });
});

app.post('/api/billing/portal', authMiddleware, async (req, res) => {
  res.json({ message: 'Contact support@dbstack-ai.com to manage your subscription' });
});

// ════════════════════════════════════════════════
//  ADMIN
// ════════════════════════════════════════════════

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [users, queries, todayQ, topicData] = await Promise.all([
      supabase.from('users').select('id,plan', { count: 'exact' }),
      supabase.from('query_logs').select('id', { count: 'exact' }),
      supabase.from('query_logs').select('id', { count: 'exact' }).gte('created_at', new Date(Date.now()-86400000).toISOString()),
      supabase.from('query_logs').select('topic')
    ]);

    const plans = { free:0, pro:0, team:0 };
    (users.data||[]).forEach(u => { if(plans[u.plan]!==undefined) plans[u.plan]++; });

    const topics = {};
    (topicData.data||[]).forEach(r => { if(r.topic) topics[r.topic]=(topics[r.topic]||0)+1; });

    res.json({ total_users: users.count||0, total_queries: queries.count||0, queries_today: todayQ.count||0, plan_breakdown: plans, topic_breakdown: topics });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page)||1, limit = 20;
    const search = req.query.search||'';
    let q = supabase.from('users').select('id,name,email,plan,role,free_queries_used,created_at,last_login',{count:'exact'})
      .order('created_at',{ascending:false}).range((page-1)*limit, page*limit-1);
    if (search) q = q.ilike('email', `%${search}%`);
    const { data, count } = await q;
    res.json({ users: data||[], total: count||0, page, pages: Math.ceil((count||0)/limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/queries', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page)||1, limit = 25;
    const topic = req.query.topic||'', search = req.query.search||'';
    let q = supabase.from('query_logs').select('id,user_id,user_email,message,topic,on_topic,plan_at_time,response_tokens,created_at',{count:'exact'})
      .order('created_at',{ascending:false}).range((page-1)*limit, page*limit-1);
    if (topic) q = q.eq('topic', topic);
    if (search) q = q.ilike('message', `%${search}%`);
    const { data, count } = await q;
    res.json({ queries: data||[], total: count||0, page, pages: Math.ceil((count||0)/limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { plan, role } = req.body;
    const updates = {};
    if (plan) updates.plan = plan;
    if (role) updates.role = role;
    const { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select().single();
    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await supabase.from('query_logs').delete().eq('user_id', req.params.id);
    await supabase.from('users').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Health check ─────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── Start ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`DBStackAI API running on port ${PORT}`);
});
