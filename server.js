/**
 * DBStackAI — Backend API
 * Stack: Node.js + Express + Supabase (Postgres) + Razorpay + Anthropic
 * 
 * Install: npm install
 * Run:     npm start
 */

const express       = require('express');
const cors          = require('cors');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Anthropic     = require('@anthropic-ai/sdk');
const Razorpay      = require('razorpay');
const crypto        = require('crypto');
const rateLimit     = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());

// ── Clients ──────────────────────────────────────────────────────────────────
const supabase  = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const razorpay  = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID     || 'placeholder',
  key_secret: process.env.RAZORPAY_KEY_SECRET || 'placeholder'
});
const razorpay  = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ── Middleware ────────────────────────────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: 'Too many requests' });
const apiLimiter  = rateLimit({ windowMs: 60 * 1000, max: 60 });

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminMiddleware(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── ALLOWED TOPICS (guardrail) ────────────────────────────────────────────────
const ALLOWED_KEYWORDS = [
  // Oracle
  'oracle','rman','sga','pga','asm','redo','archivelog','flashback','dataguard','rac','exadata',
  'awr','ash','statspack','tablespace','dbms_','dba_','v$','execution plan','hint','optimizer',
  // PostgreSQL
  'postgres','postgresql','pg_','vacuum','wal','pgbouncer','patroni','repmgr','barman',
  'autovacuum','bloat','toast','citus','timescale','replication','explain analyze',
  // AWS
  'aws','rds','aurora','redshift','dynamodb','elasticache','s3','ec2','vpc','iam',
  'cloudwatch','lambda','glue','athena','boto3','cloudformation','eks','parameter store',
  'secrets manager','aurora serverless','multi-az','read replica','rds proxy','documentdb',
  // Terraform
  'terraform','hcl','tfstate','provider','workspace','backend','plan apply','destroy',
  // Ansible
  'ansible','playbook','role','inventory','handler','vault','galaxy','molecule','jinja',
  // Python
  'python','cx_oracle','psycopg','boto','sqlalchemy','pandas','airflow','prefect','dbt',
  'alembic','fabric','paramiko','fastapi','django',
  // General DBA/DevOps
  'database','dba','dbops','dbre','devops','backup','recovery','performance','tuning',
  'index','partition','sql','query','slow query','deadlock','connection pool',
];

function isOnTopic(text) {
  const tl = text.toLowerCase();
  return ALLOWED_KEYWORDS.some(k => tl.includes(k));
}

// ═══════════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Name, email and password required' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });

  const hash = await bcrypt.hash(password, 12);

  const { data: existing } = await supabase
    .from('users').select('id').eq('email', email).single();
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  // Create Razorpay customer
  let customer = { id: null };
  try { customer = await razorpay.customers.create({ name, email, fail_existing: 0 }); } catch(e) { /* non-fatal */ }

  const { data: user, error } = await supabase.from('users').insert({
    email, name, password_hash: hash,
    role: 'user',
    plan: 'free',
    free_queries_used: 0,
    stripe_customer_id: customer.id || null,
    created_at: new Date().toISOString()
  }).select().single();

  if (error) return res.status(500).json({ error: error.message });

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, plan: user.plan },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, role: user.role } });
});

// POST /api/auth/login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  // Update last login
  await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role, plan: user.plan },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

  res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, role: user.role } });
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const { data: user } = await supabase
    .from('users')
    .select('id, name, email, plan, role, free_queries_used, created_at, last_login')
    .eq('id', req.user.id)
    .single();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// ═══════════════════════════════════════════════════════════════════════
//  CHAT ROUTES
// ═══════════════════════════════════════════════════════════════════════

// POST /api/chat
app.post('/api/chat', authMiddleware, apiLimiter, async (req, res) => {
  const { message, topic, history = [], session_id } = req.body;
  if (!message) return res.status(400).json({ error: 'Message required' });

  // Fetch fresh user data for plan/usage check
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();

  // Free plan: max 3 queries
  if (user.plan === 'free' && user.free_queries_used >= 3) {
    return res.status(402).json({
      error: 'Free limit reached',
      code: 'UPGRADE_REQUIRED',
      free_queries_used: user.free_queries_used
    });
  }

  const topic_detected = topic || detectTopic(message);
  const on_topic = isOnTopic(message);

  // Log query BEFORE calling AI (so we capture everything, even off-topic)
  const { data: queryLog } = await supabase.from('query_logs').insert({
    user_id:        user.id,
    user_email:     user.email,
    message:        message,
    topic:          topic_detected,
    on_topic:       on_topic,
    session_id:     session_id || null,
    plan_at_time:   user.plan,
    created_at:     new Date().toISOString()
  }).select().single();

  const SYSTEM = `You are DBStackAI — a proprietary AI built by the DBStackAI team, specialized ONLY for database administration and cloud infrastructure. You cover 6 areas:
1. Oracle DB — performance tuning, RMAN backup/recovery, AWR/ASH, RAC, DataGuard, Exadata, wait events
2. PostgreSQL — tuning, VACUUM, WAL, replication, Patroni, PgBouncer, EXPLAIN, partitioning, Barman
3. AWS — RDS, Aurora, Redshift, DynamoDB, ElastiCache, S3, EC2, VPC, IAM, CloudWatch, Lambda, boto3, Multi-AZ, Read Replicas, RDS Proxy, Secrets Manager
4. Terraform — IaC, modules, state, remote backends, workspaces, providers, HCL
5. Ansible — playbooks, roles, inventory, vault, Galaxy, Molecule, dynamic inventory
6. Python — cx_Oracle, psycopg2, boto3, SQLAlchemy, Airflow, dbt, automation scripting

RULES:
- If asked what AI powers you or who built you: say you are DBStackAI, a proprietary AI assistant. NEVER mention Anthropic, Claude, OpenAI, or any AI provider.
- Decline questions outside these 6 topics politely.
- Give expert answers with real commands, parameters, examples.
- Wrap code: [CODE:language]...code...[/CODE] using sql/python/hcl/yaml/bash.
- Use bullet characters for lists. No markdown headers. Max 300 words unless complexity requires more.`;

  const messages = [
    ...history.slice(-10),  // keep last 10 turns for context
    { role: 'user', content: (topic ? `[Topic: ${topic}] ` : '') + message }
  ];

  try {
    const completion = await anthropic.messages.create({
      model:      'claude-sonnet-4-20250514',
      max_tokens: 1000,
      system:     SYSTEM,
      messages
    });

    const answer = completion.content[0]?.text || 'No response generated.';
    const tokens_used = completion.usage?.input_tokens + completion.usage?.output_tokens;

    // Update query log with response info
    await supabase.from('query_logs').update({
      response_tokens: tokens_used,
      response_length: answer.length,
      model_used:      'claude-sonnet-4-20250514'
    }).eq('id', queryLog.id);

    // Increment usage counter for free users
    if (user.plan === 'free') {
      await supabase.from('users')
        .update({ free_queries_used: user.free_queries_used + 1 })
        .eq('id', user.id);
    }

    // Update session
    if (session_id) {
      await supabase.from('chat_sessions').upsert({
        id:           session_id,
        user_id:      user.id,
        topic:        topic_detected,
        last_message: message.slice(0, 100),
        updated_at:   new Date().toISOString()
      });
    }

    res.json({
      answer,
      query_id:         queryLog.id,
      tokens_used,
      free_queries_used: user.plan === 'free' ? user.free_queries_used + 1 : null,
      on_topic
    });

  } catch (err) {
    console.error('Anthropic error:', err);
    res.status(500).json({ error: 'AI service error', detail: err.message });
  }
});

// GET /api/chat/history  — user's own history
app.get('/api/chat/history', authMiddleware, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const { data } = await supabase
    .from('query_logs')
    .select('id, message, topic, on_topic, created_at, response_tokens')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false })
    .limit(limit);
  res.json(data || []);
});

// ═══════════════════════════════════════════════════════════════════════
//  STRIPE / BILLING ROUTES
// ═══════════════════════════════════════════════════════════════════════

// POST /api/billing/checkout — create Razorpay subscription
app.post('/api/billing/checkout', authMiddleware, async (req, res) => {
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  const { plan = 'pro' } = req.body;

  const planIds = {
    pro:  process.env.RAZORPAY_PLAN_PRO,   // ₹83/mo (~$1)
    team: process.env.RAZORPAY_PLAN_TEAM   // ₹166/mo (~$2)
  };

  // Create Razorpay subscription
  const subscription = await razorpay.subscriptions.create({
    plan_id:         planIds[plan],
    customer_notify: 1,
    total_count:     120,  // 10 years max
    notes:           { user_id: user.id, plan, user_email: user.email }
  });

  // Return subscription ID + key for frontend checkout
  res.json({
    subscription_id:  subscription.id,
    razorpay_key:     process.env.RAZORPAY_KEY_ID,
    amount:           plan === 'pro' ? 100 : 200,  // in USD cents (display only)
    plan,
    user_name:        user.name,
    user_email:       user.email
  });
});

// POST /api/billing/cancel — cancel Razorpay subscription
app.post('/api/billing/portal', authMiddleware, async (req, res) => {
  const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();
  if (!user.stripe_subscription_id) return res.json({ message: 'No active subscription' });
  try {
    await razorpay.subscriptions.cancel(user.stripe_subscription_id, { cancel_at_cycle_end: 1 });
    res.json({ message: 'Subscription will cancel at end of billing period' });
  } catch(e) {
    res.status(400).json({ error: e.message });
  }
});

// POST /api/webhooks/razorpay — Razorpay webhook (upgrade/cancel)
app.post('/api/webhooks/razorpay', express.raw({ type: 'application/json' }), async (req, res) => {
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
  const signature = req.headers['x-razorpay-signature'];
  const body = req.body.toString();

  // Verify webhook signature
  const expectedSig = crypto.createHmac('sha256', webhookSecret).update(body).digest('hex');
  if (signature !== expectedSig) return res.status(400).json({ error: 'Invalid signature' });

  const event = JSON.parse(body);

  // Subscription activated / payment captured → upgrade user
  if (event.event === 'subscription.activated' || event.event === 'payment.captured') {
    const sub = event.payload.subscription?.entity || event.payload.payment?.entity?.description;
    const notes = event.payload.subscription?.entity?.notes || {};
    const { user_id, plan } = notes;
    if (user_id && plan) {
      const subId = event.payload.subscription?.entity?.id;
      await supabase.from('users').update({
        plan,
        stripe_subscription_id: subId,  // reusing column for Razorpay sub ID
        free_queries_used: 0
      }).eq('id', user_id);
    }
  }

  // Subscription cancelled / expired → downgrade to free
  if (event.event === 'subscription.cancelled' || event.event === 'subscription.completed') {
    const subId = event.payload.subscription?.entity?.id;
    if (subId) {
      const { data: user } = await supabase.from('users')
        .select('id').eq('stripe_subscription_id', subId).single();
      if (user) await supabase.from('users')
        .update({ plan: 'free', stripe_subscription_id: null }).eq('id', user.id);
    }
  }

  res.json({ received: true });
});

// POST /api/billing/verify — verify Razorpay payment and upgrade user
app.post('/api/billing/verify', authMiddleware, async (req, res) => {
  const { razorpay_payment_id, razorpay_subscription_id, razorpay_signature, plan } = req.body;

  // Verify signature
  const text = `${razorpay_payment_id}|${razorpay_subscription_id}`;
  const expectedSig = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(text).digest('hex');

  if (razorpay_signature !== expectedSig) {
    return res.status(400).json({ error: 'Payment verification failed' });
  }

  // Upgrade user in database
  await supabase.from('users').update({
    plan: plan || 'pro',
    stripe_subscription_id: razorpay_subscription_id,
    free_queries_used: 0
  }).eq('id', req.user.id);

  res.json({ success: true, plan: plan || 'pro' });
});

// ═══════════════════════════════════════════════════════════════════════
//  ADMIN ROUTES  (role = 'admin' required)
// ═══════════════════════════════════════════════════════════════════════

// GET /api/admin/stats  — dashboard summary
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  const [users, queries, todayQ, topicBreakdown] = await Promise.all([
    supabase.from('users').select('id, plan', { count: 'exact' }),
    supabase.from('query_logs').select('id', { count: 'exact' }),
    supabase.from('query_logs').select('id', { count: 'exact' })
      .gte('created_at', new Date(Date.now() - 86400000).toISOString()),
    supabase.from('query_logs').select('topic').not('topic', 'is', null)
  ]);

  const planBreakdown = { free: 0, pro: 0, team: 0 };
  (users.data || []).forEach(u => { if (planBreakdown[u.plan] !== undefined) planBreakdown[u.plan]++; });

  const topics = {};
  (topicBreakdown.data || []).forEach(r => {
    if (r.topic) topics[r.topic] = (topics[r.topic] || 0) + 1;
  });

  res.json({
    total_users:   users.count || 0,
    total_queries: queries.count || 0,
    queries_today: todayQ.count || 0,
    plan_breakdown: planBreakdown,
    topic_breakdown: topics
  });
});

// GET /api/admin/users  — list all users
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const page  = parseInt(req.query.page) || 1;
  const limit = 20;
  const search = req.query.search || '';

  let q = supabase.from('users')
    .select('id, name, email, plan, role, free_queries_used, created_at, last_login', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range((page - 1) * limit, page * limit - 1);

  if (search) q = q.ilike('email', `%${search}%`);

  const { data, count } = await q;
  res.json({ users: data || [], total: count, page, pages: Math.ceil(count / limit) });
});

// GET /api/admin/queries  — all query logs with user info
app.get('/api/admin/queries', authMiddleware, adminMiddleware, async (req, res) => {
  const page   = parseInt(req.query.page) || 1;
  const limit  = 25;
  const topic  = req.query.topic || '';
  const userId = req.query.user_id || '';
  const search = req.query.search || '';

  let q = supabase.from('query_logs')
    .select('id, user_id, user_email, message, topic, on_topic, plan_at_time, response_tokens, created_at', { count: 'exact' })
    .order('created_at', { ascending: false })
    .range((page - 1) * limit, page * limit - 1);

  if (topic)  q = q.eq('topic', topic);
  if (userId) q = q.eq('user_id', userId);
  if (search) q = q.ilike('message', `%${search}%`);

  const { data, count } = await q;
  res.json({ queries: data || [], total: count, page, pages: Math.ceil(count / limit) });
});

// GET /api/admin/users/:id/queries  — queries for specific user
app.get('/api/admin/users/:id/queries', authMiddleware, adminMiddleware, async (req, res) => {
  const { data } = await supabase.from('query_logs')
    .select('*')
    .eq('user_id', req.params.id)
    .order('created_at', { ascending: false })
    .limit(50);
  res.json(data || []);
});

// PATCH /api/admin/users/:id  — update user plan or role
app.patch('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { plan, role } = req.body;
  const updates = {};
  if (plan) updates.plan = plan;
  if (role) updates.role = role;
  const { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select().single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// DELETE /api/admin/users/:id  — delete user + their logs
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await supabase.from('query_logs').delete().eq('user_id', req.params.id);
  await supabase.from('users').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
function detectTopic(text) {
  const tl = text.toLowerCase();
  if (tl.includes('oracle') || tl.includes('rman') || tl.includes('sga') || tl.includes('asm') || tl.includes('dataguard') || tl.includes('rac')) return 'Oracle';
  if (tl.includes('postgres') || tl.includes('vacuum') || tl.includes('pg_') || tl.includes('pgbouncer')) return 'PostgreSQL';
  if (tl.includes('aws') || tl.includes('rds') || tl.includes('aurora') || tl.includes('boto3') || tl.includes('redshift') || tl.includes('dynamodb') || tl.includes('ec2') || tl.includes('s3') || tl.includes('cloudwatch') || tl.includes('lambda')) return 'AWS';
  if (tl.includes('terraform') || tl.includes('hcl') || tl.includes('tfstate')) return 'Terraform';
  if (tl.includes('ansible') || tl.includes('playbook') || tl.includes('inventory')) return 'Ansible';
  if (tl.includes('python') || tl.includes('psycopg') || tl.includes('cx_oracle') || tl.includes('boto') || tl.includes('sqlalchemy')) return 'Python';
  return 'General';
}

// Health check
app.get('/health', (_, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`DBStackAI API running on port ${PORT}`));
