/**
 * DBStackAI — Backend API v4 (Clean, no payment)
 * Stack: Node.js + Express + Supabase + Groq (Llama 3.3)
 */
const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const Groq = require('groq-sdk');
const rateLimit = require('express-rate-limit');
require('dotenv').config();
const Razorpay = require('razorpay');
const crypto   = require('crypto');

const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

const PLANS = {
  pro_monthly:      { amount: 19900,  currency: 'INR', label: 'Pro',              period: 'monthly', plan_name: 'pro'      },
  advanced_monthly: { amount: 49900,  currency: 'INR', label: 'Advanced',         period: 'monthly', plan_name: 'advanced' },
  pro_yearly:       { amount: 149900, currency: 'INR', label: 'Pro Yearly',       period: 'yearly',  plan_name: 'pro'      },
  advanced_yearly:  { amount: 399900, currency: 'INR', label: 'Advanced Yearly',  period: 'yearly',  plan_name: 'advanced' },
};

// Free (non-advanced) users get this many AI-scored mock interview answers, lifetime, before
// they must upgrade to the Advanced plan for unlimited mock interviews.
const FREE_MOCK_INTERVIEWS = 2;

// Feature access by plan
const PLAN_FEATURES = {
  free:     { ai_questions: 5, mock_interview: false, kb_full: true, migration_hub: false, resume_review: false },
  pro:      { ai_questions: -1, mock_interview: false, kb_full: true, migration_hub: true, resume_review: false },
  advanced: { ai_questions: -1, mock_interview: true, kb_full: true, migration_hub: true, resume_review: true },
};

const app = express();
app.set('trust proxy', 1);  // Trust Railway's proxy
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── Clients ───────────────────────────────────────────────────────────
const supabase  = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ── Rate limiting ─────────────────────────────────────────────────────
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const apiLimit  = rateLimit({ windowMs: 60 * 1000, max: 60 });

// ── Auth middleware ───────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── Topic helpers ─────────────────────────────────────────────────────
function detectTopic(text) {
  const t = text.toLowerCase();
  if (t.includes('oracle')||t.includes('rman')||t.includes('sga')||t.includes('pga')||t.includes('asm')||t.includes('dataguard')||t.includes('rac')) return 'Oracle';
  if (t.includes('postgres')||t.includes('vacuum')||t.includes('pg_')||t.includes('pgbouncer')||t.includes('wal')) return 'PostgreSQL';
  if (t.includes('aws')||t.includes('rds')||t.includes('aurora')||t.includes('boto')||t.includes('s3')||t.includes('ec2')||t.includes('lambda')||t.includes('cloudwatch')) return 'AWS';
  if (t.includes('terraform')||t.includes('hcl')||t.includes('tfstate')) return 'Terraform';
  if (t.includes('ansible')||t.includes('playbook')||t.includes('inventory')) return 'Ansible';
  if (t.includes('python')||t.includes('psycopg')||t.includes('cx_oracle')||t.includes('boto3')||t.includes('sqlalchemy')) return 'Python';
  return 'General';
}

const ALLOWED_KEYWORDS = ['oracle','rman','sga','pga','asm','redo','archivelog','dataguard','rac',
  'awr','ash','postgres','postgresql','pg_','vacuum','wal','pgbouncer','patroni',
  'aws','rds','aurora','redshift','dynamodb','s3','ec2','vpc','iam','cloudwatch','lambda','boto',
  'terraform','hcl','tfstate','ansible','playbook','inventory','vault',
  'python','cx_oracle','psycopg','sqlalchemy','airflow','dbt',
  'database','dba','dbops','sql','index','backup','recovery','replication','performance'];

function isOnTopic(text) {
  const t = text.toLowerCase();
  return ALLOWED_KEYWORDS.some(k => t.includes(k));
}

// ════════════════════════════════════════════════
//  AUTH ROUTES
// ════════════════════════════════════════════════

// Register
app.post('/api/auth/register', authLimit, async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 8) return res.status(400).json({ error: 'Password min 8 chars' });

    const { data: exists } = await supabase.from('users').select('id').eq('email', email).single();
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const { data: user, error } = await supabase.from('users').insert({
      email, name, password_hash: hash,
      role: 'user', plan: 'free', free_queries_used: 0, mock_interviews_used: 0,
      created_at: new Date().toISOString()
    }).select().single();

    if (error) return res.status(500).json({ error: error.message });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, plan: user.plan },
      process.env.JWT_SECRET, { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, role: user.role, free_queries_used: user.free_queries_used, mock_interviews_used: user.mock_interviews_used } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Login
app.post('/api/auth/login', authLimit, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const { data: user } = await supabase.from('users').select('*').eq('email', email).single();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    await supabase.from('users').update({ last_login: new Date().toISOString() }).eq('id', user.id);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role, plan: user.plan },
      process.env.JWT_SECRET, { expiresIn: '24h' }
    );
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, plan: user.plan, role: user.role, free_queries_used: user.free_queries_used, mock_interviews_used: user.mock_interviews_used } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Me
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const { data: user } = await supabase.from('users')
      .select('id,name,email,plan,role,free_queries_used,mock_interviews_used,created_at,last_login')
      .eq('id', req.user.id).single();
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════
//  CHAT
// ════════════════════════════════════════════════

// Normalize a question to a stable cache key (exact-match cache)
function cacheKey(msg) {
  const norm = String(msg || '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .replace(/[?!.,;:'"`]+$/g, '')
    .trim();
  return crypto.createHash('sha256').update(norm).digest('hex');
}

app.post('/api/chat', auth, apiLimit, async (req, res) => {
  try {
    const { message, topic, history = [], session_id } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    const { data: user } = await supabase.from('users').select('*').eq('id', req.user.id).single();

    // Free plan: 5 questions TOTAL (lifetime, until they subscribe)
    if (user.plan === 'free' && user.free_queries_used >= 5)
      return res.status(402).json({ error: 'Free limit reached (5 questions). Upgrade to Pro for more.', code: 'UPGRADE_REQUIRED' });

    // Pro plan: 100 questions PER DAY (resets at 00:00 UTC). Advanced = unlimited.
    if (user.plan === 'pro') {
      const dayStart = new Date(); dayStart.setUTCHours(0, 0, 0, 0);
      const { count: usedToday } = await supabase.from('query_logs')
        .select('id', { count: 'exact', head: true })
        .eq('user_id', user.id)
        .gte('created_at', dayStart.toISOString());
      if ((usedToday || 0) >= 100)
        return res.status(402).json({
          error: 'Daily limit reached (100 questions/day on Pro). It resets at midnight UTC — or upgrade to Advanced for unlimited.',
          code: 'DAILY_LIMIT'
        });
    }
    // Advanced = fully unlimited, no limits

    const topic_detected = topic || detectTopic(message);
    const on_topic = isOnTopic(message);

    // Log query
    const { data: qlog } = await supabase.from('query_logs').insert({
      user_id:        user.id,
      user_email:     user.email,
      message,
      topic:          topic_detected,
      on_topic,
      session_id:     session_id || null,
      plan_at_time:   user.plan,
      ip_address:     req.ip || req.headers['x-forwarded-for'] || null,
      user_agent:     req.headers['user-agent'] || null,
      created_at:     new Date().toISOString()
    }).select().single();

    // ── ANSWER CACHE (exact-match) ───────────────────────
    // Only standalone, on-topic questions are cacheable (follow-ups need history).
    const cacheable = on_topic && (!history || history.length === 0);
    const ckey = cacheKey(message);
    if (cacheable) {
      try {
        const { data: hit } = await supabase.from('answer_cache')
          .select('answer,hits').eq('cache_key', ckey).maybeSingle();
        if (hit && hit.answer) {
          // Serve from cache — zero Groq tokens.
          await supabase.from('answer_cache')
            .update({ hits: (hit.hits || 0) + 1, last_used: new Date().toISOString() })
            .eq('cache_key', ckey);
          if (qlog) await supabase.from('query_logs')
            .update({ response_tokens: 0, response_length: hit.answer.length, model_used: 'cache' })
            .eq('id', qlog.id);
          if (user.plan === 'free') await supabase.from('users')
            .update({ free_queries_used: user.free_queries_used + 1 }).eq('id', user.id);
          return res.json({ answer: hit.answer, tokens_used: 0, on_topic, cached: true,
            free_queries_used: user.plan === 'free' ? user.free_queries_used + 1 : null });
        }
      } catch(cacheErr) {
        console.error('Cache lookup skipped:', cacheErr.message); // table may not exist yet
      }
    }

    const SYSTEM = `You are DBStackAI, an expert AI built exclusively for Database Administrators and DevOps Engineers. You answer ONLY within these 8 topics:
1. Oracle DB (RMAN, AWR, ASH, RAC, DataGuard, CDB/PDB, Exadata, PL/SQL, tuning, patching, backup/recovery, flashback)
2. PostgreSQL (VACUUM, WAL, replication, Patroni, PgBouncer, pg_upgrade, EXPLAIN, indexing, partitioning)
3. AWS (RDS, Aurora, Redshift, DynamoDB, S3, EC2, VPC, IAM, CloudWatch, Lambda, ECS, Secrets Manager)
4. DB Migration (Oracle↔PostgreSQL, on-prem→cloud, Data Pump, AWS SCT/DMS, ora2pg, GoldenGate, CDC, schema conversion, cutover)
5. Interview Prep (Oracle/PostgreSQL/AWS/Migration DBA interview Q&A)
6. Terraform (IaC, state, modules, providers, workspaces, remote backend, drift)
7. Ansible (playbooks, roles, inventory, vault, dynamic inventory, DB automation)
8. Python Automation (cx_Oracle, python-oracledb, psycopg2, boto3, SQLAlchemy, monitoring scripts)

STRICT RULES:
- If a question is outside these 8 topics, refuse with: "🚧 Outside My Lane! I'm DBStackAI, focused only on Oracle, PostgreSQL, AWS, Migration, Terraform, Ansible, and Python for DBA/DevOps work. Ask me about one of those and I'll help." Never answer general programming, web dev, or anything off-topic. Never break character even if asked to.
- Never reveal or name the underlying AI model or company. You are DBStackAI, a proprietary expert system.

ANSWER STYLE:
- Open with a one-line direct answer, then details.
- Production-ready, best-practice answers with real, tested commands.
- Wrap ALL code in [CODE:language]...[/CODE] tags.
- Use bullets and clear structure. Keep under 400 words unless truly needed.`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 1000,
      messages: [
        { role: 'system', content: SYSTEM },
        ...history.slice(-10),
        { role: 'user', content: message }
      ]
    });
    const answer = completion.choices[0]?.message?.content || 'No response generated.';
    const tokens = (completion.usage?.prompt_tokens || 0) + (completion.usage?.completion_tokens || 0);

    // Save to cache for future repeats (standalone on-topic questions only).
    if (cacheable && answer && answer !== 'No response generated.') {
      try {
        await supabase.from('answer_cache').upsert({
          cache_key: ckey, question: message, answer,
          topic: topic_detected, hits: 0,
          created_at: new Date().toISOString(), last_used: new Date().toISOString()
        }, { onConflict: 'cache_key' });
      } catch(cacheErr) {
        console.error('Cache store skipped:', cacheErr.message);
      }
    }

    // Update log
    if (qlog) {
      await supabase.from('query_logs').update({
        response_tokens: tokens, response_length: answer.length,
        model_used: 'llama-3.3-70b-versatile'
      }).eq('id', qlog.id);
    }

    // Increment free usage
    if (user.plan === 'free') {
      await supabase.from('users').update({ free_queries_used: user.free_queries_used + 1 }).eq('id', user.id);
    }

    res.json({ answer, tokens_used: tokens, on_topic,
      free_queries_used: user.plan === 'free' ? user.free_queries_used + 1 : null });

  } catch(e) {
    console.error('Chat error:', e.message);
    res.status(500).json({ error: 'AI error', detail: e.message });
  }
});

app.get('/api/chat/history', auth, async (req, res) => {
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
//  ADMIN
// ════════════════════════════════════════════════

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const [users, queries, todayQ, topicData] = await Promise.all([
      supabase.from('users').select('id,plan', { count: 'exact' }),
      supabase.from('query_logs').select('id', { count: 'exact' }),
      supabase.from('query_logs').select('id', { count: 'exact' })
        .gte('created_at', new Date(Date.now() - 86400000).toISOString()),
      supabase.from('query_logs').select('topic')
    ]);

    const plans = { free: 0, pro: 0, team: 0 };
    (users.data || []).forEach(u => { if (plans[u.plan] !== undefined) plans[u.plan]++; });

    const topics = {};
    (topicData.data || []).forEach(r => { if (r.topic) topics[r.topic] = (topics[r.topic] || 0) + 1; });

    res.json({ total_users: users.count || 0, total_queries: queries.count || 0,
      queries_today: todayQ.count || 0, plan_breakdown: plans, topic_breakdown: topics });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1, limit = 20;
    const search = req.query.search || '';
    let q = supabase.from('users')
      .select('id,name,email,plan,role,free_queries_used,created_at,last_login', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    if (search) q = q.ilike('email', `%${search}%`);
    const { data, count } = await q;
    res.json({ users: data || [], total: count || 0, page, pages: Math.ceil((count || 0) / limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/admin/queries', auth, adminOnly, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1, limit = 25;
    const topic = req.query.topic || '', search = req.query.search || '';
    let q = supabase.from('query_logs')
      .select('id,user_id,user_email,message,topic,on_topic,plan_at_time,response_tokens,created_at', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    if (topic) q = q.eq('topic', topic);
    if (search) q = q.ilike('message', `%${search}%`);
    const { data, count } = await q;
    res.json({ queries: data || [], total: count || 0, page, pages: Math.ceil((count || 0) / limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const updates = {};
    if (req.body.plan) updates.plan = req.body.plan;
    if (req.body.role) updates.role = req.body.role;
    const { data, error } = await supabase.from('users').update(updates).eq('id', req.params.id).select().single();
    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    await supabase.from('query_logs').delete().eq('user_id', req.params.id);
    await supabase.from('users').delete().eq('id', req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Health

// ── CREATE ORDER ─────────────────────────────────────────────────────
app.post('/api/payment/create-order', auth, async (req, res) => {
  try {
    const { plan_id } = req.body;
    const plan = PLANS[plan_id];
    if (!plan) return res.status(400).json({ error: 'Invalid plan' });
    const order = await razorpay.orders.create({
      amount: plan.amount, currency: plan.currency,
      receipt: ('rc_' + Date.now() + '_' + String(req.user.id).replace(/-/g,'').slice(0, 12)).slice(0, 40),
      notes: { user_id: req.user.id, user_email: req.user.email, plan_id }
    });
    res.json({
      order_id: order.id, amount: order.amount, currency: order.currency,
      plan_label: plan.label, key_id: process.env.RAZORPAY_KEY_ID
    });
  } catch(e) {
    const msg = (e && e.error && e.error.description) || e.message || 'Order creation failed';
    console.error('Order error:', JSON.stringify(e && e.error || e.message));
    res.status(500).json({ error: msg });
  }
});

// ── VERIFY & ACTIVATE ────────────────────────────────────────────────
app.post('/api/payment/verify', auth, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, plan_id } = req.body;
    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature || !plan_id)
      return res.status(400).json({ error: 'Missing payment fields' });

    // Verify signature — CRITICAL, never skip
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(razorpay_order_id + '|' + razorpay_payment_id)
      .digest('hex');
    if (expected !== razorpay_signature)
      return res.status(400).json({ error: 'Payment signature invalid' });

    const plan = PLANS[plan_id];
    if (!plan) return res.status(400).json({ error: 'Invalid plan' });
    const now  = new Date();
    const expires = new Date(now);
    if (plan.period === 'monthly') expires.setMonth(expires.getMonth() + 1);
    if (plan.period === 'yearly')  expires.setFullYear(expires.getFullYear() + 1);
    const planName = PLANS[plan_id] ? PLANS[plan_id].plan_name : 'pro';

    const { data: user, error } = await supabase.from('users')
      .update({
        plan: planName, plan_expires_at: expires.toISOString(),
        razorpay_order_id, razorpay_payment_id, free_queries_used: 0, mock_interviews_used: 0
      })
      .eq('id', req.user.id).select().single();
    if (error) return res.status(500).json({ error: error.message });

    await supabase.from('payment_logs').insert({
      user_id: req.user.id, user_email: req.user.email,
      plan_id, plan_name: planName, amount: plan.amount, currency: plan.currency,
      razorpay_order_id, razorpay_payment_id, status: 'success',
      created_at: now.toISOString()
    });

    const token = require('jsonwebtoken').sign(
      { id: user.id, email: user.email, role: user.role, plan: planName },
      process.env.JWT_SECRET, { expiresIn: '24h' }
    );
    res.json({
      success: true, plan: planName,
      expires_at: expires.toISOString(), token,
      message: 'Welcome to DBStackAI ' + planName.charAt(0).toUpperCase() + planName.slice(1) + '!'
    });
  } catch(e) { console.error('Verify error:', e.message); res.status(500).json({ error: e.message }); }
});

// ── PLANS (public) ───────────────────────────────────────────────────
app.get('/api/plans', (req, res) => {
  res.json(Object.entries(PLANS).map(([id, p]) => ({
    id,
    label:     p.label,
    amount:    p.amount,
    currency:  p.currency,
    period:    p.period,
    plan_name: p.plan_name,
    display:   '₹' + (p.amount / 100).toLocaleString('en-IN') + '/' + (p.period === 'monthly' ? 'mo' : 'yr')
  })));
});

// ── ADMIN: PAYMENT LOGS ──────────────────────────────────────────────
app.get('/api/admin/payments', auth, adminOnly, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1, limit = 25;
    const { data, count } = await supabase.from('payment_logs')
      .select('*', { count: 'exact' })
      .order('created_at', { ascending: false })
      .range((page - 1) * limit, page * limit - 1);
    res.json({ payments: data || [], total: count || 0, page, pages: Math.ceil((count || 0) / limit) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TRACK KB SEARCH ──────────────────────────────────────────────────
app.post('/api/track/kb-search', auth, async (req, res) => {
  try {
    const { topic, section, question_index, action } = req.body;
    // action: 'view_section' | 'open_lesson' | 'unlock_click'
    await supabase.from('kb_events').insert({
      user_id:        req.user.id,
      user_email:     req.user.email,
      plan:           req.user.plan,
      topic,
      section,
      question_index,
      action:         action || 'open_lesson',
      created_at:     new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false }); } // non-critical, don't fail
});

// ── TRACK PAGE VIEW ───────────────────────────────────────────────────
app.post('/api/track/pageview', auth, async (req, res) => {
  try {
    const { page } = req.body;
    await supabase.from('pageviews').insert({
      user_id:    req.user.id,
      user_email: req.user.email,
      plan:       req.user.plan,
      page,
      created_at: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false }); }
});

// ── ADMIN: SEARCH ANALYTICS ───────────────────────────────────────────
app.get('/api/admin/analytics', auth, adminOnly, async (req, res) => {
  try {
    // Top searched topics
    const { data: topTopics } = await supabase
      .from('query_logs')
      .select('topic')
      .not('topic', 'is', null)
      .order('created_at', { ascending: false })
      .limit(500);

    const topicCount = {};
    (topTopics || []).forEach(r => {
      if (r.topic) topicCount[r.topic] = (topicCount[r.topic] || 0) + 1;
    });

    // Top questions asked (most common messages)
    const { data: topQueries } = await supabase
      .from('query_logs')
      .select('message, topic, plan_at_time')
      .order('created_at', { ascending: false })
      .limit(200);

    // Off-topic rate
    const { data: ontopicStats } = await supabase
      .from('query_logs')
      .select('on_topic')
      .order('created_at', { ascending: false })
      .limit(500);

    const onCount  = (ontopicStats||[]).filter(r=>r.on_topic).length;
    const offCount = (ontopicStats||[]).filter(r=>!r.on_topic).length;

    // KB popular lessons
    const { data: kbEvents } = await supabase
      .from('kb_events')
      .select('topic, section, action')
      .order('created_at', { ascending: false })
      .limit(500);

    const kbTopics = {};
    (kbEvents||[]).forEach(r => {
      const k = r.topic + ' > ' + r.section;
      kbTopics[k] = (kbTopics[k] || 0) + 1;
    });

    const unlockClicks = (kbEvents||[]).filter(r=>r.action==='unlock_click').length;

    res.json({
      topic_breakdown:  topicCount,
      top_queries:      (topQueries||[]).slice(0, 20),
      on_topic_count:   onCount,
      off_topic_count:  offCount,
      kb_popular:       Object.entries(kbTopics).sort((a,b)=>b[1]-a[1]).slice(0,10),
      unlock_clicks:    unlockClicks,
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── FEEDBACK ─────────────────────────────────────────────────────────
app.post('/api/feedback', auth, async (req, res) => {
  try {
    const { rating, categories, message, page } = req.body;
    await supabase.from('feedback').insert({
      user_id:    req.user.id,
      user_email: req.user.email,
      plan:       req.user.plan,
      rating:     rating || null,
      categories: categories ? categories.join(', ') : null,
      message:    message || null,
      page:       page || 'about',
      created_at: new Date().toISOString()
    });
    res.json({ ok: true });
  } catch(e) {
    // Non-critical — don't fail the user
    res.json({ ok: true });
  }
});

// ── ADMIN: VIEW FEEDBACK ──────────────────────────────────────────────
app.get('/api/admin/feedback', auth, adminOnly, async (req, res) => {
  try {
    const { data } = await supabase
      .from('feedback')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(100);
    res.json({ feedback: data || [] });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── AI MOCK INTERVIEW SCORING ────────────────────────────────────────
app.post('/api/mock-interview', auth, async (req, res) => {
  try {
    const { role, question, answer, level, type } = req.body;
    if (!question || !answer) return res.status(400).json({ error: 'Missing fields' });

    // Advanced plan + admins: unlimited. Everyone else gets FREE_MOCK_INTERVIEWS free
    // AI-scored attempts (lifetime), then must upgrade to Advanced for unlimited use.
    const { data: user } = await supabase.from('users')
      .select('plan,role,mock_interviews_used').eq('id', req.user.id).single();
    const isUnlimited = user.role === 'admin' || user.plan === 'advanced';
    const usedSoFar = user.mock_interviews_used || 0;
    if (!isUnlimited && usedSoFar >= FREE_MOCK_INTERVIEWS) {
      return res.status(402).json({
        error: `Free mock interview limit reached (${FREE_MOCK_INTERVIEWS}). Upgrade to Advanced for unlimited AI-scored mock interviews.`,
        code: 'UPGRADE_REQUIRED'
      });
    }

    const LEVELS = {
      junior: { yrs: '0-5 years (junior)',  bar: 'Expect solid fundamentals and correct core concepts. Reward clear understanding; do not require deep architecture or large-scale production war stories.' },
      mid:    { yrs: '5-10 years (mid-level)', bar: 'Expect hands-on troubleshooting skill, real production experience, and the ability to reason through practical scenarios with specifics.' },
      senior: { yrs: '10-15 years (senior/architect)', bar: 'Expect architecture-level thinking, trade-off analysis, design for scale/HA/DR, risk management, and leadership. Hold the bar high; generic answers should score low.' }
    };
    const TYPES = {
      technical:    'TECHNICAL: Focus scoring on command-level accuracy, configuration detail, and correct technical reasoning.',
      incident:     'PRODUCTION INCIDENT: Focus scoring on structured troubleshooting approach, specific diagnostic steps (commands, logs, tools), and speed of isolation.',
      architecture: 'ARCHITECTURE: Focus scoring on design trade-offs, HA/DR considerations, scalability thinking, and justification of choices.',
      performance:  'PERFORMANCE TUNING: Focus scoring on diagnostic methodology, specific metrics/wait events, tool usage, and root-cause thinking.',
      migration:    'MIGRATION: Focus scoring on planning, risk mitigation, cutover strategy, validation approach, and rollback handling.',
      rapidfire:    'RAPID FIRE: Expect a concise, accurate answer. Score heavily on correctness and precision; penalise waffle or vague answers.',
      manager:      'MANAGER ROUND: Focus scoring on communication clarity, leadership thinking, stakeholder management, and real-world examples over raw technical depth.'
    };
    const lvl = LEVELS[level] || LEVELS.mid;
    const typeHint = TYPES[type] || TYPES.technical;

    const scoringPrompt = `You are a senior DBA interviewer with 20+ years experience evaluating a ${role} candidate at the ${lvl.yrs} experience level.

Interview type: ${typeHint}

Calibrate your scoring to this level: ${lvl.bar}

Calibrate your scoring to this level: ${lvl.bar}

Question asked: "${question}"

Candidate's answer: "${answer}"

Evaluate this answer and respond with ONLY valid JSON (no markdown, no backticks):
{
  "technical": <1-10 score for technical accuracy and depth>,
  "production": <1-10 score for production experience demonstrated>,
  "communication": <1-10 score for clarity and structure>,
  "overall": <1-10 overall score>,
  "feedback": "<2-3 sentences of specific, actionable feedback>",
  "strong_points": "<what they did well in one sentence>",
  "improve": "<the single most important thing to improve>"
}

Be honest and fair, judged against the ${lvl.yrs} bar. Score 8-10 only for genuinely excellent answers at that level.`;

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      max_tokens: 400,
      messages: [{ role: 'user', content: scoringPrompt }]
    });

    const raw = completion.choices[0]?.message?.content || '{}';
    // Clean JSON response
    const clean = raw.replace(/```json|```/g, '').trim();
    let scores;
    try { scores = JSON.parse(clean); }
    catch(e) {
      scores = { technical:7, production:6, communication:7, overall:7,
        feedback: 'Good attempt. Add more specific production examples.',
        strong_points: 'You covered the core concept.',
        improve: 'Include real command examples and specific scenarios from your experience.' };
    }

    // Log interview session
    await supabase.from('query_logs').insert({
      user_id: req.user.id, user_email: req.user.email,
      message: '[MOCK INTERVIEW] ' + question.substring(0,100),
      topic: role, on_topic: true,
      plan_at_time: user.plan,
      created_at: new Date().toISOString()
    });

    // Count this attempt against the free trial (unless unlimited)
    let mockInterviewsUsed = usedSoFar;
    if (!isUnlimited) {
      mockInterviewsUsed = usedSoFar + 1;
      await supabase.from('users').update({ mock_interviews_used: mockInterviewsUsed }).eq('id', req.user.id);
    }

    res.json({
      ...scores,
      mock_interviews_used: isUnlimited ? null : mockInterviewsUsed,
      mock_interviews_left: isUnlimited ? null : Math.max(0, FREE_MOCK_INTERVIEWS - mockInterviewsUsed)
    });
  } catch(e) {
    console.error('Mock interview error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Keep-alive: a tiny Supabase read so one cron ping keeps BOTH Railway
// and the Supabase project from going idle. Safe to call publicly.
app.get('/health', async (_, res) => {
  let db = 'skip';
  try {
    await supabase.from('users').select('id', { head: true, count: 'exact' }).limit(1);
    db = 'ok';
  } catch (e) { db = 'error'; }
  res.json({ status: 'ok', db, time: new Date().toISOString() });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, '0.0.0.0', () => console.log(`DBStackAI running on port ${PORT}`));
