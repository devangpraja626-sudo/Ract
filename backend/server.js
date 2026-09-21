require("dotenv").config();
const express = require("express");
const path = require("path");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const { DATABASE_URL, JWT_SECRET } = process.env;
if (!DATABASE_URL || !JWT_SECRET) {
  console.error("Missing DATABASE_URL or JWT_SECRET");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
});

const app = express();
app.use(express.json({ limit: "1mb" }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 6 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype)
      ? cb(null, true)
      : cb(Object.assign(new Error("Only JPG, PNG, WEBP or GIF images"), { status: 400 })),
});

/* ---------- helpers ---------- */
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const clip = (v, n) => String(v ?? "").trim().slice(0, n);
const norm = (s) => String(s || "").toLowerCase().replace(/\s+/g, " ").trim();
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const mediaUrl = (id) => (id ? `/api/media/${id}` : null);
const sign = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: "30d" });

const pub = (r) => ({
  id: r.id,
  full_name: r.full_name,
  startup_name: r.startup_name,
  headline: r.headline,
  industry: r.industry,
  stage: r.stage,
  bio: r.bio,
  website_url: r.website_url,
  verified: r.verified,
  avatar_url: mediaUrl(r.avatar_id),
});
const mine = (r) => ({ ...pub(r), email: r.email });

function auth(req, res, next) {
  try {
    const t = (req.headers.authorization || "").replace("Bearer ", "");
    req.uid = jwt.verify(t, JWT_SECRET).id;
    next();
  } catch {
    res.status(401).json({ error: "Please log in again" });
  }
}

app.param("id", (req, res, next, v) =>
  UUID.test(v) ? next() : res.status(400).json({ error: "Bad id" })
);

const saveMedia = async (ownerId, file) =>
  (
    await pool.query(
      "insert into media(owner_id,mime,data) values($1,$2,$3) returning id",
      [ownerId, file.mimetype, file.buffer]
    )
  ).rows[0].id;

/* ---------- health + media ---------- */
app.get("/api/health", wrap(async (req, res) => {
  await pool.query("select 1");
  res.json({ ok: true });
}));

app.get("/api/media/:id", wrap(async (req, res) => {
  const { rows } = await pool.query("select mime,data from media where id=$1", [req.params.id]);
  if (!rows[0]) return res.sendStatus(404);
  res.set("Content-Type", rows[0].mime);
  res.set("Cache-Control", "public, max-age=31536000, immutable");
  res.send(rows[0].data);
}));

/* ---------- auth ---------- */
app.post("/api/auth/signup", wrap(async (req, res) => {
  const email = clip(req.body.email, 200).toLowerCase();
  const password = String(req.body.password || "");
  const question = clip(req.body.question, 150);
  const answer = norm(req.body.answer);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: "Enter a valid email" });
  if (password.length < 6)
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  if (!question)
    return res.status(400).json({ error: "Choose a security question" });
  if (answer.length < 2)
    return res.status(400).json({ error: "Enter an answer to your security question" });
  const [hash, answerHash] = await Promise.all([
    bcrypt.hash(password, 10),
    bcrypt.hash(answer, 10),
  ]);
  try {
    const { rows } = await pool.query(
      `insert into profiles(email,password_hash,security_question,security_answer_hash)
       values($1,$2,$3,$4) returning *`,
      [email, hash, question, answerHash]
    );
    res.json({ token: sign(rows[0].id), profile: mine(rows[0]) });
  } catch (e) {
    if (e.code === "23505")
      return res.status(409).json({ error: "That email is already registered — log in instead" });
    throw e;
  }
}));

app.post("/api/auth/login", wrap(async (req, res) => {
  const email = clip(req.body.email, 200).toLowerCase();
  const password = String(req.body.password || "");
  const { rows } = await pool.query("select * from profiles where email=$1", [email]);
  if (!rows[0] || !(await bcrypt.compare(password, rows[0].password_hash)))
    return res.status(401).json({ error: "Wrong email or password" });
  res.json({ token: sign(rows[0].id), profile: mine(rows[0]) });
}));

app.post("/api/auth/question", wrap(async (req, res) => {
  const email = clip(req.body.email, 200).toLowerCase();
  const { rows } = await pool.query(
    "select security_question from profiles where email=$1", [email]
  );
  if (!rows[0] || !rows[0].security_question)
    return res.status(404).json({ error: "No recoverable account found for that email" });
  res.json({ question: rows[0].security_question });
}));

app.post("/api/auth/reset", wrap(async (req, res) => {
  const email = clip(req.body.email, 200).toLowerCase();
  const answer = norm(req.body.answer);
  const password = String(req.body.new_password || "");
  if (password.length < 6)
    return res.status(400).json({ error: "New password must be at least 6 characters" });

  const { rows } = await pool.query("select * from profiles where email=$1", [email]);
  const u = rows[0];
  if (!u || !u.security_answer_hash)
    return res.status(400).json({ error: "This account can't be reset" });
  if (u.reset_locked_until && new Date(u.reset_locked_until) > new Date())
    return res.status(429).json({ error: "Too many wrong answers. Try again in 15 minutes." });

  if (!(await bcrypt.compare(answer, u.security_answer_hash))) {
    const fails = (u.reset_fails || 0) + 1;
    if (fails >= 5) {
      await pool.query(
        "update profiles set reset_fails=0, reset_locked_until=now()+interval '15 minutes' where id=$1",
        [u.id]
      );
      return res.status(429).json({ error: "Too many wrong answers. Try again in 15 minutes." });
    }
    await pool.query("update profiles set reset_fails=$2 where id=$1", [u.id, fails]);
    return res.status(401).json({ error: "Wrong answer" });
  }

  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "update profiles set password_hash=$2, reset_fails=0, reset_locked_until=null where id=$1",
    [u.id, hash]
  );
  res.json({ token: sign(u.id), profile: mine(u) });
}));

/* ---------- me ---------- */
app.get("/api/me", auth, wrap(async (req, res) => {
  const { rows } = await pool.query("select * from profiles where id=$1", [req.uid]);
  if (!rows[0]) return res.status(401).json({ error: "Account not found" });
  res.json(mine(rows[0]));
}));

app.put("/api/me", auth, upload.single("avatar"), wrap(async (req, res) => {
  const b = req.body || {};
  const name = clip(b.full_name, 80);
  if (!name) return res.status(400).json({ error: "Please enter your name" });
  let site = clip(b.website_url, 200);
  if (site && !/^https?:\/\//i.test(site)) site = "https://" + site;

  const old = await pool.query("select avatar_id from profiles where id=$1", [req.uid]);
  if (!old.rows[0]) return res.status(401).json({ error: "Account not found" });
  let avatarId = old.rows[0].avatar_id;
  if (req.file) {
    avatarId = await saveMedia(req.uid, req.file);
    if (old.rows[0].avatar_id)
      await pool.query("delete from media where id=$1", [old.rows[0].avatar_id]);
  }
  const { rows } = await pool.query(
    `update profiles set full_name=$2, startup_name=$3, headline=$4, industry=$5,
       stage=$6, bio=$7, website_url=$8, avatar_id=$9 where id=$1 returning *`,
    [req.uid, name, clip(b.startup_name, 100), clip(b.headline, 120), clip(b.industry, 40),
     clip(b.stage, 40), clip(b.bio, 1000), site, avatarId]
  );
  res.json(mine(rows[0]));
}));

app.delete("/api/me", auth, wrap(async (req, res) => {
  await pool.query("delete from profiles where id=$1", [req.uid]);
  res.json({ ok: true });
}));

/* ---------- founders + connections ---------- */
app.get("/api/founders", auth, wrap(async (req, res) => {
  const q = "%" + clip(req.query.q, 60).toLowerCase() + "%";
  const { rows } = await pool.query(
    `select p.*, exists(select 1 from follows f where f.follower_id=$1 and f.following_id=p.id) as connected
     from profiles p
     where p.id<>$1 and p.full_name<>''
       and lower(concat_ws(' ',p.full_name,p.startup_name,p.headline,p.industry,p.stage,p.bio)) like $2
     order by p.created_at desc limit 60`,
    [req.uid, q]
  );
  res.json(rows.map((r) => ({ ...pub(r), connected: r.connected })));
}));

app.get("/api/founders/:id", auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select p.*,
       (select count(*) from posts where user_id=p.id)::int as posts,
       (select count(*) from follows where following_id=p.id)::int as followers,
       (select count(*) from follows where follower_id=p.id)::int as following,
       exists(select 1 from follows where follower_id=$2 and following_id=p.id) as connected
     from profiles p where p.id=$1`,
    [req.params.id, req.uid]
  );
  if (!rows[0]) return res.status(404).json({ error: "Founder not found" });
  const r = rows[0];
  res.json({ ...pub(r), posts: r.posts, followers: r.followers, following: r.following, connected: r.connected });
}));

app.post("/api/connect/:id", auth, wrap(async (req, res) => {
  if (req.params.id === req.uid)
    return res.status(400).json({ error: "You can't connect with yourself" });
  const del = await pool.query(
    "delete from follows where follower_id=$1 and following_id=$2",
    [req.uid, req.params.id]
  );
  if (del.rowCount) return res.json({ connected: false });
  await pool.query("insert into follows(follower_id,following_id) values($1,$2)", [req.uid, req.params.id]);
  res.json({ connected: true });
}));

/* ---------- posts / likes / comments ---------- */
const postSql = `
  select p.id, p.content, p.image_id, p.created_at,
    u.id as author_id, u.full_name, u.startup_name, u.headline, u.avatar_id, u.verified,
    (select count(*) from likes l where l.post_id=p.id)::int as likes,
    (select count(*) from comments c where c.post_id=p.id)::int as comments,
    exists(select 1 from likes l where l.post_id=p.id and l.user_id=$1) as liked
  from posts p join profiles u on u.id=p.user_id`;

const mapPost = (r) => ({
  id: r.id,
  content: r.content,
  image_url: mediaUrl(r.image_id),
  created_at: r.created_at,
  likes: r.likes,
  comments: r.comments,
  liked: r.liked,
  author: pub({
    id: r.author_id, full_name: r.full_name, startup_name: r.startup_name,
    headline: r.headline, avatar_id: r.avatar_id, verified: r.verified,
  }),
});

app.get("/api/feed", auth, wrap(async (req, res) => {
  const params = [req.uid];
  let where = "";
  if (req.query.user && UUID.test(req.query.user)) {
    params.push(req.query.user);
    where = " where p.user_id=$2";
  }
  const { rows } = await pool.query(postSql + where + " order by p.created_at desc limit 100", params);
  res.json(rows.map(mapPost));
}));

app.post("/api/posts", auth, upload.single("image"), wrap(async (req, res) => {
  const content = clip(req.body && req.body.content, 2000);
  if (!content && !req.file)
    return res.status(400).json({ error: "Write something or add an image" });
  const imageId = req.file ? await saveMedia(req.uid, req.file) : null;
  const { rows } = await pool.query(
    "insert into posts(user_id,content,image_id) values($1,$2,$3) returning id",
    [req.uid, content, imageId]
  );
  res.json({ id: rows[0].id });
}));

app.delete("/api/posts/:id", auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    "delete from posts where id=$1 and user_id=$2 returning image_id",
    [req.params.id, req.uid]
  );
  if (!rows[0]) return res.status(404).json({ error: "Post not found" });
  if (rows[0].image_id) await pool.query("delete from media where id=$1", [rows[0].image_id]);
  res.json({ ok: true });
}));

app.post("/api/posts/:id/like", auth, wrap(async (req, res) => {
  const del = await pool.query("delete from likes where post_id=$1 and user_id=$2", [req.params.id, req.uid]);
  if (!del.rowCount)
    await pool.query("insert into likes(post_id,user_id) values($1,$2)", [req.params.id, req.uid]);
  const c = await pool.query("select count(*)::int as n from likes where post_id=$1", [req.params.id]);
  res.json({ liked: !del.rowCount, likes: c.rows[0].n });
}));

app.get("/api/posts/:id/comments", auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select c.id, c.content, c.created_at, u.id as uid, u.full_name, u.avatar_id
     from comments c join profiles u on u.id=c.user_id
     where c.post_id=$1 order by c.created_at asc`,
    [req.params.id]
  );
  res.json(rows.map((r) => ({
    id: r.id, content: r.content, created_at: r.created_at,
    author: pub({ id: r.uid, full_name: r.full_name, avatar_id: r.avatar_id }),
  })));
}));

app.post("/api/posts/:id/comments", auth, wrap(async (req, res) => {
  const content = clip(req.body.content, 500);
  if (!content) return res.status(400).json({ error: "Write a comment first" });
  await pool.query("insert into comments(post_id,user_id,content) values($1,$2,$3)", [req.params.id, req.uid, content]);
  res.json({ ok: true });
}));

/* ---------- direct messages ---------- */
app.get("/api/messages", auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select u.id, u.full_name, u.startup_name, u.avatar_id, m.content, m.created_at
     from (
       select distinct on (other) other, content, created_at
       from (
         select case when sender_id=$1 then receiver_id else sender_id end as other, content, created_at
         from messages where sender_id=$1 or receiver_id=$1
       ) x
       order by other, created_at desc
     ) m join profiles u on u.id=m.other
     order by m.created_at desc`,
    [req.uid]
  );
  res.json(rows.map((r) => ({
    id: r.id, full_name: r.full_name, startup_name: r.startup_name,
    avatar_url: mediaUrl(r.avatar_id), content: r.content, created_at: r.created_at,
  })));
}));

app.get("/api/messages/:id", auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select * from (
       select id, sender_id, content, created_at from messages
       where (sender_id=$1 and receiver_id=$2) or (sender_id=$2 and receiver_id=$1)
       order by id desc limit 300
     ) t order by id asc`,
    [req.uid, req.params.id]
  );
  res.json(rows.map((r) => ({ ...r, id: Number(r.id) })));
}));

app.post("/api/messages/:id", auth, wrap(async (req, res) => {
  const content = clip(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message is empty" });
  await pool.query("insert into messages(sender_id,receiver_id,content) values($1,$2,$3)", [req.uid, req.params.id, content]);
  res.json({ ok: true });
}));

/* ---------- rooms (groups) ---------- */
app.get("/api/groups", auth, wrap(async (req, res) => {
  const { rows } = await pool.query(
    `select g.id, g.name, g.description,
       (select count(*) from group_members m where m.group_id=g.id)::int as members,
       exists(select 1 from group_members m where m.group_id=g.id and m.user_id=$1) as joined
     from groups g order by g.created_at desc limit 100`,
    [req.uid]
  );
  res.json(rows);
}));

app.post("/api/groups", auth, wrap(async (req, res) => {
  const name = clip(req.body.name, 60);
  if (!name) return res.status(400).json({ error: "Give your room a name" });
  const g = await pool.query(
    "insert into groups(name,description,created_by) values($1,$2,$3) returning id",
    [name, clip(req.body.description, 200), req.uid]
  );
  await pool.query("insert into group_members(group_id,user_id) values($1,$2)", [g.rows[0].id, req.uid]);
  res.json({ id: g.rows[0].id });
}));

app.post("/api/groups/:id/join", auth, wrap(async (req, res) => {
  await pool.query(
    "insert into group_members(group_id,user_id) values($1,$2) on conflict do nothing",
    [req.params.id, req.uid]
  );
  const { rows } = await pool.query("select id,name,description from groups where id=$1", [req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: "Room not found" });
  res.json(rows[0]);
}));

const isMember = async (gid, uid) =>
  (await pool.query("select 1 from group_members where group_id=$1 and user_id=$2", [gid, uid])).rowCount > 0;

app.get("/api/groups/:id/messages", auth, wrap(async (req, res) => {
  if (!(await isMember(req.params.id, req.uid))) return res.status(403).json({ error: "Join this room first" });
  const { rows } = await pool.query(
    `select * from (
       select m.id, m.sender_id, m.content, m.created_at, u.full_name
       from group_messages m join profiles u on u.id=m.sender_id
       where m.group_id=$1 order by m.id desc limit 300
     ) t order by id asc`,
    [req.params.id]
  );
  res.json(rows.map((r) => ({ ...r, id: Number(r.id) })));
}));

app.post("/api/groups/:id/messages", auth, wrap(async (req, res) => {
  if (!(await isMember(req.params.id, req.uid))) return res.status(403).json({ error: "Join this room first" });
  const content = clip(req.body.content, 2000);
  if (!content) return res.status(400).json({ error: "Message is empty" });
  await pool.query("insert into group_messages(group_id,sender_id,content) values($1,$2,$3)", [req.params.id, req.uid, content]);
  res.json({ ok: true });
}));

/* ---------- static site + errors ---------- */
app.use("/api", (req, res) => res.status(404).json({ error: "Not found" }));
app.use(express.static(path.join(__dirname, "public")));

app.use((err, req, res, next) => {
  console.error(err.message);
  if (err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: "Image is too large (max 6 MB)" });
  if (err.code === "23503") return res.status(404).json({ error: "Not found" });
  res.status(err.status || 500).json({
    error: err.status ? err.message : "Something went wrong on the server",
  });
});

app.listen(process.env.PORT || 3000, () => console.log("Delta is running"));