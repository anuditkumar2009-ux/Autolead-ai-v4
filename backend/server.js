const express=require("express");
const cors=require("cors");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const multer=require("multer");
const crypto=require("crypto");
const {parse}=require("csv-parse/sync");
const {body,validationResult}=require("express-validator");
const {Pool}=require("pg");
const {GoogleGenAI}=require("@google/genai");
require("dotenv").config();

const app=express();
app.set("trust proxy",1);
app.use(helmet());
app.use(cors({origin:process.env.FRONTEND_ORIGIN?process.env.FRONTEND_ORIGIN.split(",").map(x=>x.trim()):true}));
app.use(express.json({limit:"1mb"}));
app.use("/api/",rateLimit({windowMs:Number(process.env.RATE_LIMIT_WINDOW_MS)||900000,limit:Number(process.env.RATE_LIMIT_MAX)||100,standardHeaders:"draft-8",legacyHeaders:false}));

const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:2*1024*1024,files:1}});
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const JWT_SECRET=process.env.JWT_SECRET;
const GEMINI_MODEL=process.env.GEMINI_MODEL||"gemini-3-flash-preview";
const TRIAL_DAYS=Number(process.env.TRIAL_DAYS)||7;
const TRIAL_LEADS=Number(process.env.TRIAL_LEADS)||10;
const RESET_MINUTES=30;
const FRONTEND_URL=(process.env.FRONTEND_URL||process.env.FRONTEND_ORIGIN||"").split(",")[0].trim().replace(/\/$/,"");

if(!JWT_SECRET){console.error("FATAL: JWT_SECRET missing");process.exit(1);}

function validate(req,res,next){
  const e=validationResult(req);
  if(!e.isEmpty())return res.status(400).json({error:"Validation failed",details:e.array()});
  next();
}

function tokenFor(u){
  return jwt.sign({id:u.id,email:u.email},JWT_SECRET,{expiresIn:"7d"});
}

function auth(req,res,next){
  const [scheme,t]=String(req.headers.authorization||"").split(" ");
  if(scheme!=="Bearer"||!t)return res.status(401).json({error:"Authentication required"});
  try{
    req.user=jwt.verify(t,JWT_SECRET);
    next();
  }catch{
    return res.status(401).json({error:"Invalid or expired token"});
  }
}

function expired(t){
  return !t.is_active||
    (Date.now()-new Date(t.trial_start_date).getTime())>=TRIAL_DAYS*86400000||
    t.leads_processed_count>=TRIAL_LEADS;
}

function hashResetToken(t){
  return crypto.createHash("sha256").update(t).digest("hex");
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_trials(
      agent_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      trial_start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      leads_processed_count INTEGER NOT NULL DEFAULT 0 CHECK(leads_processed_count>=0),
      is_active BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS leads(
      id BIGSERIAL PRIMARY KEY,
      agent_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name VARCHAR(150) NOT NULL,
      phone VARCHAR(30),
      email VARCHAR(254),
      location VARCHAR(150),
      property_requirement VARCHAR(200),
      budget VARCHAR(100),
      buyer_segment VARCHAR(100),
      source VARCHAR(150) NOT NULL,
      verification_status VARCHAR(30) NOT NULL DEFAULT 'Needs Verification',
      last_verified_date DATE,
      lead_score INTEGER CHECK(lead_score IS NULL OR lead_score BETWEEN 0 AND 100),
      lead_temperature VARCHAR(10),
      lead_status VARCHAR(30) NOT NULL DEFAULT 'New',
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_leads_agent_created ON leads(agent_id,created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_leads_agent_status ON leads(agent_id,lead_status);

    CREATE TABLE IF NOT EXISTS lead_activities(
      id BIGSERIAL PRIMARY KEY,
      lead_id BIGINT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
      agent_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      activity_type VARCHAR(50) NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens(
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash VARCHAR(64) UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_hash ON password_reset_tokens(token_hash);
  `);
}

app.get("/api/health",async(req,res)=>{
  try{
    await pool.query("SELECT 1");
    res.json({
      status:"healthy",
      database:"connected",
      ai:Boolean(process.env.GEMINI_API_KEY),
      email:Boolean(process.env.RESEND_API_KEY),
      model:GEMINI_MODEL
    });
  }catch{
    res.status(503).json({
      status:"unhealthy",
      database:"disconnected",
      ai:Boolean(process.env.GEMINI_API_KEY),
      email:Boolean(process.env.RESEND_API_KEY)
    });
  }
});

app.post("/api/auth/signup",[
  body("name").trim().isLength({min:2,max:100}),
  body("email").trim().isEmail().normalizeEmail(),
  body("password").isLength({min:8,max:128})
],validate,async(req,res)=>{
  const c=await pool.connect();

  try{
    await c.query("BEGIN");

    const h=await bcrypt.hash(req.body.password,12);

    const r=await c.query(
      "INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email",
      [req.body.name,req.body.email,h]
    );

    const u=r.rows[0];

    await c.query(
      "INSERT INTO agent_trials(agent_id) VALUES($1)",
      [u.id]
    );

    await c.query("COMMIT");

    res.status(201).json({
      token:tokenFor(u),
      user:u
    });

  }catch(e){
    await c.query("ROLLBACK");

    if(e.code==="23505"){
      return res.status(409).json({error:"Email already registered"});
    }

    console.error("SIGNUP ERROR",e);
    res.status(500).json({error:"Signup failed"});

  }finally{
    c.release();
  }
});

app.post("/api/auth/login",[
  body("email").trim().isEmail().normalizeEmail(),
  body("password").notEmpty()
],validate,async(req,res)=>{
  try{
    const r=await pool.query(
      "SELECT id,name,email,password_hash FROM users WHERE email=$1",
      [req.body.email]
    );

    const u=r.rows[0];

    if(!u||!(await bcrypt.compare(req.body.password,u.password_hash))){
      return res.status(401).json({error:"Invalid credentials"});
    }

    res.json({
      token:tokenFor(u),
      user:{
        id:u.id,
        name:u.name,
        email:u.email
      }
    });

  }catch(e){
    console.error("LOGIN ERROR",e);
    res.status(500).json({error:"Login failed"});
  }
});

app.post("/api/auth/forgot-password",[
  body("email").trim().isEmail().normalizeEmail()
],validate,async(req,res)=>{
  const generic={
    success:true,
    message:"If an account with that email exists, a password reset link has been sent."
  };

  if(!process.env.RESEND_API_KEY||!process.env.MAIL_FROM||!FRONTEND_URL){
    return res.status(503).json({
      error:"Password reset email service is not configured on the server."
    });
  }

  try{
    const r=await pool.query(
      "SELECT id,name,email FROM users WHERE email=$1",
      [req.body.email]
    );

    if(!r.rows[0])return res.json(generic);

    const u=r.rows[0];

    const raw=crypto.randomBytes(32).toString("hex");
    const hash=hashResetToken(raw);

    await pool.query(
      "DELETE FROM password_reset_tokens WHERE user_id=$1 OR expires_at<NOW()",
      [u.id]
    );

    await pool.query(
      "INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,NOW()+$3 * INTERVAL '1 minute')",
      [u.id,hash,RESET_MINUTES]
    );

    const link=`${FRONTEND_URL}/?reset_token=${encodeURIComponent(raw)}`;

    const safeName=String(u.name).replace(/[&<>\"]/g,"");

    const emailHtml=
      `<div style="font-family:Arial,sans-serif;max-width:560px;margin:auto">`+
      `<h2>Reset your AutoLead AI password</h2>`+
      `<p>Hello ${safeName},</p>`+
      `<p>We received a request to reset your AutoLead AI password.</p>`+
      `<p><a href="${link}" style="display:inline-block;background:#2563eb;color:#fff;padding:12px 18px;border-radius:8px;text-decoration:none">Reset Password</a></p>`+
      `<p>This link expires in ${RESET_MINUTES} minutes and can be used only once.</p>`+
      `<p>If you did not request this, you can safely ignore this email.</p>`+
      `</div>`;

    const rr=await fetch("https://api.resend.com/emails",{
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        Authorization:`Bearer ${process.env.RESEND_API_KEY}`
      },
      body:JSON.stringify({
        from:process.env.MAIL_FROM,
        to:[u.email],
        subject:"Reset your AutoLead AI password",
        html:emailHtml
      })
    });

    if(!rr.ok){
      const detail=await rr.text();

      console.error("RESEND ERROR",detail);

      await pool.query(
        "DELETE FROM password_reset_tokens WHERE token_hash=$1",
        [hash]
      );

      return res.status(502).json({
        error:"Password reset email could not be sent. Check the email service configuration."
      });
    }

    res.json(generic);

  }catch(e){
    console.error("FORGOT PASSWORD ERROR",e);
    res.status(500).json({
      error:"Password reset request failed"
    });
  }
});

app.post("/api/auth/reset-password",[
  body("token").isHexadecimal().isLength({min:64,max:64}),
  body("password").isLength({min:8,max:128})
],validate,async(req,res)=>{
  try{
    const h=hashResetToken(req.body.token);

    const r=await pool.query(
      "SELECT id,user_id FROM password_reset_tokens WHERE token_hash=$1 AND used_at IS NULL AND expires_at>NOW()",
      [h]
    );

    const row=r.rows[0];

    if(!row){
      return res.status(400).json({
        error:"This reset link is invalid or expired."
      });
    }

    const ph=await bcrypt.hash(req.body.password,12);

    const c=await pool.connect();

    try{
      await c.query("BEGIN");

      await c.query(
        "UPDATE users SET password_hash=$1 WHERE id=$2",
        [ph,row.user_id]
      );

      await c.query(
        "UPDATE password_reset_tokens SET used_at=NOW() WHERE user_id=$1 AND used_at IS NULL",
        [row.user_id]
      );

      await c.query("COMMIT");

    }catch(e){
      await c.query("ROLLBACK");
      throw e;

    }finally{
      c.release();
    }

    res.json({
      success:true,
      message:"Password updated successfully. You can now log in with your new password."
    });

  }catch(e){
    console.error("RESET PASSWORD ERROR",e);
    res.status(500).json({
      error:"Password reset failed"
    });
  }
});

app.get("/api/trial",auth,async(req,res)=>{
  try{
    const r=await pool.query(
      "SELECT * FROM agent_trials WHERE agent_id=$1",
      [req.user.id]
    );

    const t=r.rows[0];

    if(!t){
      return res.status(404).json({error:"Trial not found"});
    }

    const days=Math.max(
      0,
      TRIAL_DAYS-
      (Date.now()-new Date(t.trial_start_date).getTime())/86400000
    );

    res.json({
      active:t.is_active&&days>0&&t.leads_processed_count<TRIAL_LEADS,
      daysLeft:Math.ceil(days),
      leadsUsed:t.leads_processed_count,
      leadsRemaining:Math.max(
        0,
        TRIAL_LEADS-t.leads_processed_count
      ),
      limits:{
        days:TRIAL_DAYS,
        leads:TRIAL_LEADS
      }
    });

  }catch(e){
    res.status(500).json({
      error:"Failed to read trial"
    });
  }
});

app.get("/api/leads",auth,async(req,res)=>{
  try{
    const r=await pool.query(
      "SELECT * FROM leads WHERE agent_id=$1 ORDER BY created_at DESC",
      [req.user.id]
    );

    res.json(r.rows);

  }catch(e){
    res.status(500).json({
      error:"Failed to fetch leads"
    });
  }
});

app.post("/api/leads/import",auth,upload.single("file"),async(req,res)=>{
  if(!req.file){
    return res.status(400).json({
      error:"CSV file is required"
    });
  }

  const c=await pool.connect();

  try{
    await c.query("BEGIN");

    const tr=(
      await c.query(
        "SELECT * FROM agent_trials WHERE agent_id=$1 FOR UPDATE",
        [req.user.id]
      )
    ).rows[0];

    if(!tr||expired(tr)){
      await c.query("ROLLBACK");

      return res.status(403).json({
        error:"Free trial expired"
      });
    }

    const rows=parse(
      req.file.buffer.toString("utf8"),
      {
        columns:true,
        skip_empty_lines:true,
        bom:true,
        relax_column_count:true,
        trim:true
      }
    );

    const remain=TRIAL_LEADS-tr.leads_processed_count;

    let imported=0;
    let duplicates=0;
    let invalid=0;

    for(const row of rows.slice(0,remain)){

      const pick=(...ks)=>{
        for(const k of ks){
          const f=Object.keys(row).find(
            x=>x.trim().toLowerCase()===k
          );

          if(f&&String(row[f]).trim()){
            return String(row[f]).trim();
          }
        }

        return null;
      };

      const name=pick(
        "name",
        "full name",
        "prospect",
        "buyer"
      );

      const phone=pick(
        "phone",
        "mobile",
        "contact"
      );

      const email=pick(
        "email",
        "email address"
      );

      const location=pick(
        "city",
        "location"
      );

      const reqt=pick(
        "property",
        "property type",
        "requirement"
      );

      const budget=pick(
        "budget",
        "budget range"
      );

      const segment=pick(
        "segment",
        "buyer segment"
      );

      if(!name||(!phone&&!email)){
        invalid++;
        continue;
      }

      const d=await c.query(
        `SELECT id FROM leads
         WHERE agent_id=$1
         AND (
           ($2 IS NOT NULL AND $2<>'' AND phone=$2)
           OR
           ($3 IS NOT NULL AND $3<>'' AND LOWER(email)=LOWER($3))
         )
         LIMIT 1`,
        [
          req.user.id,
          phone,
          email
        ]
      );

      if(d.rows.length){
        duplicates++;
        continue;
      }

      await c.query(
        `INSERT INTO leads(
          agent_id,
          name,
          phone,
          email,
          location,
          property_requirement,
          budget,
          buyer_segment,
          source,
          verification_status
        )
        VALUES(
          $1,$2,$3,$4,$5,$6,$7,$8,$9,'Needs Verification'
        )`,
        [
          req.user.id,
          name,
          phone,
          email,
          location,
          reqt,
          budget,
          segment,
          `Authorized CSV: ${req.file.originalname}`
        ]
      );

      imported++;
    }

    await c.query(
      "UPDATE agent_trials SET leads_processed_count=leads_processed_count+$1 WHERE agent_id=$2",
      [
        imported,
        req.user.id
      ]
    );

    await c.query("COMMIT");

    res.json({
      success:true,
      imported,
      duplicates,
      invalid,
      message:`${imported} authorized leads imported.`
    });

  }catch(e){
    await c.query("ROLLBACK");

    console.error("CSV IMPORT ERROR",e);

    res.status(400).json({
      error:"CSV could not be processed safely"
    });

  }finally{
    c.release();
  }
});

app.patch("/api/leads/:id/status",auth,[
  body("status").isIn([
    "New",
    "Qualified",
    "Contacted",
    "Interested",
    "Site Visit",
    "Negotiation",
    "Booked",
    "Converted"
  ]),
  body("notes")
    .optional()
    .isString()
    .isLength({max:5000})
],validate,async(req,res)=>{
  try{
    const r=await pool.query(
      "UPDATE leads SET lead_status=$1,notes=COALESCE($2,notes) WHERE id=$3 AND agent_id=$4 RETURNING *",
      [
        req.body.status,
        req.body.notes||null,
        req.params.id,
        req.user.id
      ]
    );

    if(!r.rows[0]){
      return res.status(404).json({
        error:"Lead not found"
      });
    }

    await pool.query(
      "INSERT INTO lead_activities(lead_id,agent_id,activity_type,details) VALUES($1,$2,'Status Change',$3)",
      [
        req.params.id,
        req.user.id,
        `Status changed to ${req.body.status}`
      ]
    );

    res.json({
      success:true,
      lead:r.rows[0]
    });

  }catch(e){
    res.status(500).json({
      error:"Status update failed"
    });
  }
});

app.post("/api/ai/analyze",auth,[
  body("leadId").isInt({min:1})
],validate,async(req,res)=>{

  if(!process.env.GEMINI_API_KEY){
    return res.status(503).json({
      error:"AI provider not connected",
      message:"GEMINI_API_KEY is not configured on the server."
    });
  }

  try{

    const r=await pool.query(
      `SELECT
        id,
        name,
        phone,
        email,
        location,
        property_requirement,
        budget,
        buyer_segment,
        verification_status,
        lead_status,
        notes
       FROM leads
       WHERE id=$1 AND agent_id=$2`,
      [
        req.body.leadId,
        req.user.id
      ]
    );

    const lead=r.rows[0];

    if(!lead){
      return res.status(404).json({
        error:"Lead not found"
      });
    }

    const ai=new GoogleGenAI({
      apiKey:process.env.GEMINI_API_KEY
    });

    const prompt=
      `You are AutoLead AI, a real-estate sales copilot. `+
      `Analyze ONLY the supplied lead data. `+
      `Never invent facts, contact details, property availability, pricing, intent, or verification. `+
      `Return JSON with score (0-100), temperature (Hot/Warm/Cold), `+
      `intent (High/Medium/Low/Unknown), next_best_action, `+
      `follow_up_timing, whatsapp_message, missing_information (array), `+
      `verification_note. Lead data: ${JSON.stringify(lead)}`;

    const out=await ai.models.generateContent({
      model:GEMINI_MODEL,
      contents:prompt,
      config:{
        responseMimeType:"application/json",
        thinkingConfig:{
          thinkingLevel:"high"
        }
      }
    });

    let a;

    try{
      a=JSON.parse(out.text);
    }catch{
      return res.status(502).json({
        error:"AI returned an invalid structured response"
      });
    }

    const score=
      Number.isInteger(a.score)
        ?Math.max(0,Math.min(100,a.score))
        :null;

    const temp=
      ["Hot","Warm","Cold"].includes(a.temperature)
        ?a.temperature
        :null;

    await pool.query(
      "UPDATE leads SET lead_score=$1,lead_temperature=$2 WHERE id=$3 AND agent_id=$4",
      [
        score,
        temp,
        lead.id,
        req.user.id
      ]
    );

    res.json({
      success:true,
      model:GEMINI_MODEL,
      analysis:a
    });

  }catch(e){

    console.error("AI ANALYSIS ERROR",e);

    res.status(502).json({
      error:"AI analysis failed",
      message:"Gemini did not return a usable result."
    });
  }
});

app.get("/",(req,res)=>{
  res.json({
    name:"AutoLead AI V4",
    status:"running"
  });
});

initDb().then(()=>{
  const PORT=Number(process.env.PORT)||5000;

  app.listen(
    PORT,
    ()=>console.log(`AutoLead AI V4 backend on :${PORT}`)
  );

}).catch(e=>{
  console.error("DATABASE INIT FAILED",e);
  process.exit(1);
});
// ==========================================
// META (FACEBOOK) LEAD ADS WEBHOOK ENDPOINT
// ==========================================

// 1. Webhook Verification (Meta API Handshake)
app.get('/api/webhooks/facebook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN || 'autolead_secret_token_2026';

  if (mode && token) {
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('✅ Meta Webhook Verified Successfully!');
      return res.status(200).send(challenge);
    } else {
      return res.sendStatus(403);
    }
  }
  res.sendStatus(400);
});

// 2. Lead Data Processing Endpoint
app.post('/api/webhooks/facebook', async (req, res) => {
  try {
    const body = req.body;

    if (body.object === 'page') {
      for (const entry of body.entry) {
        for (const change of entry.changes) {
          if (change.field === 'leadgen') {
            const leadgenId = change.value.leadgen_id;
            const pageId = change.value.page_id;
            
            console.log(`📥 New Meta Lead Event Received! Lead ID: ${leadgenId}, Page ID: ${pageId}`);

            // DB Insert Query for Lead Record
            // Production me Meta Graph API Call se lead details fecth karke save hoti hain
          }
        }
      }
      return res.status(200).send('EVENT_RECEIVED');
    } else {
      return res.sendStatus(404);
    }
  } catch (error) {
    console.error('❌ Meta Webhook Error:', error);
    return res.status(500).send('Internal Server Error');
  }
});
