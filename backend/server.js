const express=require("express");
const cors=require("cors");
const helmet=require("helmet");
const rateLimit=require("express-rate-limit");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const multer=require("multer");
const {parse}=require("csv-parse/sync");
const {body,validationResult}=require("express-validator");
const {Pool}=require("pg");
const {GoogleGenAI}=require("@google/genai");
require("dotenv").config();

const app=express(); app.set("trust proxy",1); app.use(helmet());
app.use(cors({origin:process.env.FRONTEND_ORIGIN?process.env.FRONTEND_ORIGIN.split(",").map(x=>x.trim()):true}));
app.use(express.json({limit:"1mb"}));
app.use("/api/",rateLimit({windowMs:Number(process.env.RATE_LIMIT_WINDOW_MS)||900000,limit:Number(process.env.RATE_LIMIT_MAX)||100,standardHeaders:"draft-8",legacyHeaders:false}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:2*1024*1024,files:1}});
const pool=new Pool({connectionString:process.env.DATABASE_URL});
const JWT_SECRET=process.env.JWT_SECRET;
const GEMINI_MODEL=process.env.GEMINI_MODEL||"gemini-3-flash-preview";
const TRIAL_DAYS=Number(process.env.TRIAL_DAYS)||7, TRIAL_LEADS=Number(process.env.TRIAL_LEADS)||10;
if(!JWT_SECRET){console.error("FATAL: JWT_SECRET missing");process.exit(1);}

function validate(req,res,next){const e=validationResult(req);if(!e.isEmpty())return res.status(400).json({error:"Validation failed",details:e.array()});next();}
function tokenFor(u){return jwt.sign({id:u.id,email:u.email},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){
 const [scheme,t]=String(req.headers.authorization||"").split(" ");
 if(scheme!=="Bearer"||!t)return res.status(401).json({error:"Authentication required"});
 try{req.user=jwt.verify(t,JWT_SECRET);next();}catch{return res.status(401).json({error:"Invalid or expired token"});}
}
function expired(t){return !t.is_active||(Date.now()-new Date(t.trial_start_date).getTime())>=TRIAL_DAYS*86400000||t.leads_processed_count>=TRIAL_LEADS;}

app.get("/api/health",async(req,res)=>{try{await pool.query("SELECT 1");res.json({status:"healthy",database:"connected",ai:Boolean(process.env.GEMINI_API_KEY),model:GEMINI_MODEL});}catch{res.status(503).json({status:"unhealthy",database:"disconnected",ai:Boolean(process.env.GEMINI_API_KEY)});}});

app.post("/api/auth/signup",[
 body("name").trim().isLength({min:2,max:100}),body("email").trim().isEmail().normalizeEmail(),body("password").isLength({min:8,max:128})
],validate,async(req,res)=>{
 const c=await pool.connect();try{await c.query("BEGIN");const h=await bcrypt.hash(req.body.password,12);
 const r=await c.query("INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email",[req.body.name,req.body.email,h]);
 const u=r.rows[0];await c.query("INSERT INTO agent_trials(agent_id) VALUES($1)",[u.id]);await c.query("COMMIT");
 res.status(201).json({token:tokenFor(u),user:u});}catch(e){await c.query("ROLLBACK");if(e.code==="23505")return res.status(409).json({error:"Email already registered"});res.status(500).json({error:"Signup failed"});}finally{c.release();}
});

app.post("/api/auth/login",[body("email").trim().isEmail().normalizeEmail(),body("password").notEmpty()],validate,async(req,res)=>{
 try{const r=await pool.query("SELECT id,name,email,password_hash FROM users WHERE email=$1",[req.body.email]);const u=r.rows[0];
 if(!u||!(await bcrypt.compare(req.body.password,u.password_hash)))return res.status(401).json({error:"Invalid credentials"});
 res.json({token:tokenFor(u),user:{id:u.id,name:u.name,email:u.email}});}catch{res.status(500).json({error:"Login failed"});}
});

app.get("/api/trial",auth,async(req,res)=>{try{const r=await pool.query("SELECT * FROM agent_trials WHERE agent_id=$1",[req.user.id]);const t=r.rows[0];if(!t)return res.status(404).json({error:"Trial not found"});
 const days=Math.max(0,TRIAL_DAYS-(Date.now()-new Date(t.trial_start_date).getTime())/86400000);
 res.json({active:t.is_active&&days>0&&t.leads_processed_count<TRIAL_LEADS,daysLeft:Math.ceil(days),leadsUsed:t.leads_processed_count,leadsRemaining:Math.max(0,TRIAL_LEADS-t.leads_processed_count),limits:{days:TRIAL_DAYS,leads:TRIAL_LEADS}});
}catch{res.status(500).json({error:"Failed to read trial"});}});

app.get("/api/leads",auth,async(req,res)=>{try{const r=await pool.query("SELECT * FROM leads WHERE agent_id=$1 ORDER BY created_at DESC",[req.user.id]);res.json(r.rows);}catch{res.status(500).json({error:"Failed to fetch leads"});}});

app.post("/api/leads/import",auth,upload.single("file"),async(req,res)=>{
 if(!req.file)return res.status(400).json({error:"CSV file is required"});
 const c=await pool.connect();try{await c.query("BEGIN");const tr=(await c.query("SELECT * FROM agent_trials WHERE agent_id=$1 FOR UPDATE",[req.user.id])).rows[0];
 if(!tr||expired(tr)){await c.query("ROLLBACK");return res.status(403).json({error:"Free trial expired"});}
 const rows=parse(req.file.buffer.toString("utf8"),{columns:true,skip_empty_lines:true,bom:true,relax_column_count:true,trim:true});
 const remain=TRIAL_LEADS-tr.leads_processed_count;let imported=0,duplicates=0,invalid=0;
 for(const row of rows.slice(0,remain)){
  const pick=(...ks)=>{for(const k of ks){const f=Object.keys(row).find(x=>x.trim().toLowerCase()===k);if(f&&String(row[f]).trim())return String(row[f]).trim();}return null;};
  const name=pick("name","full name","prospect","buyer"),phone=pick("phone","mobile","contact"),email=pick("email","email address");
  const location=pick("city","location"),reqt=pick("property","property type","requirement"),budget=pick("budget","budget range"),segment=pick("segment","buyer segment");
  if(!name||(!phone&&!email)){invalid++;continue;}
  const d=await c.query(`SELECT id FROM leads WHERE agent_id=$1 AND (($2 IS NOT NULL AND $2<>'' AND phone=$2) OR ($3 IS NOT NULL AND $3<>'' AND LOWER(email)=LOWER($3))) LIMIT 1`,[req.user.id,phone,email]);
  if(d.rows.length){duplicates++;continue;}
  await c.query(`INSERT INTO leads(agent_id,name,phone,email,location,property_requirement,budget,buyer_segment,source,verification_status)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'Needs Verification')`,
   [req.user.id,name,phone,email,location,reqt,budget,segment,`Authorized CSV: ${req.file.originalname}`]);imported++;
 }
 await c.query("UPDATE agent_trials SET leads_processed_count=leads_processed_count+$1 WHERE agent_id=$2",[imported,req.user.id]);
 await c.query("COMMIT");res.json({success:true,imported,duplicates,invalid,message:`${imported} authorized leads imported.`});
}catch(e){await c.query("ROLLBACK");console.error(e);res.status(400).json({error:"CSV could not be processed safely"});}finally{c.release();}
});

app.patch("/api/leads/:id/status",auth,[body("status").isIn(["New","Qualified","Contacted","Interested","Site Visit","Negotiation","Booked","Converted"]),body("notes").optional().isString().isLength({max:5000})],validate,async(req,res)=>{
 try{const r=await pool.query("UPDATE leads SET lead_status=$1,notes=COALESCE($2,notes) WHERE id=$3 AND agent_id=$4 RETURNING *",[req.body.status,req.body.notes||null,req.params.id,req.user.id]);
 if(!r.rows[0])return res.status(404).json({error:"Lead not found"});await pool.query("INSERT INTO lead_activities(lead_id,agent_id,activity_type,details) VALUES($1,$2,'Status Change',$3)",[req.params.id,req.user.id,`Status changed to ${req.body.status}`]);res.json({success:true,lead:r.rows[0]});
 }catch{res.status(500).json({error:"Status update failed"});}
});

app.post("/api/ai/analyze",auth,[body("leadId").isInt({min:1})],validate,async(req,res)=>{
 if(!process.env.GEMINI_API_KEY)return res.status(503).json({error:"AI provider not connected",message:"GEMINI_API_KEY is not configured on the server."});
 try{const r=await pool.query("SELECT id,name,phone,email,location,property_requirement,budget,buyer_segment,verification_status,lead_status,notes FROM leads WHERE id=$1 AND agent_id=$2",[req.body.leadId,req.user.id]);const lead=r.rows[0];
 if(!lead)return res.status(404).json({error:"Lead not found"});
 const ai=new GoogleGenAI({apiKey:process.env.GEMINI_API_KEY});
 const prompt=`You are AutoLead AI, a real-estate sales copilot. Analyze ONLY the supplied lead data. Never invent facts, contact details, property availability, pricing, intent, or verification. Return JSON with score (0-100), temperature (Hot/Warm/Cold), intent (High/Medium/Low/Unknown), next_best_action, follow_up_timing, whatsapp_message, missing_information (array), verification_note. Lead data: ${JSON.stringify(lead)}`;
 const out=await ai.models.generateContent({model:GEMINI_MODEL,contents:prompt,config:{responseMimeType:"application/json",thinkingConfig:{thinkingLevel:"high"}}});
 let a;try{a=JSON.parse(out.text);}catch{return res.status(502).json({error:"AI returned an invalid structured response"});}
 const score=Number.isInteger(a.score)?Math.max(0,Math.min(100,a.score)):null,temp=["Hot","Warm","Cold"].includes(a.temperature)?a.temperature:null;
 await pool.query("UPDATE leads SET lead_score=$1,lead_temperature=$2 WHERE id=$3 AND agent_id=$4",[score,temp,lead.id,req.user.id]);
 res.json({success:true,model:GEMINI_MODEL,analysis:a});
 }catch(e){console.error(e);res.status(502).json({error:"AI analysis failed",message:"Gemini did not return a usable result."});}
});

const PORT=Number(process.env.PORT)||5000;app.listen(PORT,()=>console.log(`AutoLead AI V4 backend on :${PORT}`));
