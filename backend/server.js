const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { parse } = require("csv-parse/sync");
const { body, validationResult } = require("express-validator");
const { Pool } = require("pg");
const { GoogleGenAI } = require("@google/genai");
require("dotenv").config();

const app = express();

app.set("trust proxy", 1);
app.use(helmet());

app.use(
  cors({
    origin: process.env.FRONTEND_ORIGIN
      ? process.env.FRONTEND_ORIGIN.split(",").map((x) => x.trim())
      : true,
  })
);

app.use(express.json({ limit: "1mb" }));

app.use(
  "/api/",
  rateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
    limit: Number(process.env.RATE_LIMIT_MAX) || 100,
    standardHeaders: "draft-8",
    legacyHeaders: false,
  })
);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024,
    files: 1,
  },
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes("render.com")
    ? { rejectUnauthorized: false }
    : undefined,
});

const JWT_SECRET = process.env.JWT_SECRET;

const GEMINI_MODEL =
  process.env.GEMINI_MODEL || "gemini-3-flash-preview";

const TRIAL_DAYS =
  Number(process.env.TRIAL_DAYS) || 7;

const TRIAL_LEADS =
  Number(process.env.TRIAL_LEADS) || 10;

if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET missing");
  process.exit(1);
}

/* =========================
   DATABASE INITIALIZATION
========================= */

async function initializeDatabase() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id BIGSERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(254) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS agent_trials (
        agent_id BIGINT PRIMARY KEY
          REFERENCES users(id) ON DELETE CASCADE,
        trial_start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        leads_processed_count INTEGER NOT NULL DEFAULT 0
          CHECK (leads_processed_count >= 0),
        is_active BOOLEAN NOT NULL DEFAULT TRUE
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS leads (
        id BIGSERIAL PRIMARY KEY,
        agent_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE CASCADE,
        name VARCHAR(150) NOT NULL,
        phone VARCHAR(30),
        email VARCHAR(254),
        location VARCHAR(150),
        property_requirement VARCHAR(200),
        budget VARCHAR(100),
        buyer_segment VARCHAR(100),
        source VARCHAR(150) NOT NULL,
        verification_status VARCHAR(30)
          NOT NULL DEFAULT 'Needs Verification',
        last_verified_date DATE,
        lead_score INTEGER
          CHECK (
            lead_score IS NULL
            OR lead_score BETWEEN 0 AND 100
          ),
        lead_temperature VARCHAR(10),
        lead_status VARCHAR(30)
          NOT NULL DEFAULT 'New',
        notes TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_leads_agent_created
      ON leads(agent_id, created_at DESC);
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_leads_agent_status
      ON leads(agent_id, lead_status);
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS lead_activities (
        id BIGSERIAL PRIMARY KEY,
        lead_id BIGINT NOT NULL
          REFERENCES leads(id) ON DELETE CASCADE,
        agent_id BIGINT NOT NULL
          REFERENCES users(id) ON DELETE CASCADE,
        activity_type VARCHAR(50) NOT NULL,
        details TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await client.query("COMMIT");

    console.log("Database tables initialized successfully.");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("DATABASE INITIALIZATION ERROR:", e);
    throw e;
  } finally {
    client.release();
  }
}

/* =========================
   HELPERS
========================= */

function validate(req, res, next) {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: "Validation failed",
      details: errors.array(),
    });
  }

  next();
}

function tokenFor(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

function auth(req, res, next) {
  const [scheme, token] = String(
    req.headers.authorization || ""
  ).split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({
      error: "Authentication required",
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

function expired(trial) {
  return (
    !trial.is_active ||
    Date.now() -
      new Date(trial.trial_start_date).getTime() >=
      TRIAL_DAYS * 86400000 ||
    trial.leads_processed_count >= TRIAL_LEADS
  );
}

/* =========================
   HEALTH
========================= */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      status: "healthy",
      database: "connected",
      ai: Boolean(process.env.GEMINI_API_KEY),
      model: GEMINI_MODEL,
    });
  } catch (e) {
    console.error("HEALTH ERROR:", e);

    res.status(503).json({
      status: "unhealthy",
      database: "disconnected",
      ai: Boolean(process.env.GEMINI_API_KEY),
      details: e.message,
      code: e.code,
    });
  }
});

/* =========================
   SIGNUP
========================= */

app.post(
  "/api/auth/signup",
  [
    body("name")
      .trim()
      .isLength({ min: 2, max: 100 }),

    body("email")
      .trim()
      .isEmail()
      .normalizeEmail(),

    body("password")
      .isLength({ min: 8, max: 128 }),
  ],
  validate,
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const passwordHash = await bcrypt.hash(
        req.body.password,
        12
      );

      const result = await client.query(
        `
        INSERT INTO users(
          name,
          email,
          password_hash
        )
        VALUES($1, $2, $3)
        RETURNING id, name, email
        `,
        [
          req.body.name,
          req.body.email,
          passwordHash,
        ]
      );

      const user = result.rows[0];

      await client.query(
        `
        INSERT INTO agent_trials(agent_id)
        VALUES($1)
        `,
        [user.id]
      );

      await client.query("COMMIT");

      res.status(201).json({
        token: tokenFor(user),
        user,
      });
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error("SIGNUP ERROR:", e);

      if (e.code === "23505") {
        return res.status(409).json({
          error: "Email already registered",
        });
      }

      res.status(500).json({
        error: "Signup failed",
        details: e.message,
        code: e.code,
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/auth/login",
  [
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail(),

    body("password").notEmpty(),
  ],
  validate,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT
          id,
          name,
          email,
          password_hash
        FROM users
        WHERE email = $1
        `,
        [req.body.email]
      );

      const user = result.rows[0];

      if (
        !user ||
        !(await bcrypt.compare(
          req.body.password,
          user.password_hash
        ))
      ) {
        return res.status(401).json({
          error: "Invalid credentials",
        });
      }

      res.json({
        token: tokenFor(user),
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      });
    } catch (e) {
      console.error("LOGIN ERROR:", e);

      res.status(500).json({
        error: "Login failed",
        details: e.message,
        code: e.code,
      });
    }
  }
);

/* =========================
   TRIAL
========================= */

app.get("/api/trial", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM agent_trials
      WHERE agent_id = $1
      `,
      [req.user.id]
    );

    const trial = result.rows[0];

    if (!trial) {
      return res.status(404).json({
        error: "Trial not found",
      });
    }

    const days = Math.max(
      0,
      TRIAL_DAYS -
        (Date.now() -
          new Date(
            trial.trial_start_date
          ).getTime()) /
          86400000
    );

    res.json({
      active:
        trial.is_active &&
        days > 0 &&
        trial.leads_processed_count <
          TRIAL_LEADS,

      daysLeft: Math.ceil(days),

      leadsUsed:
        trial.leads_processed_count,

      leadsRemaining: Math.max(
        0,
        TRIAL_LEADS -
          trial.leads_processed_count
      ),

      limits: {
        days: TRIAL_DAYS,
        leads: TRIAL_LEADS,
      },
    });
  } catch (e) {
    console.error("TRIAL ERROR:", e);

    res.status(500).json({
      error: "Trial fetch failed",
      details: e.message,
      code: e.code,
    });
  }
});

/* =========================
   GET LEADS
========================= */

app.get("/api/leads", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `
      SELECT *
      FROM leads
      WHERE agent_id = $1
      ORDER BY created_at DESC
      `,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (e) {
    console.error("LEADS ERROR:", e);

    res.status(500).json({
      error: "Failed to fetch leads",
      details: e.message,
      code: e.code,
    });
  }
});

/* =========================
   CSV IMPORT
========================= */

app.post(
  "/api/leads/import",
  auth,
  upload.single("file"),
  async (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: "CSV file is required",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const trialResult =
        await client.query(
          `
          SELECT *
          FROM agent_trials
          WHERE agent_id = $1
          FOR UPDATE
          `,
          [req.user.id]
        );

      const trial = trialResult.rows[0];

      if (!trial || expired(trial)) {
        await client.query("ROLLBACK");

        return res.status(403).json({
          error: "Free trial expired",
        });
      }

      const rows = parse(
        req.file.buffer.toString("utf8"),
        {
          columns: true,
          skip_empty_lines: true,
          bom: true,
          relax_column_count: true,
          trim: true,
        }
      );

      const remaining =
        TRIAL_LEADS -
        trial.leads_processed_count;

      let imported = 0;
      let duplicates = 0;
      let invalid = 0;

      for (const row of rows.slice(
        0,
        remaining
      )) {
        const pick = (...keys) => {
          for (const key of keys) {
            const field = Object.keys(row).find(
              (x) =>
                x.trim().toLowerCase() === key
            );

            if (
              field &&
              String(row[field]).trim()
            ) {
              return String(
                row[field]
              ).trim();
            }
          }

          return null;
        };

        const name = pick(
          "name",
          "full name",
          "prospect",
          "buyer"
        );

        const phone = pick(
          "phone",
          "mobile",
          "contact"
        );

        const email = pick(
          "email",
          "email address"
        );

        const location = pick(
          "city",
          "location"
        );

        const requirement = pick(
          "property",
          "property type",
          "requirement"
        );

        const budget = pick(
          "budget",
          "budget range"
        );

        const segment = pick(
          "segment",
          "buyer segment"
        );

        if (
          !name ||
          (!phone && !email)
        ) {
          invalid++;
          continue;
        }

        const duplicateResult =
          await client.query(
            `
            SELECT id
            FROM leads
            WHERE agent_id = $1
            AND (
              (
                $2 IS NOT NULL
                AND $2 <> ''
                AND phone = $2
              )
              OR
              (
                $3 IS NOT NULL
                AND $3 <> ''
                AND LOWER(email) =
                    LOWER($3)
              )
            )
            LIMIT 1
            `,
            [
              req.user.id,
              phone,
              email,
            ]
          );

        if (duplicateResult.rows.length) {
          duplicates++;
          continue;
        }

        await client.query(
          `
          INSERT INTO leads(
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
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            'Needs Verification'
          )
          `,
          [
            req.user.id,
            name,
            phone,
            email,
            location,
            requirement,
            budget,
            segment,
            `Authorized CSV: ${req.file.originalname}`,
          ]
        );

        imported++;
      }

      await client.query(
        `
        UPDATE agent_trials
        SET leads_processed_count =
          leads_processed_count + $1
        WHERE agent_id = $2
        `,
        [
          imported,
          req.user.id,
        ]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        imported,
        duplicates,
        invalid,
        message:
          `${imported} authorized leads imported.`,
      });
    } catch (e) {
      try {
        await client.query("ROLLBACK");
      } catch {}

      console.error("CSV ERROR:", e);

      res.status(400).json({
        error:
          "CSV could not be processed safely",
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   LEAD STATUS
========================= */

app.patch(
  "/api/leads/:id/status",
  auth,
  [
    body("status").isIn([
      "New",
      "Qualified",
      "Contacted",
      "Interested",
      "Site Visit",
      "Negotiation",
      "Booked",
      "Converted",
    ]),

    body("notes")
      .optional()
      .isString()
      .isLength({ max: 5000 }),
  ],
  validate,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        UPDATE leads
        SET
          lead_status = $1,
          notes = COALESCE($2, notes)
        WHERE id = $3
        AND agent_id = $4
        RETURNING *
        `,
        [
          req.body.status,
          req.body.notes || null,
          req.params.id,
          req.user.id,
        ]
      );

      if (!result.rows[0]) {
        return res.status(404).json({
          error: "Lead not found",
        });
      }

      await pool.query(
        `
        INSERT INTO lead_activities(
          lead_id,
          agent_id,
          activity_type,
          details
        )
        VALUES(
          $1,
          $2,
          'Status Change',
          $3
        )
        `,
        [
          req.params.id,
          req.user.id,
          `Status changed to ${req.body.status}`,
        ]
      );

      res.json({
        success: true,
        lead: result.rows[0],
      });
    } catch (e) {
      console.error("STATUS ERROR:", e);

      res.status(500).json({
        error: "Status update failed",
        details: e.message,
        code: e.code,
      });
    }
  }
);

/* =========================
   GEMINI AI
========================= */

app.post(
  "/api/ai/analyze",
  auth,
  [
    body("leadId").isInt({
      min: 1,
    }),
  ],
  validate,
  async (req, res) => {
    if (!process.env.GEMINI_API_KEY) {
      return res.status(503).json({
        error:
          "AI provider not connected",
        message:
          "GEMINI_API_KEY is not configured on the server.",
      });
    }

    try {
      const result = await pool.query(
        `
        SELECT
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
        WHERE id = $1
        AND agent_id = $2
        `,
        [
          req.body.leadId,
          req.user.id,
        ]
      );

      const lead = result.rows[0];

      if (!lead) {
        return res.status(404).json({
          error: "Lead not found",
        });
      }

      const ai = new GoogleGenAI({
        apiKey:
          process.env.GEMINI_API_KEY,
      });

      const prompt = `
You are AutoLead AI, a real-estate sales copilot.

Analyze ONLY the supplied lead data.

Never invent facts, contact details,
property availability, pricing, intent,
or verification.

Return JSON with:
score (0-100),
temperature (Hot/Warm/Cold),
intent (High/Medium/Low/Unknown),
next_best_action,
follow_up_timing,
whatsapp_message,
missing_information (array),
verification_note.

Lead data:
${JSON.stringify(lead)}
`;

      const output =
        await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            responseMimeType:
              "application/json",

            thinkingConfig: {
              thinkingLevel: "high",
            },
          },
        });

      let analysis;

      try {
        analysis = JSON.parse(
          output.text
        );
      } catch {
        return res.status(502).json({
          error:
            "AI returned an invalid structured response",
        });
      }

      const score =
        Number.isInteger(analysis.score)
          ? Math.max(
              0,
              Math.min(
                100,
                analysis.score
              )
            )
          : null;

      const temperature = [
        "Hot",
        "Warm",
        "Cold",
      ].includes(
        analysis.temperature
      )
        ? analysis.temperature
        : null;

      await pool.query(
        `
        UPDATE leads
        SET
          lead_score = $1,
          lead_temperature = $2
        WHERE id = $3
        AND agent_id = $4
        `,
        [
          score,
          temperature,
          lead.id,
          req.user.id,
        ]
      );

      res.json({
        success: true,
        model: GEMINI_MODEL,
        analysis,
      });
    } catch (e) {
      console.error("AI ERROR:", e);

      res.status(502).json({
        error: "AI analysis failed",
        message:
          "Gemini did not return a usable result.",
      });
    }
  }
);

/* ===================
