const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const crypto = require("crypto");
const { parse } = require("csv-parse/sync");
const { body, validationResult } = require("express-validator");
const { Pool } = require("pg");
const { GoogleGenAI } = require("@google/genai");
const { Resend } = require("resend");
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
});

const JWT_SECRET = process.env.JWT_SECRET;
const GEMINI_MODEL =
  process.env.GEMINI_MODEL || "gemini-3-flash-preview";

const TRIAL_DAYS = Number(process.env.TRIAL_DAYS) || 7;
const TRIAL_LEADS = Number(process.env.TRIAL_LEADS) || 10;

if (!JWT_SECRET) {
  console.error("FATAL: JWT_SECRET missing");
  process.exit(1);
}

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
   DATABASE INITIALIZATION
========================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_trials (
      agent_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      trial_start_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      leads_processed_count INTEGER NOT NULL DEFAULT 0
        CHECK (leads_processed_count >= 0),
      is_active BOOLEAN NOT NULL DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS leads (
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
      verification_status VARCHAR(30)
        NOT NULL DEFAULT 'Needs Verification',
      last_verified_date DATE,
      lead_score INTEGER
        CHECK (lead_score IS NULL OR lead_score BETWEEN 0 AND 100),
      lead_temperature VARCHAR(10),
      lead_status VARCHAR(30) NOT NULL DEFAULT 'New',
      notes TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_leads_agent_created
      ON leads(agent_id, created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_leads_agent_status
      ON leads(agent_id, lead_status);

    CREATE TABLE IF NOT EXISTS lead_activities (
      id BIGSERIAL PRIMARY KEY,
      lead_id BIGINT NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
      agent_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      activity_type VARCHAR(50) NOT NULL,
      details TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token_hash VARCHAR(64) NOT NULL UNIQUE,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_password_reset_user
      ON password_reset_tokens(user_id);

    CREATE INDEX IF NOT EXISTS idx_password_reset_expiry
      ON password_reset_tokens(expires_at);
  `);

  console.log("Database initialized successfully");
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
      email: Boolean(process.env.RESEND_API_KEY),
      model: GEMINI_MODEL,
    });
  } catch {
    res.status(503).json({
      status: "unhealthy",
      database: "disconnected",
      ai: Boolean(process.env.GEMINI_API_KEY),
      email: Boolean(process.env.RESEND_API_KEY),
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
        INSERT INTO users
          (name, email, password_hash)
        VALUES
          ($1, $2, $3)
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
        INSERT INTO agent_trials (agent_id)
        VALUES ($1)
        `,
        [user.id]
      );

      await client.query("COMMIT");

      res.status(201).json({
        token: tokenFor(user),
        user,
      });
    } catch (error) {
      await client.query("ROLLBACK");

      if (error.code === "23505") {
        return res.status(409).json({
          error: "Email already registered",
        });
      }

      console.error("SIGNUP ERROR:", error);

      res.status(500).json({
        error: "Signup failed",
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

    body("password")
      .notEmpty(),
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
    } catch (error) {
      console.error("LOGIN ERROR:", error);

      res.status(500).json({
        error: "Login failed",
      });
    }
  }
);

/* =========================
   FORGOT PASSWORD
========================= */

app.post(
  "/api/auth/forgot-password",
  [
    body("email")
      .trim()
      .isEmail()
      .normalizeEmail(),
  ],
  validate,
  async (req, res) => {
    const genericResponse = {
      message:
        "If an account exists for this email, a password reset link has been sent.",
    };

    try {
      const result = await pool.query(
        `
        SELECT id, email, name
        FROM users
        WHERE email = $1
        `,
        [req.body.email]
      );

      const user = result.rows[0];

      /*
       Never reveal whether an email exists.
      */
      if (!user) {
        return res.json(genericResponse);
      }

      /*
       Invalidate previous unused reset tokens
       for this user.
      */
      await pool.query(
        `
        UPDATE password_reset_tokens
        SET used_at = NOW()
        WHERE user_id = $1
          AND used_at IS NULL
        `,
        [user.id]
      );

      /*
       Generate a cryptographically secure token.
      */
      const rawToken = crypto.randomBytes(32).toString("hex");

      const tokenHash = crypto
        .createHash("sha256")
        .update(rawToken)
        .digest("hex");

      /*
       Token valid for 30 minutes.
      */
      const expiresAt = new Date(
        Date.now() + 30 * 60 * 1000
      );

      await pool.query(
        `
        INSERT INTO password_reset_tokens
          (user_id, token_hash, expires_at)
        VALUES
          ($1, $2, $3)
        `,
        [
          user.id,
          tokenHash,
          expiresAt,
        ]
      );

      const frontendUrl =
        process.env.FRONTEND_URL ||
        process.env.FRONTEND_ORIGIN;

      if (!frontendUrl) {
        console.error(
          "FRONTEND_URL is not configured"
        );

        return res.status(503).json({
          error:
            "Password reset email service is not configured",
        });
      }

      const resetUrl =
        `${frontendUrl.replace(/\/$/, "")}` +
        `/?reset_token=${encodeURIComponent(rawToken)}`;

      /*
       Do not silently pretend an email was sent
       if email configuration is missing.
      */
      if (!process.env.RESEND_API_KEY) {
        console.error(
          "RESEND_API_KEY is not configured"
        );

        return res.status(503).json({
          error:
            "Password reset email service is not configured",
        });
      }

      if (!process.env.MAIL_FROM) {
        console.error(
          "MAIL_FROM is not configured"
        );

        return res.status(503).json({
          error:
            "Password reset email sender is not configured",
        });
      }

      const resend = new Resend(
        process.env.RESEND_API_KEY
      );

      const emailResult = await resend.emails.send({
        from: process.env.MAIL_FROM,
        to: [user.email],
        subject: "Reset your AutoLead AI password",
        html: `
          <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto">
            <h2>AutoLead AI</h2>

            <p>Hello ${String(user.name)
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")},</p>

            <p>
              We received a request to reset your
              AutoLead AI password.
            </p>

            <p>
              <a
                href="${resetUrl}"
                style="
                  display:inline-block;
                  background:#2563eb;
                  color:white;
                  padding:12px 18px;
                  border-radius:8px;
                  text-decoration:none;
                  font-weight:bold
                "
              >
                Reset Password
              </a>
            </p>

            <p>
              This link will expire in 30 minutes
              and can only be used once.
            </p>

            <p>
              If you did not request this, you can
              safely ignore this email.
            </p>

            <p>
              AutoLead AI
            </p>
          </div>
        `,
      });

      if (emailResult?.error) {
        console.error(
          "PASSWORD RESET EMAIL ERROR:",
          emailResult.error
        );

        return res.status(502).json({
          error:
            "Password reset email could not be sent",
        });
      }

      console.log(
        "Password reset email sent:",
        user.email
      );

      return res.json(genericResponse);
    } catch (error) {
      console.error(
        "FORGOT PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Password reset request failed",
      });
    }
  }
);

/* =========================
   RESET PASSWORD
========================= */

app.post(
  "/api/auth/reset-password",
  [
    body("token")
      .isString()
      .isLength({ min: 64, max: 64 }),

    body("password")
      .isLength({ min: 8, max: 128 }),
  ],
  validate,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const tokenHash = crypto
        .createHash("sha256")
        .update(req.body.token)
        .digest("hex");

      await client.query("BEGIN");

      const result = await client.query(
        `
        SELECT
          id,
          user_id,
          expires_at
        FROM password_reset_tokens
        WHERE token_hash = $1
          AND used_at IS NULL
        FOR UPDATE
        `,
        [tokenHash]
      );

      const resetToken = result.rows[0];

      if (!resetToken) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "Invalid or already used reset link",
        });
      }

      if (
        new Date(resetToken.expires_at).getTime() <=
        Date.now()
      ) {
        await client.query("ROLLBACK");

        return res.status(400).json({
          error:
            "This reset link has expired",
        });
      }

      const passwordHash = await bcrypt.hash(
        req.body.password,
        12
      );

      await client.query(
        `
        UPDATE users
        SET password_hash = $1
        WHERE id = $2
        `,
        [
          passwordHash,
          resetToken.user_id,
        ]
      );

      /*
       Mark token as used immediately.
      */
      await client.query(
        `
        UPDATE password_reset_tokens
        SET used_at = NOW()
        WHERE id = $1
        `,
        [resetToken.id]
      );

      /*
       Invalidate any other unused tokens
       belonging to the same user.
      */
      await client.query(
        `
        UPDATE password_reset_tokens
        SET used_at = NOW()
        WHERE user_id = $1
          AND used_at IS NULL
        `,
        [resetToken.user_id]
      );

      await client.query("COMMIT");

      res.json({
        success: true,
        message:
          "Password updated successfully. You can now log in.",
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(
        "RESET PASSWORD ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Password could not be reset",
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   TRIAL
========================= */

app.get(
  "/api/trial",
  auth,
  async (req, res) => {
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
    } catch {
      res.status(500).json({
        error: "Failed to read trial",
      });
    }
  }
);

/* =========================
   LEADS
========================= */

app.get(
  "/api/leads",
  auth,
  async (req, res) => {
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
    } catch {
      res.status(500).json({
        error: "Failed to fetch leads",
      });
    }
  }
);

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

      for (
        const row of rows.slice(0, remaining)
      ) {
        const pick = (...keys) => {
          for (const key of keys) {
            const field = Object.keys(row).find(
              (x) =>
                x.trim().toLowerCase() ===
                key
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

        if (!name || (!phone && !email)) {
          invalid++;
          continue;
        }

        const duplicate =
          await client.query(
            `
            SELECT id
            FROM leads
            WHERE 
