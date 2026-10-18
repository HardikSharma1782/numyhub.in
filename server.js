const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET || "change-this-secret-in-production";

const db = new sqlite3.Database("./auth.db", (err) => {
  if (err) {
    console.error("Could not open database:", err.message);
  } else {
    console.log("SQLite database connected.");
  }
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

db.run(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
  `,
  (err) => {
    if (err) {
      console.error("Database error:", err.message);
    } else {
      console.log("Database ready.");
    }
  }
);

/* =========================
   AUTH SUCCESS RESPONSE
========================= */

function authSuccess(res, status, message) {
  return res.status(status).json({
    success: true,
    message,
    redirect: "/home.html"
  });
}

/* =========================
   SIGN UP
========================= */

app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        success: false,
        message: "Please fill in every field."
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2) {
      return res.status(400).json({
        success: false,
        message: "Name must contain at least 2 characters."
      });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email address."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    db.get(
      "SELECT id FROM users WHERE email = ?",
      [cleanEmail],
      async (err, existingUser) => {
        if (err) {
          console.error(err);

          return res.status(500).json({
            success: false,
            message: "Database error."
          });
        }

        if (existingUser) {
          return res.status(409).json({
            success: false,
            message: "An account with this email already exists."
          });
        }

        try {
          const hashedPassword = await bcrypt.hash(password, 12);

          db.run(
            `
            INSERT INTO users
            (name, email, password)
            VALUES (?, ?, ?)
            `,
            [cleanName, cleanEmail, hashedPassword],
            function (insertError) {
              if (insertError) {
                console.error(insertError);

                return res.status(500).json({
                  success: false,
                  message: "Could not create account."
                });
              }

              // Log in the new user
              req.session.userId = this.lastID;

              // Redirect frontend to home.html
              return authSuccess(
                res,
                201,
                "Account created successfully."
              );
            }
          );
        } catch (hashError) {
          console.error(hashError);

          return res.status(500).json({
            success: false,
            message: "Could not secure the password."
          });
        }
      }
    );
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Something went wrong."
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    !email ||
    !password
  ) {
    return res.status(400).json({
      success: false,
      message: "Email and password are required."
    });
  }

  const cleanEmail = email.trim().toLowerCase();

  db.get(
    "SELECT * FROM users WHERE email = ?",
    [cleanEmail],
    async (err, user) => {
      if (err) {
        console.error(err);

        return res.status(500).json({
          success: false,
          message: "Database error."
        });
      }

      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Invalid email or password."
        });
      }

      try {
        const passwordCorrect = await bcrypt.compare(
          password,
          user.password
        );

        if (!passwordCorrect) {
          return res.status(401).json({
            success: false,
            message: "Invalid email or password."
          });
        }

        // Store the logged-in user's ID in the session
        req.session.userId = user.id;

        // Redirect frontend to home.html
        return authSuccess(res, 200, "Login successful.");
      } catch (compareError) {
        console.error(compareError);

        return res.status(500).json({
          success: false,
          message: "Could not verify password."
        });
      }
    }
  );
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      success: false,
      message: "Not authenticated."
    });
  }

  db.get(
    `
    SELECT
      id,
      name,
      email,
      created_at
    FROM users
    WHERE id = ?
    `,
    [req.session.userId],
    (err, user) => {
      if (err || !user) {
        return res.status(401).json({
          success: false,
          message: "User not found."
        });
      }

      return res.json({
        success: true,
        user
      });
    }
  );
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Could not log out."
      });
    }

    res.clearCookie("connect.sid");

    return res.json({
      success: true,
      message: "Logged out successfully."
    });
  });
});

/* =========================
   PROTECTED HOME PAGE
========================= */

app.get("/home.html", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  return res.sendFile(
    path.join(__dirname, "public", "home.html")
  );
});

/* Optional dashboard alias */

app.get("/dashboard", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  return res.redirect("/home.html");
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
  console.log("");
  console.log("================================");
  console.log(" NOVA AUTH SERVER");
  console.log("================================");
  console.log(` http://localhost:${PORT}`);
  console.log("================================");
  console.log("");
});