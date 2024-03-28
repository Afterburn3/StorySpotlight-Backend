import "dotenv/config";
import express from "express";
import cors from "cors";
import * as db from "./db/index.js";
import { check, validationResult } from "express-validator";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import passport from "passport";
import { Strategy } from "passport-jwt";

const CLIENT_URL = process.env.CLIENT_URL;
const SECRET = process.env.SECRET;

const app = express();
const port = 4000;

app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: CLIENT_URL, credentials: true }));
app.use(passport.initialize());

//checking password, email and username with express-validator
const password = check("password")
  .isLength({ min: 6, max: 15 })
  .withMessage("Passsword has to be between 6 and 15 characters");

const email = check("email")
  .isEmail()
  .withMessage("Please provide a valid email");

const emailExists = check("email").custom(async (value) => {
  const { rows } = await db.query("SELECT * from users WHERE email = $1", [
    value,
  ]);
  if (rows.length) {
    throw new Error("Email already exists.");
  }
});

const usernameExists = check("username").custom(async (value) => {
  const { rows } = await db.query("SELECT * from users WHERE username = $1", [
    value,
  ]);
  if (rows.length) {
    throw new Error("Username already exists.");
  }
});

const regiserValidation = [password, email, emailExists, usernameExists];

//login validation check
const loginFieldsCheck = check("email").custom(async (value, { req }) => {
  const user = await db.query("SELECT * from users WHERE email = $1", [value]);
  if (!user.rows.length) {
    throw new Error("Email does not exists");
  }
  //password check
  const validPassword = await bcrypt.compare(
    req.body.password,
    user.rows[0].password
  );

  if (!validPassword) {
    throw new Error("Wrong password");
  }

  req.user = user.rows[0];
});

//custom function for validationMiddleware
function validationMiddleware(req, res, next) {
  let errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({
      errors: errors.array(),
    });
  }

  next();
}

//custum function if the user send cookie back after successful login
const cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) token = req.cookies["token"];
  return token;
};

const opts = {
  secretOrKey: SECRET,
  jwtFromRequest: cookieExtractor,
};

passport.use(
  new Strategy(opts, async ({ id }, done) => {
    try {
      const { rows } = await db.query(
        "SELECT user_id, email, username FROM users WHERE user_id = $1",
        [id]
      );

      if (!rows.length) {
        throw new Error("401 not authorized");
      }
      let user = {
        id: rows[0].user_id,
        email: rows[0].email,
        username: rows[0].username,
      };
      return await done(null, user);
    } catch (error) {
      console.error(error.message);
      done(null, false);
    }
  })
);

const userAuth = passport.authenticate("jwt", { session: false });

//Get all Book
app.get("/allBooks", async (req, res) => {
  try {
    const results = await db.query("select * FROM bookslist");
    res.status(200).json({
      status: "success",
      results: results.rows.length,
      data: {
        bookslist: results.rows,
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//GET individual books
app.get("/allBooks/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const results = await db.query("SELECT * FROM bookslist WHERE id = $1", [
      id,
    ]);
    res.status(200).json({
      status: "success",
      results: results.rows.length,
      data: {
        bookslist: results.rows[0],
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//POST create book
app.post("/allBooks", async (req, res) => {
  try {
    const {
      book_title,
      author,
      book_id,
      year,
      book_snippet,
      img_link,
      categories,
      book_description,
    } = req.body;
    const results = await db.query(
      "INSERT INTO bookslist (book_title, author, book_id, year, book_snippet, img_link, categories, book_description) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
      [
        book_title,
        author,
        book_id,
        year,
        book_snippet,
        img_link,
        categories,
        book_description,
      ]
    );
    res.status(201).json({
      status: "success",
      results: results.rows.length,
      data: {
        bookslist: results.rows[0],
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//User Authentication, Email and Password
//Get all user name and email
app.get("/getuser", async (req, res) => {
  try {
    const results = await db.query(
      "select user_id, username, email FROM users"
    );
    res.status(200).json({
      status: "success",

      users: results.rows,
    });
  } catch (error) {
    console.log(error);
  }
});

//Register, POST also included validation and hash password from bcrypted
app.post(
  "/register",
  regiserValidation,
  validationMiddleware,
  async (req, res) => {
    const { email, password, username } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query(
        "INSERT INTO users (email, password, username) VALUES ($1, $2, $3)",
        [email, hashedPassword, username]
      );

      res.status(200).json({ message: "Registration successful!" });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

//Login, check
app.post("/login", loginFieldsCheck, validationMiddleware, async (req, res) => {
  let user = req.user;
  let payload = {
    id: user.user_id,
    email: user.email,
    username: user.username,
  };
  try {
    const token = await jwt.sign(payload, SECRET);
    res
      .status(200)
      .cookie("token", token, { httpOnly: true })
      .json({ status: "success", message: "Logged in successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

//Protected route
app.get("/protected", userAuth, async (req, res) => {
  try {
    res.status(200).json({ info: " protected info" });
  } catch (error) {}
});

//Logout route
app.get("/logout", async (req, res) => {
  try {
    res
      .status(200)
      .clearCookie("token", { httpOnly: true })
      .json({ status: "success", message: "Logged out successfully" });
  } catch (error) {
    console.error(error);
  }
});

//Edit book
//Need to change this to edit review
app.put("/allBooks/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      book_title,
      author,
      book_id,
      year,
      book_snippet,
      img_link,
      categories,
      book_description,
    } = req.body;
    const results = await db.query(
      "UPDATE bookslist SET book_title = $1, author  = $2, book_id  = $3, year = $4, book_snippet  = $5, img_link, categories = $7, book_description = $8 WHERE id = $6 RETURNING *",
      [
        book_title,
        author,
        book_id,
        year,
        book_snippet,
        img_link,
        id,
        categories,
        book_description,
      ]
    );
    res.status(200).json({
      status: "success",
      data: {
        bookslist: results.rows[0],
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//Delete book
//Need to change this to delete review
app.delete("/allBooks/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const results = await db.query("DELETE FROM bookslist WHERE id = $1", [id]);
    res.status(200).json({
      status: "success",
    });
  } catch (err) {
    console.error(err.message);
  }
});

app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});
