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
    const results = await db.query("SELECT * FROM bookslist");
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
    const booklist = await db.query("SELECT * FROM bookslist WHERE id = $1", [
      id,
    ]);

    const review = await db.query(
      "SELECT * FROM reviews WHERE bookslist_id = $1",
      [id]
    );

    const averageRating = await db.query(
      "SELECT Avg(rating) FROM reviews WHERE bookslist_id = $1;",
      [id]
    );

    res.status(200).json({
      status: "success",
      data: {
        bookslist: booklist.rows[0],
        review: review.rows,
        averageRating: averageRating.rows[0],
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
    const { email } = req.query;

    const results = await db.query(
      "SELECT username FROM users WHERE email = $1",
      [email]
    );

    if (results.rows.length > 0) {
      res.status(200).json({
        status: "success",
        username: results.rows[0].username,
      });
    } else {
      res.status(404).json({
        status: "error",
        message: "User not found",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      status: "error",
      message: "Internal server error",
    });
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

//Get review from a user
app.get("/review/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const results = await db.query(
      "SELECT reviews.id, review, rating, bookslist_id, created_at, book_title, author, year, img_link FROM reviews INNER JOIN bookslist ON reviews.bookslist_id = bookslist.id WHERE user_username = $1",
      [id]
    );
    res.status(200).json({
      status: "success",
      results: results.rows.length,
      data: {
        review: results.rows,
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//Get reivew base on id (reviews itself)
app.get("/revieweditdata/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // const results = await db.query("SELECT * FROM reviews WHERE id = $1", [id]);
    const results = await db.query(
      "SELECT reviews.id, review, rating, created_at, book_title, author, year, img_link FROM reviews INNER JOIN bookslist ON reviews.bookslist_id = bookslist.id WHERE reviews.id = $1",
      [id]
    );
    res.status(200).json({
      status: "success",
      results: results.rows.length,
      data: {
        review: results.rows[0],
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//Add a review
app.post("/addBookReview/:id", async (req, res) => {
  try {
    const { user_username, review, rating } = req.body;
    const results = await db.query(
      "INSERT INTO reviews (bookslist_id, user_username, review, rating) VALUES ($1, $2, $3, $4) returning *",
      [req.params.id, user_username, review, rating]
    );
    res.status(201).json({
      status: "success",
      data: {
        review: results.rows[0],
      },
    });
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ message: err.message });
  }
});

//edit review
app.put("/alterreview/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { review, rating } = req.body;
    const results = await db.query(
      "UPDATE reviews SET review = $1, rating = $2 WHERE id = $3 RETURNING *",
      [review, rating, id]
    );
    res.status(200).json({
      status: "success",
      data: {
        review: results.rows[0],
      },
    });
  } catch (err) {
    console.error(err.message);
  }
});

//Delete review
app.delete("/deletereview/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const results = await db.query("DELETE FROM reviews WHERE id = $1", [id]);
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
