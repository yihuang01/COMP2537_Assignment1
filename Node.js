require("dotenv").config();

const express = require("express");
const session = require("express-session");
const { MongoStore } = require("connect-mongo");
const bcrypt = require("bcrypt");
const Joi = require("joi");
const mongoSanitizer = require("mongo-sanitizer").default;
const mongoURI = process.env.mongoURI;

const app = express();

const saltRounds = 10;
const PORT = process.env.PORT || 3000;
const expireTime = 1 * 60 * 60; // 1 hour

// Joi schema for validating user input
const schema = Joi.object({
  name: Joi.string().max(20).required(),
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().max(20).required(),
});

// Load environment variables
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

const { database } = require("./databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(__dirname + "/public"));

app.use(mongoSanitizer({ replaceWith: "_" }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
  }),
);

app.get("/", (req, res) => {
  if (!req.session.authenticated) {
    res.send(`
      <button onclick="location.href='/signup'">Sign up</button>
      <button onclick="location.href='/login'">Log in</button>
    `);
  } else {
    res.send(`
      Hello, ${req.session.name}!
      <br>
      <button onclick="location.href='/members'">Go to Members Area</button>
      <button onclick="location.href='/logout'">Logout</button>
    `);
  }
});

app.get("/signup", (req, res) => {
  res.send(`
    <form action="/signup" method="post">
      <p>Create user</p>
      <div style="display: flex; flex-direction: column; gap: 10px; width: 300px;">
        <input type="text" name="name" placeholder="name" required />
        <input type="text" name="email" placeholder="email" required />
        <input type="password" name="password" placeholder="password" required />
        <button type="submit">Submit</button>
      </div>
    </form>
  `);
});

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name) {
    return res.send(
      `<h1>Error</h1> <p>Name is required.</p> <a href="/signup">Try again</a>`,
    );
  }
  if (!email) {
    return res.send(
      `<h1>Error</h1> <p>Please provide an email address.</p> <a href="/signup">Try again</a>`,
    );
  }
  if (!password) {
    return res.send(
      `<h1>Error</h1> <p>Password is required.</p> <a href="/signup">Try again</a>`,
    );
  }

  const validationResult = schema.validate({ name, email, password });

  if (validationResult.error != null) {
    const message = validationResult.error.details[0].message;
    res.send(
      `<h1>Error </h1> <p> ${message} </p> <a href="/signup">Try again</a>`,
    );
    return;
  }

  const hashedPassword = await bcrypt.hash(password, saltRounds);

  const newUser = {
    name: name,
    email: email,
    password: hashedPassword,
  };

  await userCollection.insertOne(newUser);

  req.session.authenticated = true;
  req.session.name = name;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  res.send(`
    <form action="/login" method="post">
      <p>Login</p>
      <div style="display: flex; flex-direction: column; gap: 10px; width: 300px;">
        <input type="text" name="email" placeholder="email" required />
        <input type="password" name="password" placeholder="password" required />
        <button type="submit">Submit</button>
      </div>
    </form>
  `);
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const validationResult = loginSchema.validate({ email, password });

  if (validationResult.error != null) {
    const message = validationResult.error.details[0].message;
    res.send(
      `<h1>Error </h1> <p> ${message} </p> <a href="/login">Try again</a>`,
    );
    return;
  }

  const user = await userCollection.findOne({ email: email });

  if (user == null) {
    res.send(
      `<h1>Error </h1> <p> Invalid email/password combination </p> <a href="/login">Try again</a>`,
    );
    return;
  }

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (passwordMatch) {
    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.cookie.maxAge = expireTime;
    res.redirect("/members");
  } else {
    console.log("Password does not match");
    res.send(
      `<h1>Error </h1> <p> Invalid email/password combination </p> <a href="/login">Try again</a>`,
    );
  }
});

app.get("/members", (req, res) => {
  if (!req.session.authenticated) {
    res.redirect("/login");
    return;
  }

  // Logic to pick a random image between 1 and 3
  const imageNumber = Math.floor(Math.random() * 3) + 1;
  const imageName = "img" + imageNumber + ".jpg";

  res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src='/${imageName}' style='width:300px;'>
        <br>
        <a href="/logout"><button>Sign out</button></a>
    `);
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.use((req, res) => {
  res.status(404).send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
