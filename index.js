require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const passport = require("passport");
const LocalStratergy = require("passport-local").Strategy;
const flash = require("express-flash");
const session = require("express-session");
const methodOverride = require("method-override");
const mongoose = require("mongoose");
const sendEmail = require("./utils/sendEmail");

mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
});

const db = mongoose.connection;
db.on("error", (error) => console.error(error));
db.once("open", () => console.log("Connected to MongoDB"));

//MIDDLEWARE_____________________
app.use(express.static("views"));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(methodOverride("_method"));

//VAR____________________________

//AUTHENTICATION_________________
const User = require("./models/User"); // Adjust path as needed

function initialize(passport) {
  const authenticateUser = async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email });
      if (!user) {
        return done(null, false, { message: "No user with that email" });
      }

      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Wrong Password" });
      }
    } catch (error) {
      return done(error);
    }
  };

  passport.use(
    new LocalStratergy({ usernameField: "email" }, authenticateUser)
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
}

initialize(passport);

function checkAuth(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}
function checkNotAuth(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

//GET________________________
app.get("/", checkAuth, (req, res) => {
  res.render("home", { user: req.user.name });
});
app.get("/login", checkNotAuth, (req, res) => {
  res.render("login");
});
app.get("/register", checkNotAuth, (req, res) => {
  res.render("register");
});
app.get("/forgot-password", (req, res) => {
  res.render("forgot");
});

//POST________________________
app.post(
  "/login",
  checkNotAuth,
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

app.post("/register", checkNotAuth, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword,
    });
    await user.save();
    res.redirect("/login");
  } catch (error) {
    console.error(error);
    res.redirect("/register");
  }
});

app.post("/forgot-password", (req, res) => {
  try {
    let email = req.body.email;
    // const url = `${process.env.BASE_URL}users/${user.id}/verify/${token.token}`;
    sendEmail(email, "Forgot Password", "url");
    console.log(req.body.email);
    res.redirect("/");
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

//DELETE________________________
app.delete("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
  });
  res.redirect("/login");
});

app.listen(3000);
