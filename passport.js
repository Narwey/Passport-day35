const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Initialize session middleware
app.use(
  session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false,
  })
);

// Server Variable Structure
const users = [
  {
    id: 1,
    username: 'bo9al',
    password: 'admin',
  },
];

// Passport.js Configuration
passport.use(
  new LocalStrategy((username, password, done) => {
    const user = users.find((user) => user.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return done(null, false, { message: 'Invalid username or password' });
    }

    return done(null, user);
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find((user) => user.id === id);
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  } else {
    res.redirect('/login');
  }
}

app.get('/', (req, res) => {
  res.send('Welcome to the home page');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (users.some((user) => user.username === username)) {
    return res.render('register');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    username: username,
    password: hashedPassword,
  };

  users.push(newUser);

  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
  })
);

app.get('/dashboard', isAuthenticated, (req, res) => {
  res.send(`Welcome to the dashboard, ${req.user.username}!`);
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});