const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const supabase = require('./supabase');

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('../public'));

app.get('/', (req, res) => {
  res.sendFile(path.resolve('../public/index.html'));
});

app.post('/register', async (req, res) => {
  if (req.body.password === req.body.passwordRepeat) {
    try {
      const { user, error } = await supabase.auth.signUp({
        email: req.body.email,
        password: req.body.password,
      });
      if (error) {
        res.send({
          message: 'Email is in use.',
        });
      } else {
        res.send({
          status: 200,
          message: 'Successfully registered.',
        });
      }
    } catch (e) {
      res.send({
        message: 'Unexpected error.',
      });
    }
  } else {
    res.send({
      message: 'Passwords do not match.',
    });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { user, session, error } = await supabase.auth.signIn({
      email: req.body.email,
      password: req.body.password,
    });
    if (error) {
      res.send({
        message: 'Authentication failed.',
      });
    } else {
      res.send({
        message: 'Successfully logged in.',
      });
    }
  } catch (e) {
    res.send({
      message: 'Unexpected error.',
    });
  }
});

app.get('/profile', async (req, res) => {
  const session = supabase.auth.session();
  if (session) {
    res.send('Profile page');
  } else {
    res.send('You can not access.');
  }
});

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
