const express = require('express');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcrypt');
const supabase = require('./supabase');
const { reset } = require('nodemon');

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
  const username = req.body.username;
  const password = req.body.password;
  const passwordRepeat = req.body.repeatedPassword;

  const { data: usernameMatch, errorRead } = await supabase
    .from('user')
    .select('username')
    .eq('username', username);

  if (usernameMatch.length !== 0) {
    return res.send({
      message: 'Username already exists.',
    });
  } else if (errorRead) {
    return res.send({
      message: 'Unexpected error. Try again.',
    });
  }

  if (password === passwordRepeat) {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const { data, errorInsert } = await supabase.from('user').insert([
      {
        username: username,
        password: hashedPassword,
      },
    ]);
  } else if (password !== passwordRepeat) {
    return res.send({
      message: 'Passwords do not match.',
    });
  } else if (errorInsert) {
    return res.send({
      message: 'Unexpected error. Try again.',
    });
  }

  return res.send({
    message: 'Successfully registered.',
  });
});

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const { data: databasePassword, errorRead } = await supabase
    .from('user')
    .select('password')
    .eq('username', username);
  if (errorRead) {
    return res.send({
      message: 'Unexpected error. Try again.',
    });
  } else {
    const isAuthenticated = await bcrypt.compare(
      password,
      databasePassword[0].password
    );
    if (isAuthenticated) {
      return res.send({
        message: 'Successfully logged in.',
      });
    } else {
      return res.send({
        message: 'Wrong username or password.',
      });
    }
  }
});

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
