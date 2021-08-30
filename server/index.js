const express = require('express');
const cors = require('cors');
const path = require('path');

const supabase = require('./supabase/client');
const auth = require('./authentication/auth');
const profile = require('./profile/profile');

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('../public/index'));
app.use('/auth', auth);
app.use('/lobby', profile);

app.get('/', (req, res) => {
  res.sendFile(path.resolve('../public/index/index.html'));
});

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
