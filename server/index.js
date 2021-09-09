const express = require('express');
const cors = require('cors');

const auth = require('./authentication/auth');
const profile = require('./profile/profile');
const home = require('./home/home');
const lobby = require('./lobby/lobby');
const room = require('./room/room');

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use('/', home);
app.use('/auth', auth);
app.use('/user', profile);
app.use('/lobby', lobby);
app.use('/room', room);

app.listen(port, () => {
  console.log(`Listening on http://localhost:${port}`);
});
