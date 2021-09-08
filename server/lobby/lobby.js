const express = require('express');
const router = express.Router();
const path = require('path');
const supabase = require('../supabase/client');

router.use(express.static('../public/lobby'));

router.get('/', async (req, res) => {
  const session = await supabase.auth.session();
  if (session) {
    res.sendFile(path.resolve('../public/lobby/lobby.html'));
  }
});

router.get('/data', async (req, res) => {
  const { data, error } = await supabase.from('rooms').select('*');
  if (error) {
    res.send({
      message: 'Unexpected error.',
    });
  } else {
    res.send({ data });
  }
});

router.post('/create', async (req, res) => {
  const session = await supabase.auth.session();
  const { data, error } = await supabase
    .from('profiles')
    .select('character_name')
    .eq('id', session.user.id);
  if (error) {
    res.send({
      message: 'Unexpected error.',
    });
  } else {
    const { error } = await supabase.from('rooms').insert([
      {
        id: session.user.id,
        character_name: data[0].character_name,
        room_name: req.body.name,
        player_count: 1,
        capacity: parseInt(req.body.capacity),
      },
    ]);
    if (error) {
      res.send({
        message: 'Unexpected error.',
      });
    } else {
      res.send({
        message: 'Successful.',
      });
    }
  }
});

module.exports = router;
