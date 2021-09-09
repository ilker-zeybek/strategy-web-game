const express = require('express');
const router = express.Router();
const path = require('path');

const supabase = require('../supabase/client');

router.get('/:id', async (req, res) => {
  const session = await supabase.auth.session();
  const { data, error } = await supabase
    .from('rooms')
    .select('player_count,capacity,players')
    .eq('id', req.params.id);
  if (error) {
    res.send({
      message: 'Unexpected error.',
    });
  } else {
    if (data[0].capacity > data[0].player_count) {
      for (const property in data[0].players) {
        if (data[0].players[property] !== session.user.id) {
          const key = data[0].player_count + 1;
          data[0].players[key] = session.user.id;
        } else {
          return res.send({
            message: 'You are already in this room.',
          });
        }
      }
      const { error } = await supabase
        .from('rooms')
        .update({
          player_count: data[0].player_count + 1,
          players: data[0].players,
        })
        .eq('id', req.params.id);
      if (error) {
        res.send({
          message: 'Unexpected error.',
        });
      } else {
        res.sendFile(path.resolve('../public/room/room.html'));
      }
    } else {
      res.send({
        message: 'Room is full.',
      });
    }
  }
});

router.use(express.static('../public/room/'));

module.exports = router;