const express = require('express');
const router = express.Router();
const path = require('path');
const nodeFetch = require('node-fetch');

const supabase = require('../supabase/client');

let sockets = [];

const isInRoom = async (req, res, next) => {
  const session = await supabase.auth.session();
  const io = req.app.get('io');
  const { data, error } = await supabase.from('rooms').select('id,players');
  if (error) {
    return res.send({
      message: 'Unexpected error.',
    });
  } else {
    for (room in data) {
      for (const key in data[room].players) {
        if (data[room].players[key] === session.user.id) {
          io.on('connection', (socket) => {
            sockets.push({ id: session.user.id, socket: socket.id });
            socket.join(req.params.id);
            socket.on('generalmessage', async (msg) => {
              const to = req.params.id;
              const from = session.user.id;
              const message = msg;
              const { error } = await supabase.from('generalchat').insert({
                from: from,
                to: to,
                message: message,
              });
              if (error) {
                return res.send({
                  message: 'Unexpected error.',
                });
              } else {
                let data = await nodeFetch('http://localhost:3000/user/data');
                data = await data.json();
                socket.broadcast.to(to).emit('generalmessage', {
                  characterName: data.characterName,
                  profilePictureUrl: data.profilePictureUrl,
                  message: message,
                });
                io.sockets.emit('generalmessage', {
                  characterName: data.characterName,
                  profilePictureUrl: data.profilePictureUrl,
                  message: message,
                });
              }
            });
          });
        }

        return res.sendFile(path.resolve('../public/room/room.html'));
      }
    }

    next();
  }
};

const hasSocket = async (req, res, next) => {
  const session = await supabase.auth.session();
};

router.use(express.static('../public/room/'));

router.get('/:id', isInRoom, async (req, res) => {
  const session = await supabase.auth.session();
  const { data, error } = await supabase
    .from('rooms')
    .select('player_count,capacity,players')
    .eq('id', req.params.id);
  if (error) {
    return res.send({
      message: 'Unexpected error.',
    });
  } else {
    if (data[0].capacity > data[0].player_count) {
      for (const property in data[0].players) {
        if (data[0].players[property] !== session.user.id) {
          const key = data[0].player_count + 1;
          data[0].players[key] = session.user.id;
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
        return res.send({
          message: 'Unexpected error.',
        });
      } else {
        res.sendFile(path.resolve('../public/room/room.html'));
      }
    } else {
      return res.send({
        message: 'Room is full.',
      });
    }
  }
});

module.exports = router;
