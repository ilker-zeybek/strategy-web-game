const express = require('express');
const router = express.Router();
const supabase = require('../supabase/client');

router.post('/register', async (req, res) => {
  if (req.body.password === req.body.passwordRepeat) {
    try {
      const { user, error } = await supabase.auth.signUp({
        email: req.body.email,
        password: req.body.password,
      });
      if (error) {
        return res.send({
          message: 'Email is in use.',
        });
      } else {
        const { error } = await supabase.from('profiles').insert([
          {
            id: user.id,
            updated_at: user.updated_at,
            email: user.email,
            character_name: null,
            profile_picture: null,
            win_count: 0,
            lose_count: 0,
          },
        ]);
        if (error) {
          return res.send({
            message: 'Unexpected error.',
          });
        } else {
          return res.send({
            status: 200,
            message: 'Successfully registered.',
          });
        }
      }
    } catch (e) {
      return res.send({
        message: 'Unexpected error.',
      });
    }
  } else {
    return res.send({
      message: 'Passwords do not match.',
    });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { user, session, error } = await supabase.auth.signIn({
      email: req.body.email,
      password: req.body.password,
    });
    if (error) {
      return res.send({
        message: 'Authentication failed.',
      });
    } else {
      return res.send({
        message: 'Successfully logged in.',
      });
    }
  } catch (e) {
    return res.send({
      message: 'Unexpected error.',
    });
  }
});

router.get('/signout', async (req, res) => {
  const { error } = await supabase.auth.signOut();
  if (error) {
    return res.send({
      message: 'Unexpected error.',
    });
  } else {
    return res.send({
      message: 'Successfully signed out.',
    });
  }
});

module.exports = router;
