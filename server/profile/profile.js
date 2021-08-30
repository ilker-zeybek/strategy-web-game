const express = require('express');
const router = express.Router();
const supabase = require('../supabase/client');

router.use(express.static('../public/profile'));

router.get('/profile', async (req, res) => {
  const session = supabase.auth.session();
  if (session) {
    res.sendFile(path.resolve('../public/profile/index.html'));
  } else {
    res.redirect('/');
  }
});

module.exports = router;
