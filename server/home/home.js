const express = require('express');
const router = express.Router();
const path = require('path');
const supabase = require('../supabase/client');

router.use((req, res, next) => {
  const session = supabase.auth.session();
  if (session) {
    res.redirect('/user/profile');
  } else {
    next();
  }
});
router.use(express.static('../public/index'));

router.get('/', (req, res) => {
  res.sendFile(path.resolve('../public/index/index.html'));
});

module.exports = router;
