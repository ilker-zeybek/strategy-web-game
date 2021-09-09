const express = require('express');
const router = express.Router();
const path = require('path');
const supabase = require('../supabase/client');

const checkAuth = (req, res, next) => {
  const session = supabase.auth.session();
  if (session) {
    return res.redirect('/user/profile');
  } else {
    next();
  }
};

router.get('/', checkAuth, (req, res) => {
  return res.sendFile(path.resolve('../public/index/index.html'));
});

router.use(express.static('../public/index'));

module.exports = router;
