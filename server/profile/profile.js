const express = require('express');
const router = express.Router();
const path = require('path');
const multer = require('multer');
const supabase = require('../supabase/client');
const { decode } = require('base64-arraybuffer');

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

router.use(express.static('../public/profile'));

router.get('/profile', async (req, res) => {
  const session = supabase.auth.session();
  if (session) {
    res.sendFile(path.resolve('../public/profile/profile.html'));
  } else {
    res.redirect('/');
  }
});

router.post('/profile/setname', async (req, res) => {
  const session = supabase.auth.session();
  if (session) {
    const { error } = await supabase
      .from('profiles')
      .update({ character_name: req.body.name })
      .eq('id', session.user.id);
    if (error) {
      res.send({
        message: 'Failed to set character name.',
      });
    } else {
      res.send({
        message: 'Character name set successfully.',
      });
    }
  }
});

router.post(
  '/profile/setprofilepicture',
  upload.single('image'),
  async (req, res) => {
    const session = supabase.auth.session();
    if (session) {
      const image = req.file.buffer;
      const { error } = await supabase.storage
        .from('profile_pictures')
        .upload(`${session.user.id}.jpg`, image, {
          contentType: req.file.mimetype,
        });
      if (error) {
        res.send({
          message: 'Failed to upload.',
        });
      } else {
        res.send({
          message: 'Successfully uploaded.',
        });
      }
    }
  }
);

module.exports = router;
