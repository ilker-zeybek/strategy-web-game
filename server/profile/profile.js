const express = require('express');
const router = express.Router();
const path = require('path');
const multer = require('multer');
const supabase = require('../supabase/client');

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

router.use(express.static('../public/profile'));

router.get('/profile', async (req, res) => {
  const session = supabase.auth.session();
  if (session) {
    return res.sendFile(path.resolve('../public/profile/profile.html'));
  } else {
    return res.redirect('/');
  }
});

router.get('/data', async (req, res) => {
  const session = supabase.auth.session();
  const userID = session.user.id;
  const { data, error } = await supabase
    .from('profiles')
    .select('email,character_name,profile_picture,win_count,lose_count')
    .eq('id', userID);
  if (error) {
    return res.send({
      message: 'Unexpected error.',
    });
  } else {
    return res.send({
      email: data[0].email,
      characterName: data[0].character_name,
      profilePictureUrl: data[0].profile_picture,
      winCount: data[0].win_count,
      loseCount: data[0].lose_count,
    });
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
      return res.send({
        message: 'Failed to set character name.',
      });
    } else {
      return res.send({
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
        return res.send({
          message: 'Failed to upload.',
        });
      } else {
        const { publicURL, error } = await supabase.storage
          .from('profile_pictures')
          .getPublicUrl(`${session.user.id}.jpg`);
        if (error) {
          return res.send({
            message: 'Failed to get profile picture url.',
          });
        } else {
          const { error } = await supabase
            .from('profiles')
            .update({ profile_picture: publicURL })
            .match({ id: session.user.id });
          if (error) {
            return res.send({
              message: 'Failed to insert profile picture url.',
            });
          } else {
            return res.send({
              message: 'Successfully uploaded.',
            });
          }
        }
      }
    }
  }
);

module.exports = router;
