const { createClient } = require('@supabase/supabase-js');

const SUPABASE_URL = 'https://pyikzcxmpzwlbitjmhaz.supabase.co';
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlhdCI6MTYyOTY0MTk2NCwiZXhwIjoxOTQ1MjE3OTY0fQ.K51nlFzMf6Qmj3uju4aizXvWcGkQtqLLnRtrk48E1vs';

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const getCookie = (cname) => {
  const name = cname + '=';
  const decodedCookie = decodeURIComponent(document.cookie);
  const ca = decodedCookie.split(';');
  for (let i = 0; i < ca.length; i++) {
    let c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return '';
};

const app = {
  data() {
    return {
      email: null,
      updatedAt: null,
      characterName: null,
      profilePicture: null,
      profilePictureUrl: null,
      winCount: null,
      loseCount: null,
      messageProfileData: null,
      messageProfilePicture: null,
      messageCharacterName: null,
      response: null,
    };
  },
  mounted() {
    const profilePictureElement = document.getElementById('formFile');
    profilePictureElement.addEventListener('change', async (e) => {
      this.profilePicture = e.target.files[0];
    });
  },
  methods: {
    async getProfileData() {
      const userID = getCookie('id');
      console.log(userID);
      const { error } = await supabase
        .from('profiles')
        .select('email,character_name,profile_picture,win_count,lose_count')
        .filter('id', 'eq', userID);
      if (error) {
        this.messageProfileData =
          'Failed to retrieve data. Please reload the page.';
      } else {
        this.email = data[0].email;
        this.characterName = data[0].character_name;
        this.profilePictureUrl = data[0].profile_picture;
        this.winCount = data[0].win_count;
        this.loseCount = data[0].lose_count;
      }
    },
    async setCharacterName() {
      const response = await fetch(
        'http://localhost:3000/lobby/profile/setname',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: this.characterName,
          }),
        }
      );
      this.response = await response.json();
      this.messageCharacterName = this.response.message;
    },
    async uploadImage() {
      const formData = new FormData();
      formData.append('image', this.profilePicture);
      const response = await fetch(
        'http://localhost:3000/lobby/profile/setprofilepicture',
        {
          method: 'POST',
          body: formData,
        }
      );
      this.response = await response.json();
      this.messageProfilePicture = this.response.message;
    },
  },
};

Vue.createApp(app).mount('#app');
