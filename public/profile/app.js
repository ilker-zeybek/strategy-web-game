const getCookie = require('../utilities/getCookie');

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
    };
  },
  methods: {
    async setCharacterName() {
      let response = await fetch('http://localhost:3000/user/profile/setname', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: this.characterName,
        }),
      });
      response = await response.json();
      this.messageCharacterName = response.message;
    },
    async uploadImage() {
      const formData = new FormData();
      formData.append('image', this.profilePicture);
      let response = await fetch(
        'http://localhost:3000/user/profile/setprofilepicture',
        {
          method: 'POST',
          body: formData,
        }
      );
      response = await response.json();
      this.messageProfilePicture = response.message;
    },
  },
  async mounted() {
    //Get the profile data on mount event.
    const userID = getCookie('id');
    let response = await fetch(`http://localhost:3000/user/${userID}`);
    response = await response.json();
    this.email = response.email;
    this.characterName = response.characterName;
    this.profilePictureUrl = response.profilePictureUrl;
    this.winCount = response.winCount;
    this.loseCount = response.loseCount;

    //Add the event listener for profile picture upload.
    const profilePictureElement = document.getElementById('formFile');
    profilePictureElement.addEventListener('change', async (e) => {
      this.profilePicture = e.target.files[0];
    });
  },
};

Vue.createApp(app).mount('#app');
