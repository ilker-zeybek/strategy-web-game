const getCookie = require('../utilities/getCookie');

const app = {
  data() {
    return {
      email: null,
      updatedAt: null,
      characterName: null,
      characterNameDisplay: null,
      profilePicture: null,
      profilePictureUrl: null,
      winCount: null,
      loseCount: null,
      messageProfileData: null,
      messageProfilePicture: null,
      messageCharacterName: null,
    };
  },
  async beforeMount() {
    //Get the profile data on mount event.
    this.getProfileData();
  },
  destroyed() {
    //Add event listener to the profile picture input.
    const profilePictureElement = document.getElementById('profilePicture');
    console.log(profilePictureElement);
    profilePictureElement.removeEventListener('change', async (e) => {
      this.profilePicture = e.target.files[0];
    });
  },
  updated() {
    //Add event listener to the profile picture input.
    const profilePictureElement = document.getElementById('profilePicture');
    console.log(profilePictureElement);
    profilePictureElement.addEventListener('change', async (e) => {
      this.profilePicture = e.target.files[0];
    });
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
      this.getProfileData();
    },
    async uploadImage() {
      const formData = new FormData();
      formData.append('image', this.profilePicture);
      console.log(formData);
      let response = await fetch(
        'http://localhost:3000/user/profile/setprofilepicture',
        {
          method: 'POST',
          body: formData,
        }
      );
      response = await response.json();
      this.messageProfilePicture = response.message;
      this.getProfileData();
    },
    async getProfileData() {
      const userID = getCookie('id');
      let response = await fetch(`http://localhost:3000/user/${userID}`);
      response = await response.json();
      this.email = response.email;
      this.characterNameDisplay = response.characterName;
      this.profilePictureUrl = response.profilePictureUrl;
      this.winCount = response.winCount;
      this.loseCount = response.loseCount;
    },
  },
};

Vue.createApp(app).mount('#app');
