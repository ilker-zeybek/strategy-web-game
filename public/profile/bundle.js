(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
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
    goToLobby() {
      window.location.href = 'http://localhost:3000/lobby';
    },
  },
};

Vue.createApp(app).mount('#app');

},{"../utilities/getCookie":2}],2:[function(require,module,exports){
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

module.exports = getCookie;

},{}]},{},[1]);
