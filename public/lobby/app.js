const app = {
  data() {
    return {
      rooms: [],
    };
  },
  methods: {
    goToProfile() {
      window.location.href = 'http://localhost:3000/user/profile';
    },
    async signOut() {
      let response = await fetch('http://localhost:3000/auth/signout');
      response = await response.json();
      message = response.message;
      if (message === 'Successfully signed out.') {
        window.location.href = 'http://localhost:3000/';
      }
    },
  },
};

Vue.createApp(app).mount('#app');
