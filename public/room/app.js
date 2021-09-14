const app = {
  data() {
    return {
      readyCount: null,
      totalPlayers: null,
      timer: null,
      ready: false,
      profilePictureUrl: null,
      characterName: null,
      message: null,
      socket: io(),
    };
  },
  methods: {
    sendMessage() {},
    ready() {},
    notReady() {},
    leaveRoom() {},
    goToProfile() {},
  },
};

Vue.createApp(app).mount('#app');
