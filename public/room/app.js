const app = {
  data() {
    return {
      readyCount: null,
      totalPlayers: null,
      timer: null,
      ready: false,
      profilePictureUrl: null,
      characterName: null,
      messageCopy: null,
      message: null,
      socket: io(),
      messages: [],
    };
  },
  mounted() {
    this.socket.on('generalmessage', (data) => {
      this.messages.push({ class: 'message', message: data.message });
      if (data.profilePictureUrl.length > 0) {
        this.profilePictureUrl = data.profilePictureUrl;
      }
      this.characterName = data.characterName;
    });
  },
  methods: {
    async sendMessage() {
      let data = await fetch('http://localhost:3000/user/data');
      data = await data.json();
      this.characterName = data.characterName;
      if (data.profilePictureUrl.length > 0) {
        this.profilePictureUrl = data.profilePictureUrl;
      }
      this.message = this.messageCopy;
      this.socket.emit('generalmessage', this.message);
      this.messages.push({ class: 'message mine', message: this.message });
    },
    ready() {},
    notReady() {},
    leaveRoom() {},
    goToProfile() {},
  },
};

Vue.createApp(app).mount('#app');
