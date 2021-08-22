const app = {
  data() {
    return {
      register: false,
      login: false,
    };
  },
  methods: {
    onClickRegister() {
      const card = document.querySelector('main');
      this.login = false;
      this.register = !this.register;

      if (this.register) {
        card.classList.add('is-flipped');
      } else {
        card.classList.remove('is-flipped');
      }
    },
    onClickLogin() {
      const card = document.querySelector('main');

      this.register = false;
      this.login = !this.login;

      if (this.login) {
        card.classList.add('is-flipped');
      } else {
        card.classList.remove('is-flipped');
      }
    },
  },
};

Vue.createApp(app).mount('#app');
