const app = {
  data() {
    return {
      register: false,
      login: false,
      usernameRegister: null,
      passwordRegister: null,
      passwordRepeatRegister: null,
      usernameLogin: null,
      passwordLogin: null,
      response: null,
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
    onClickLogo() {
      this.register = false;
      this.login = false;
    },
    async onRegister() {
      const response = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: this.usernameRegister,
          password: this.passwordRegister,
          repeatedPassword: this.passwordRepeatRegister,
        }),
      });
      this.usernameRegister = null;
      this.passwordRegister = null;
      this.passwordRepeatRegister = null;
      this.response = await response.json();
      console.log(this.response.message);
    },
    async onLogin() {
      const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: this.usernameLogin,
          password: this.passwordLogin,
        }),
      });
      this.usernameLogin = null;
      this.passwordLogin = null;
      this.response = await response.json();
      console.log(this.response.message);
    },
  },
};

Vue.createApp(app).mount('#app');
