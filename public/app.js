const app = {
  data() {
    return {
      register: false,
      login: false,
      emailRegister: null,
      passwordRegister: null,
      passwordRepeatRegister: null,
      emailLogin: null,
      passwordLogin: null,
      response: null,
      registerMessage: null,
      loginMessage: null,
    };
  },
  methods: {
    onClickRegister() {
      this.login = false;
      this.register = !this.register;
      this.response = null;
      this.registerMessage = null;
      this.loginMessage = null;
    },
    onClickLogin() {
      this.register = false;
      this.login = !this.login;
      this.response = null;
      this.registerMessage = null;
      this.loginMessage = null;
    },
    onClickLogo() {
      this.register = false;
      this.login = false;
      this.response = null;
      this.registerMessage = null;
      this.loginMessage = null;
    },
    async onRegister() {
      const response = await fetch('http://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: this.emailRegister,
          password: this.passwordRegister,
          passwordRepeat: this.passwordRepeatRegister,
        }),
      });
      this.emailRegister = null;
      this.passwordRegister = null;
      this.passwordRepeatRegister = null;
      this.response = await response.json();
      this.registerMessage = this.response.message;
    },
    async onLogin() {
      const response = await fetch('http://localhost:3000/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: this.emailLogin,
          password: this.passwordLogin,
        }),
      });
      this.emailLogin = null;
      this.passwordLogin = null;
      this.response = await response.json();
      this.loginMessage = this.response.message;
    },
  },
};

Vue.createApp(app).mount('#app');
