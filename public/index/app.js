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
      registerMessage: null,
      loginMessage: null,
    };
  },
  methods: {
    onClickRegister() {
      this.login = false;
      this.register = !this.register;
      this.registerMessage = null;
      this.loginMessage = null;
    },
    onClickLogin() {
      this.register = false;
      this.login = !this.login;
      this.registerMessage = null;
      this.loginMessage = null;
    },
    onClickLogo() {
      this.register = false;
      this.login = false;
      this.registerMessage = null;
      this.loginMessage = null;
    },
    async onRegister() {
      let response = await fetch('http://localhost:3000/auth/register', {
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
      response = await response.json();
      this.registerMessage = response.message;
    },
    async onLogin() {
      let response = await fetch('http://localhost:3000/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: this.emailLogin,
          password: this.passwordLogin,
        }),
      });
      this.emailLogin = null;
      this.passwordLogin = null;
      response = await response.json();
      this.loginMessage = response.message;
      if (this.loginMessage == 'Successfully logged in.') {
        window.location.href = 'http://localhost:3000/user/profile';
      }
    },
  },
};

Vue.createApp(app).mount('#app');
