const app = {
  data() {
    return {
      counterr: 0,
    };
  },
  methods: {
    increaseCounter() {
      this.counter++;
    },
  },
};

Vue.createApp(app).mount('#app');
