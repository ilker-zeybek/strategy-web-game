const app = {
  data() {
    return {
      rooms: [],
      room: {
        name: null,
        capacity: 'Room Capacity',
        error: null,
      },
      createRoomError: null,
      done: null,
    };
  },
  async beforeMount() {
    //Get the room data on mount event.
    this.getRoomData();
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
    async getRoomData() {
      let response = await fetch('http://localhost:3000/lobby/data');
      response = await response.json();
      this.rooms = response.data;
      this.done = true;
    },
    async createRoom() {
      let response = await fetch('http://localhost:3000/lobby/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: this.room.name,
          capacity: this.room.capacity,
        }),
      });
      response = await response.json();
      if (response.message === 'Successful.') {
        this.getRoomData();
        this.room.name = null;
        this.room.capacity = null;
        this.room.error = false;
      } else {
        this.room.error = true;
      }
    },
    joinRoom(room) {
      window.location.href = `http://localhost:3000/room/${room.id}`;
    },
  },
};

Vue.createApp(app).mount('#app');
