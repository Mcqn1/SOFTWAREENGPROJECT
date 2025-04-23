// client/src/axios.js
import axios from 'axios';

const instance = axios.create({
  baseURL: 'https://carboncredits-backend.onrender.com/',
  withCredentials: true, // ✅ required for session cookie-based auth
});

export default instance;
