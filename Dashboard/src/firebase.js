// firebase.js
// ─────────────────────────────────────────────────────────────
// SETUP STEPS:
//  1. Go to https://console.firebase.google.com
//  2. Create a project → Add a Web App
//  3. Copy your firebaseConfig values below
//  4. In Firebase console → Realtime Database → Create database
//  5. Set rules to allow read/write for development:
//     { "rules": { ".read": true, ".write": true } }
// ─────────────────────────────────────────────────────────────

import { initializeApp } from 'firebase/app'
import { getDatabase } from 'firebase/database'
import { getAuth } from 'firebase/auth'

const firebaseConfig = {
  apiKey: "AIzaSyCRdk70Y8V1HJfLT_YieQ9isnvyWhy9_hk",
  authDomain: "hive-f839e.firebaseapp.com",
  databaseURL:       "https://hive-f839e-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "hive-f839e",
  storageBucket: "hive-f839e.firebasestorage.app",
  messagingSenderId: "404355161913",
  appId: "1:404355161913:web:5b292e5a72fa4a2c86d2e8",
  measurementId: "G-SHVB4TX7Q7"
};

const app = initializeApp(firebaseConfig)
export const db   = getDatabase(app)
export const auth = getAuth(app)
