import { initializeApp, getApps, getApp } from 'firebase/app';
import { getAuth, GithubAuthProvider } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';
import { getStorage } from 'firebase/storage';

const firebaseConfig = {
  apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
  measurementId: process.env.NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID,
};

// Initialize Firebase
const app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig);

// Initialize Firebase services
export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);

// Configure GitHub OAuth provider with proper scopes
export const githubProvider = new GithubAuthProvider();
// Add scopes for repository access
githubProvider.addScope('repo'); // Full repository access (includes private repos)
githubProvider.addScope('read:user'); // Read user profile
githubProvider.addScope('user:email'); // Read user email
githubProvider.addScope('read:org'); // Read organization data
githubProvider.addScope('workflow'); // Read workflow files

// Set custom parameters to ensure we get the access token
githubProvider.setCustomParameters({
  prompt: 'consent' // Force consent screen to ensure token generation
});

export default app;
