# Deploy Firestore Security Rules

To fix the "Missing or insufficient permissions" error, you need to deploy the Firestore security rules.

## Option 1: Using Firebase CLI (Recommended)

1. Install Firebase CLI if you haven't already:
   ```bash
   npm install -g firebase-tools
   ```

2. Login to Firebase:
   ```bash
   firebase login
   ```

3. Initialize Firebase in your project (if not already done):
   ```bash
   firebase init firestore
   ```

4. Deploy the security rules:
   ```bash
   firebase deploy --only firestore:rules
   ```

## Option 2: Using Firebase Console

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Select your project
3. Go to Firestore Database → Rules
4. Copy the contents of `firestore.rules` file
5. Paste and publish the rules

## Option 3: Quick Test (Development Only)

If you want to quickly test your OAuth flow, you can temporarily use the development rules:

1. In Firebase Console, go to Firestore Database → Rules
2. Replace the rules with:
   ```
   rules_version = '2';
   service cloud.firestore {
     match /databases/{database}/documents {
       match /{document=**} {
         allow read, write: if true;
       }
     }
   }
   ```
3. **WARNING: This allows all access - ONLY use for development!**

## Current Rules

The `firestore.rules` file contains secure rules that:
- Allow authenticated users to read/write their own data
- Allow creating new users during OAuth flow
- Deny all other access for security

## After Deployment

Once the rules are deployed, your OAuth flow should work without permission errors. The rules will:
1. Allow the Firebase Auth user to be created
2. Allow the user document to be written to Firestore
3. Allow subsequent reads/writes to the user's own data
