# VibeCatcher - Security Audit Tool

Ship with confidence. We catch the bad vibes first.

VibeCatcher is a comprehensive security audit tool that analyzes your codebase for vulnerabilities and provides AI-powered remediation suggestions.

## 🚀 Features

- **Comprehensive Security Analysis**: Deep static analysis of your codebase
- **Vulnerability Detection**: Identifies XSS, outdated dependencies, and security misconfigurations
- **AI-Powered Remediation**: Context-aware code fixes and custom prompts
- **Enterprise-Grade Reporting**: Detailed security reports with severity classification
- **Firebase Integration**: Secure authentication and data storage
- **Modern UI**: Built with Next.js 15, TypeScript, and Tailwind CSS

## 🛠️ Tech Stack

- **Frontend**: Next.js 15, React 18, TypeScript
- **Styling**: Tailwind CSS, Radix UI Components
- **Authentication**: Firebase Auth (Google Sign-In)
- **Database**: Firebase Firestore
- **Storage**: Firebase Storage
- **Deployment**: Vercel

## 📋 Prerequisites

- Node.js 18+ 
- npm or yarn
- Firebase project
- Google Cloud account (for Firebase)

## 🚀 Getting Started

### 1. Clone and Install

```bash
git clone <your-repo-url>
cd vibecatcher.dev
npm install
```

### 2. Firebase Setup

1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create a new project or select existing one
3. Enable Authentication and select Google as a sign-in method
4. Create a Firestore database
5. Get your Firebase config from Project Settings > General > Your apps

### 3. Environment Variables

Copy `env.example` to `.env.local` and fill in your Firebase values:

```bash
cp env.example .env.local
```

Edit `.env.local` with your actual Firebase configuration:

```env
NEXT_PUBLIC_FIREBASE_API_KEY=your_api_key_here
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=your_project.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=your_project_id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=your_project.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=123456789
NEXT_PUBLIC_FIREBASE_APP_ID=1:123456789:web:abcdef123456
NEXT_PUBLIC_FIREBASE_MEASUREMENT_ID=G-XXXXXXXXXX
```

### 4. Run Development Server

```bash
npm run dev
```

Your app will be available at `http://localhost:9002`

## 🚀 Deployment to Vercel

### 1. Push to GitHub

```bash
git add .
git commit -m "Setup Firebase and prepare for Vercel deployment"
git push origin main
```

### 2. Deploy to Vercel

1. Go to [Vercel](https://vercel.com) and sign in with GitHub
2. Click "New Project" and import your repository
3. Add your environment variables in the Vercel dashboard
4. Deploy!

### 3. Environment Variables in Vercel

Add the same environment variables from your `.env.local` file to your Vercel project settings.

## 📁 Project Structure

```
src/
├── app/                    # Next.js app router
│   ├── dashboard/         # Dashboard pages
│   ├── globals.css        # Global styles
│   ├── layout.tsx         # Root layout with AuthProvider
│   └── page.tsx           # Landing page
├── components/            # Reusable UI components
│   ├── common/           # Common components
│   ├── icons/            # Icon components
│   └── ui/               # Radix UI components
├── contexts/              # React contexts
│   └── auth-context.tsx  # Authentication context
├── hooks/                 # Custom hooks
│   └── use-auth.ts       # Firebase auth hook
└── lib/                   # Utility libraries
    └── firebase.ts       # Firebase configuration
```

## 🔐 Authentication

The app uses Firebase Authentication with Google Sign-In. Users can:

- Sign in with their Google account
- Access protected dashboard routes
- Sign out securely

## 🎨 Customization

- **Colors**: Modify `tailwind.config.ts` for custom color schemes
- **Components**: Update UI components in `src/components/`
- **Styling**: Customize styles in `src/app/globals.css`
- **Content**: Replace placeholder data in `src/app/page.tsx`

## 📝 Available Scripts

- `npm run dev` - Start development server (port 9002)
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm run lint` - Run ESLint
- `npm run typecheck` - Run TypeScript type checking

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For support, please open an issue in the GitHub repository.
