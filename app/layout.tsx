import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Toaster } from 'react-hot-toast'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'VibeCatcher.dev - Ship with Confidence',
  description: 'We catch the bad vibes first. Enterprise-level security audits for vibe coders, microsaas entrepreneurs, and solopreneurs.',
  keywords: 'security audit, code security, web app security, developer tools, cybersecurity',
  authors: [{ name: 'VibeCatcher.dev' }],
  openGraph: {
    title: 'VibeCatcher.dev - Ship with Confidence',
    description: 'We catch the bad vibes first. Enterprise-level security audits for vibe coders, microsaas entrepreneurs, and solopreneurs.',
    type: 'website',
    locale: 'en_US',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'VibeCatcher.dev - Ship with Confidence',
    description: 'We catch the bad vibes first. Enterprise-level security audits for vibe coders, microsaas entrepreneurs, and solopreneurs.',
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className={inter.className}>
        {children}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1e293b',
              color: '#fff',
              border: '1px solid #475569',
            },
          }}
        />
      </body>
    </html>
  )
}
