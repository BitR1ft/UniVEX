import Link from 'next/link'

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center p-24 bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white">
      <div className="max-w-5xl w-full text-center">
        <h1 className="text-6xl font-bold mb-6 bg-gradient-to-r from-blue-500 to-purple-600 text-transparent bg-clip-text">
          UniVex
        </h1>
        
        <p className="text-xl text-gray-300 mb-12 max-w-2xl mx-auto">
          An agentic, fully-automated penetration testing framework powered by AI
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="text-3xl mb-4">🔍</div>
            <h3 className="text-lg font-semibold mb-2">Reconnaissance</h3>
            <p className="text-sm text-gray-400">
              Multi-phase discovery, subdomain enumeration, and port scanning
            </p>
          </div>
          
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="text-3xl mb-4">🎯</div>
            <h3 className="text-lg font-semibold mb-2">Exploitation</h3>
            <p className="text-sm text-gray-400">
              AI-driven vulnerability detection and exploitation strategies
            </p>
          </div>
          
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
            <div className="text-3xl mb-4">📊</div>
            <h3 className="text-lg font-semibold mb-2">Reporting</h3>
            <p className="text-sm text-gray-400">
              Professional reports with evidence and remediation guidance
            </p>
          </div>
        </div>
        
        <div className="flex gap-4 justify-center">
          <Link
            href="/auth/login"
            className="px-8 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold transition-colors"
          >
            Get Started
          </Link>
          <Link
            href="/auth/register"
            className="px-8 py-3 bg-gray-700 hover:bg-gray-600 rounded-lg font-semibold transition-colors"
          >
            Sign Up
          </Link>
        </div>
        
        <div className="mt-16 text-sm text-gray-500">
          <p>⚠️ For authorized penetration testing only</p>
        </div>
      </div>
    </main>
  )
}
