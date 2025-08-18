import { SignInButton, SignUpButton, SignedIn, SignedOut } from "@clerk/nextjs";
import { auth } from "@clerk/nextjs/server";
import { redirect } from "next/navigation";

export default async function Home() {
  // Check if user is authenticated, if so redirect to dashboard
  const { userId } = await auth();
  
  if (userId) {
    redirect("/dashboard");
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-violet-900">
      <div className="min-h-screen flex items-center justify-center px-4 sm:px-6 lg:px-8">
        <div className="max-w-md w-full space-y-8 text-center">
          {/* Logo/Header */}
          <div>
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-4">
              🏠 Tiger Dorm
            </h1>
            <h2 className="text-xl md:text-2xl text-gray-300 mb-6">
              Real-time Dorm Status Dashboard
            </h2>
            <p className="text-gray-400 text-lg">
              Track your roommates' status with GPS-powered geofences and real-time updates
            </p>
          </div>

          {/* Features Preview */}
          <div className="space-y-4 py-8">
            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4 text-left">
              <div className="flex items-center space-x-3">
                <span className="text-2xl">🎯</span>
                <div>
                  <h3 className="text-white font-semibold">Smart Geofencing</h3>
                  <p className="text-gray-300 text-sm">Automatic status updates based on location</p>
                </div>
              </div>
            </div>
            
            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4 text-left">
              <div className="flex items-center space-x-3">
                <span className="text-2xl">⚡</span>
                <div>
                  <h3 className="text-white font-semibold">Real-time Updates</h3>
                  <p className="text-gray-300 text-sm">See status changes instantly across all devices</p>
                </div>
              </div>
            </div>
            
            <div className="bg-white/10 backdrop-blur-sm rounded-lg p-4 text-left">
              <div className="flex items-center space-x-3">
                <span className="text-2xl">👥</span>
                <div>
                  <h3 className="text-white font-semibold">Multi-Room Support</h3>
                  <p className="text-gray-300 text-sm">Join multiple dorms with invite-based access</p>
                </div>
              </div>
            </div>
          </div>

          {/* Authentication Buttons */}
          <SignedOut>
            <div className="space-y-4">
              <SignUpButton>
                <button className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-6 rounded-lg transition-colors duration-200 shadow-lg hover:shadow-xl">
                  Get Started - Sign Up
                </button>
              </SignUpButton>
              
              <SignInButton>
                <button className="w-full bg-white/20 hover:bg-white/30 text-white font-semibold py-3 px-6 rounded-lg transition-colors duration-200 border border-white/30 hover:border-white/50">
                  Already have an account? Sign In
                </button>
              </SignInButton>
            </div>
          </SignedOut>

          <SignedIn>
            <div className="bg-green-500/20 border border-green-500/50 rounded-lg p-4">
              <p className="text-green-200">
                ✅ You're signed in! Redirecting to dashboard...
              </p>
            </div>
          </SignedIn>

          {/* Footer */}
          <div className="pt-8 text-gray-500 text-sm">
            <p>
              Built with Next.js 15, Clerk Auth, and Supabase
            </p>
            <p className="mt-2">
              🚧 Epic 1: Authentication Foundation - Complete
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}