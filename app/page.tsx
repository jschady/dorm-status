import { SignUpButton, SignedIn, SignedOut } from "@clerk/nextjs";
import { auth } from "@clerk/nextjs/server";
import { redirect } from "next/navigation";
import GoogleSignInButton from "./components/google-signin-button";

export default async function Home() {
  // Check if user is authenticated, if so redirect to dashboard
  const { userId } = await auth();
  
  if (userId) {
    redirect("/dashboard");
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-tiger-blue via-tiger-purple to-tiger-pink">
      <div id="clerk-captcha" />
      {/* Fixed Navigation Header */}
      <div className="fixed top-4 left-1/2 transform -translate-x-1/2 max-w-6xl w-11/12 px-4 py-2 bg-white rounded-2xl shadow-md z-50">
        <nav className="flex justify-between sm:grid sm:grid-cols-3">
          {/* Logo/Brand */}
          <div className="flex items-center flex-shrink-0 gap-2 text-black">
            <span className="text-2xl">🏠</span>
            <span className="font-semibold text-xl tracking-tight">Tiger Dorm</span>
          </div>
          
          {/* Center Navigation - Empty for now */}
          <div className="items-center justify-center lg:gap-8 gap-4 hidden sm:flex">
            {/* Future navigation links can go here */}
          </div>
          
          {/* Login Button */}
          <div className="flex items-center justify-end">
            <SignedOut>
              <GoogleSignInButton />
            </SignedOut>
            
            <SignedIn>
              <div className="bg-green-100 border border-green-300 rounded-lg px-3 py-2">
                <span className="text-green-700 font-medium text-sm">✅ Signed In</span>
              </div>
            </SignedIn>
          </div>
        </nav>
      </div>

      {/* Main Content */}
      <div className="flex items-center justify-center px-4 sm:px-6 lg:px-8 pt-24 pb-12">
        <div className="max-w-4xl w-full space-y-12 text-center">
          {/* Hero Section */}
          <div className="space-y-6">
            <h2 className="text-4xl md:text-5xl font-bold text-white mb-6">
              Real-time Dorm Status Dashboard
            </h2>
            <p className="text-xl md:text-2xl text-gray-200 max-w-2xl mx-auto leading-relaxed">
              Track your roommates' status with GPS-powered geofences and real-time updates
            </p>
          </div>

          {/* Enhanced Features Preview */}
          <div className="grid md:grid-cols-3 gap-6 py-8">
            <div className="group bg-white/10 hover:bg-white/20 backdrop-blur-lg rounded-2xl p-8 text-center transition-all duration-300 transform hover:scale-105 hover:shadow-2xl border border-white/20 hover:border-white/30">
              <div className="bg-gradient-to-br from-indigo-400 to-purple-500 rounded-full w-16 h-16 mx-auto mb-6 flex items-center justify-center transform group-hover:rotate-6 transition-transform duration-300">
                <span className="text-3xl">🎯</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Smart Geofencing</h3>
              <p className="text-gray-300 leading-relaxed">
                Automatic status updates based on location with customizable boundaries and notifications
              </p>
            </div>
            
            <div className="group bg-white/10 hover:bg-white/20 backdrop-blur-lg rounded-2xl p-8 text-center transition-all duration-300 transform hover:scale-105 hover:shadow-2xl border border-white/20 hover:border-white/30">
              <div className="bg-gradient-to-br from-yellow-400 to-orange-500 rounded-full w-16 h-16 mx-auto mb-6 flex items-center justify-center transform group-hover:rotate-6 transition-transform duration-300">
                <span className="text-3xl">⚡</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Real-time Updates</h3>
              <p className="text-gray-300 leading-relaxed">
                See status changes instantly across all devices with lightning-fast synchronization
              </p>
            </div>
            
            <div className="group bg-white/10 hover:bg-white/20 backdrop-blur-lg rounded-2xl p-8 text-center transition-all duration-300 transform hover:scale-105 hover:shadow-2xl border border-white/20 hover:border-white/30">
              <div className="bg-gradient-to-br from-green-400 to-teal-500 rounded-full w-16 h-16 mx-auto mb-6 flex items-center justify-center transform group-hover:rotate-6 transition-transform duration-300">
                <span className="text-3xl">👥</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3">Multi-Room Support</h3>
              <p className="text-gray-300 leading-relaxed">
                Join multiple dorms with secure invite-based access and role management
              </p>
            </div>
          </div>

          {/* Call to Action */}
          <SignedOut>
            <div className="space-y-6">               
                  <GoogleSignInButton 
                    variant="cta" 
                    text="🔑 Sign Up with Google"
                    mode="signup"
                  />
            </div>
          </SignedOut>

          <SignedIn>
            <div className="bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/50 rounded-2xl p-6 max-w-md mx-auto backdrop-blur-lg">
              <p className="text-green-200 text-lg font-medium">
                ✅ You're signed in! Redirecting to dashboard...
              </p>
            </div>
          </SignedIn>

          {/* Footer */}
          <div className="pt-12 text-gray-400 text-sm">
            <p className="flex items-center justify-center space-x-2">
              <span>Built with</span>
              <span className="font-medium text-white">Next.js 15</span>
              <span>•</span>
              <span className="font-medium text-white">Clerk Auth</span>
              <span>•</span>
              <span className="font-medium text-white">Supabase</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}