'use client';

import { useSignIn } from '@clerk/nextjs';

interface GoogleSignInButtonProps {
  variant?: 'header' | 'cta';
  text?: string;
  className?: string;
}

export default function GoogleSignInButton({ 
  variant = 'header', 
  text,
  className 
}: GoogleSignInButtonProps) {
  const { signIn, isLoaded } = useSignIn();

  const handleGoogleSignIn = async () => {
    if (!isLoaded) return;

    try {
      await signIn.authenticateWithRedirect({
        strategy: 'oauth_google',
        redirectUrl: '/dashboard',
        redirectUrlComplete: '/dashboard'
      });
    } catch (error) {
      console.error('Error signing in with Google:', error);
    }
  };

  // Default styles for each variant
  const variantStyles = {
    header: 'bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-400 text-white text-center px-4 py-2 rounded-lg font-bold duration-100',
    cta: 'w-full max-w-md mx-auto block bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 hover:from-purple-600 hover:via-indigo-600 hover:to-purple-600 text-white font-bold py-4 px-8 rounded-2xl transition-all duration-300 shadow-2xl hover:shadow-3xl transform hover:scale-105 text-lg disabled:opacity-50'
  };

  // Default text for each variant
  const defaultText = {
    header: 'Log In',
    cta: '🚀 Sign Up with Google'
  };

  const buttonText = defaultText[variant];
  const buttonClassName = variantStyles[variant];

  return (
    <button 
      onClick={handleGoogleSignIn}
      disabled={!isLoaded}
      className={buttonClassName}
    >
      {buttonText}
    </button>
  );
} 