'use client';

import { useSignIn, useSignUp } from '@clerk/nextjs';

interface GoogleSignInButtonProps {
  variant?: 'header' | 'cta';
  text?: string;
  className?: string;
  mode?: 'signin' | 'signup';
}

export default function GoogleSignInButton({ 
  variant = 'header', 
  text,
  className,
  mode = 'signin'
}: GoogleSignInButtonProps) {
  const { signIn, isLoaded: signInLoaded } = useSignIn();
  const { signUp, isLoaded: signUpLoaded } = useSignUp();

  const isLoaded = mode === 'signin' ? signInLoaded : signUpLoaded;

  const handleGoogleAuth = async () => {
    if (!isLoaded) return;

    try {
      if (mode === 'signup') {
        if (!signUp) return;
        await signUp.authenticateWithRedirect({
          strategy: 'oauth_google',
          redirectUrl: '/dashboard',
          redirectUrlComplete: '/dashboard'
        });
      } else {
        if (!signIn) return;
        await signIn.authenticateWithRedirect({
          strategy: 'oauth_google',
          redirectUrl: '/dashboard',
          redirectUrlComplete: '/dashboard'
        });
      }
    } catch (error) {
      console.error(`Error ${mode === 'signup' ? 'signing up' : 'signing in'} with Google:`, error);
    }
  };

  // Default styles for each variant
  const variantStyles = {
    header: 'bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-400 text-white text-center px-4 py-2 rounded-lg font-bold duration-100',
    cta: 'w-full max-w-md mx-auto block bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-600 hover:from-purple-600 hover:via-indigo-600 hover:to-purple-600 text-white font-bold py-4 px-8 rounded-2xl transition-all duration-300 shadow-2xl hover:shadow-3xl transform hover:scale-105 active:scale-100 text-lg disabled:opacity-50'
  };

  // Default text for each variant and mode
  const defaultText = {
    header: mode === 'signup' ? 'Sign Up' : 'Log In',
    cta: mode === 'signup' ? '🚀 Sign Up with Google' : '🔑 Sign In with Google'
  };

  const buttonText = text || defaultText[variant];
  const buttonClassName = className || variantStyles[variant];

  return (
    <button 
      onClick={handleGoogleAuth}
      disabled={!isLoaded}
      className={buttonClassName}
    >
      {buttonText}
    </button>
  );
} 