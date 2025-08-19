'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams } from 'next/navigation';
import { useUser, SignInButton } from '@clerk/nextjs';
import { 
  MapPinIcon, 
  UserGroupIcon, 
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ArrowRightIcon
} from '@heroicons/react/24/outline';
import Link from 'next/link';
import { InviteValidationResponse } from '../(dashboard)/(lib)/types';
import { joinGeofence, validateInvite } from '../(dashboard)/(lib)/supabase/geofences';

function JoinPageContent() {
  const searchParams = useSearchParams();
  const { user, isLoaded: userLoaded } = useUser();
  
  const inviteCode = searchParams.get('invite');
  const geofenceName = searchParams.get('name'); // Optional for better UX
  
  const [validationData, setValidationData] = useState<InviteValidationResponse | null>(null);
  const [isValidating, setIsValidating] = useState(false);
  const [isJoining, setIsJoining] = useState(false);
  const [joinSuccess, setJoinSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Validate invite code
  useEffect(() => {
    if (inviteCode && userLoaded) {
      validateInviteCode(inviteCode);
    }
  }, [inviteCode, userLoaded]);

  const validateInviteCode = async (code: string) => {
    setIsValidating(true);
    setError(null);
    
    try {
      // Use the new server action to validate the invite
      const result = await validateInvite(code);
      
      if (result.success) {
        setValidationData(result.data);
        if (!result.data.valid) {
          setError(result.data.error || 'Invalid or expired invitation code');
        }
      } else {
        setError(result.error || 'Failed to validate invitation. Please try again.');
      }
    } catch (error) {
      console.error('Failed to validate invite:', error);
      setError('Failed to validate invitation. Please try again.');
    } finally {
      setIsValidating(false);
    }
  };

  const handleJoin = async () => {
    if (!user || !inviteCode) return;
    
    setIsJoining(true);
    setError(null);
    
    try {
      // Call server action
      const result = await joinGeofence(inviteCode);
      
      if (result.success) {
        setJoinSuccess(true);
        // Redirect to dashboard after a short delay
        setTimeout(() => {
          window.location.href = '/dashboard';
        }, 2000);
      } else {
        setError(result.error);
      }
    } catch (error) {
      console.error('Failed to join geofence:', error);
      setError('Failed to join geofence. Please try again.');
    } finally {
      setIsJoining(false);
    }
  };

  // Show loading while user auth is loading
  if (!userLoaded) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
      </div>
    );
  }

  // No invite code provided
  if (!inviteCode) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl p-8 max-w-md w-full text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-yellow-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-4">Invalid Invitation Link</h1>
          <p className="text-gray-400 mb-6">
            This invitation link appears to be incomplete or invalid.
          </p>
          <Link
            href="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition-colors"
          >
            Go Home
            <ArrowRightIcon className="h-4 w-4" />
          </Link>
        </div>
      </div>
    );
  }

  // Show success state
  if (joinSuccess) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
        <div className="bg-gray-800 rounded-2xl p-8 max-w-md w-full text-center">
          <CheckCircleIcon className="h-12 w-12 text-green-400 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-4">Welcome to the Dorm!</h1>
          <p className="text-gray-400 mb-6">
            You've successfully joined {validationData?.geofence?.name}. Redirecting to your dashboard...
          </p>
          <div className="flex items-center justify-center">
            <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-indigo-500"></div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-4">
      <div className="bg-gray-800 rounded-2xl p-8 max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-white mb-2">Join Geofence</h1>
          <p className="text-gray-400">
            You've been invited to join {geofenceName || 'a geofence'}
          </p>
        </div>

        {/* Validation Loading */}
        {isValidating && (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500 mx-auto mb-4"></div>
            <p className="text-gray-400">Validating invitation...</p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-3">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-400 flex-shrink-0" />
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Geofence Preview */}
        {validationData?.valid && validationData.geofence && (
          <div className="bg-gray-700 rounded-lg p-6 mb-6">
            <div className="flex items-start gap-4">
              <div className="bg-indigo-600 rounded-lg p-3">
                <MapPinIcon className="h-6 w-6 text-white" />
              </div>
              <div className="flex-1">
                <h3 className="text-lg font-semibold text-white mb-2">
                  {validationData.geofence.name}
                </h3>
                <div className="space-y-2 text-sm text-gray-300">
                  <div className="flex items-center gap-2">
                    <UserGroupIcon className="h-4 w-4" />
                    <span>{validationData.geofence.member_count} members</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span>Owner:</span>
                    <span className="text-indigo-400">{validationData.geofence.owner_name}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Authentication & Join Flow */}
        {!user ? (
          /* User needs to sign in */
          <div className="text-center">
            <p className="text-gray-400 mb-6">
              Please sign in to join this geofence
            </p>
            <SignInButton mode="modal">
              <button className="w-full flex items-center justify-center gap-2 py-3 px-6 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-lg transition-colors">
                Sign In to Join
                <ArrowRightIcon className="h-4 w-4" />
              </button>
            </SignInButton>
          </div>
        ) : validationData?.valid ? (
          /* User is authenticated and invite is valid */
          <div className="space-y-4">
            <button
              onClick={handleJoin}
              disabled={isJoining}
              className={`w-full flex items-center justify-center gap-2 py-3 px-6 font-semibold rounded-lg transition-colors ${
                isJoining
                  ? 'bg-gray-600 cursor-not-allowed text-gray-300'
                  : 'bg-green-600 hover:bg-green-700 text-white'
              }`}
            >
              {isJoining ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
                  Joining...
                </>
              ) : (
                <>
                  <CheckCircleIcon className="h-5 w-5" />
                  Join {validationData.geofence?.name}
                </>
              )}
            </button>
            
            <Link
              href="/dashboard"
              className="block w-full text-center py-3 px-6 text-gray-400 hover:text-white font-semibold transition-colors"
            >
              Go to Dashboard Instead
            </Link>
          </div>
        ) : (
          /* Show nothing while validating or if there's an error */
          !isValidating && (
            <div className="text-center">
              <Link
                href="/"
                className="inline-flex items-center gap-2 px-6 py-3 bg-gray-600 hover:bg-gray-700 text-white font-semibold rounded-lg transition-colors"
              >
                Go Home
                <ArrowRightIcon className="h-4 w-4" />
              </Link>
            </div>
          )
        )}
      </div>
    </div>
  );
}

export default function JoinPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
      </div>
    }>
      <JoinPageContent />
    </Suspense>
  );
} 