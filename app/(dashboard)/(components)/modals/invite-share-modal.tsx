'use client';

import React, { useState, useEffect } from 'react';
import { 
  XMarkIcon, 
  ClipboardDocumentIcon, 
  CheckIcon,
  QrCodeIcon,
  ShareIcon
} from '@heroicons/react/24/outline';

interface InviteShareModalProps {
  isOpen: boolean;
  onClose: () => void;
  geofence: {
    id_geofence: string;
    name: string;
    invite_code: string;
  };
}

export function InviteShareModal({ isOpen, onClose, geofence }: InviteShareModalProps) {
  const [copied, setCopied] = useState(false);
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [isGeneratingQR, setIsGeneratingQR] = useState(false);
  const [inviteUrl, setInviteUrl] = useState('');

  // Generate the shareable invitation URL on client-side only
  useEffect(() => {
    if (typeof window !== 'undefined') {
      const url = `${window.location.origin}/join?invite=${geofence.invite_code}&name=${encodeURIComponent(geofence.name)}`;
      setInviteUrl(url);
    }
  }, [geofence.invite_code, geofence.name]);

  // Copy to clipboard functionality
  const handleCopyUrl = async () => {
    if (!inviteUrl) return;
    
    try {
      await navigator.clipboard.writeText(inviteUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (error) {
      console.error('Failed to copy to clipboard:', error);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = inviteUrl;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  // Generate QR code
  const generateQRCode = async () => {
    setIsGeneratingQR(true);
    try {
      // Use a QR code API service (qr-server.com is free and reliable)
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(inviteUrl)}`;
      setQrCode(qrUrl);
    } catch (error) {
      console.error('Failed to generate QR code:', error);
    } finally {
      setIsGeneratingQR(false);
    }
  };

  // Generate QR code when modal opens and URL is ready
  useEffect(() => {
    if (isOpen && inviteUrl) {
      generateQRCode();
    } else {
      setQrCode(null);
      setCopied(false);
    }
  }, [isOpen, inviteUrl]);

  // Share via Web Share API (mobile) - TODO: Add back when TypeScript issue is resolved
  const handleNativeShare = async () => {
    console.log('Native sharing not implemented yet');
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="fixed inset-0 bg-black/60" onClick={onClose} />
      <div className="relative min-h-screen flex items-center justify-center p-4">
        <div className="relative bg-gray-800 rounded-2xl w-full max-w-md p-6 shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-2xl font-bold text-white">Share Geofence</h2>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-white transition-colors"
            >
              <XMarkIcon className="h-6 w-6" />
            </button>
          </div>

          {/* Geofence Info */}
          <div className="bg-gray-700 rounded-lg p-4 mb-6">
            <h3 className="text-lg font-semibold text-white mb-2">{geofence.name}</h3>
            <p className="text-gray-300 text-sm">
              Invite code: <span className="font-mono text-indigo-400">{geofence.invite_code}</span>
            </p>
          </div>

          {/* QR Code */}
          <div className="text-center mb-6">
            <div className="bg-white rounded-lg p-4 inline-block">
              {isGeneratingQR ? (
                <div className="w-48 h-48 flex items-center justify-center">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
                </div>
              ) : qrCode ? (
                <img 
                  src={qrCode} 
                  alt="QR Code for invitation"
                  className="w-48 h-48"
                />
              ) : (
                <div className="w-48 h-48 flex items-center justify-center text-gray-500">
                  <QrCodeIcon className="h-12 w-12" />
                </div>
              )}
            </div>
            <p className="text-gray-400 text-sm mt-2">Scan to join</p>
          </div>

          {/* URL Display */}
          <div className="bg-gray-700 rounded-lg p-3 mb-4">
            <div className="flex items-center justify-between">
              <input
                type="text"
                value={inviteUrl || 'Generating invitation URL...'}
                readOnly
                className="bg-transparent text-white text-sm flex-1 mr-2 truncate"
                placeholder="Generating invitation URL..."
              />
              <button
                onClick={handleCopyUrl}
                disabled={!inviteUrl}
                className="text-indigo-400 hover:text-indigo-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {copied ? (
                  <CheckIcon className="h-5 w-5 text-green-400" />
                ) : (
                  <ClipboardDocumentIcon className="h-5 w-5" />
                )}
              </button>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3">
            <button
              onClick={handleCopyUrl}
              disabled={!inviteUrl}
              className={`flex-1 flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                copied 
                  ? 'bg-green-600 text-white'
                  : 'bg-indigo-600 hover:bg-indigo-700 text-white'
              }`}
            >
              {copied ? (
                <>
                  <CheckIcon className="h-5 w-5" />
                  Copied!
                </>
              ) : (
                <>
                  <ClipboardDocumentIcon className="h-5 w-5" />
                  Copy Link
                </>
              )}
            </button>
          </div>

          {/* Instructions */}
          <div className="mt-6 text-center text-gray-400 text-sm">
            Share this link or QR code with friends to invite them to join your geofence
          </div>
        </div>
      </div>
    </div>
  );
} 