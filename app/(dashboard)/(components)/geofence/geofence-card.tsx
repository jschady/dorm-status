'use client';

import React from 'react';
import { GeofenceCardProps } from '../../(lib)/types';
import { 
  MapPinIcon, 
  UserGroupIcon, 
  EllipsisVerticalIcon,
  StarIcon,
  ShareIcon,
  PencilSquareIcon,
  TrashIcon 
} from '@heroicons/react/24/outline';
import { useState } from 'react';

export function GeofenceCard({ geofence, onEdit, onDelete, onViewDetails, onShare }: GeofenceCardProps) {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [showInviteCode, setShowInviteCode] = useState(false);

  const isOwner = geofence.role === 'owner';
  const createdDate = new Date(geofence.created_at).toLocaleDateString();

  const copyInviteCode = async () => {
    try {
      await navigator.clipboard.writeText(geofence.invite_code);
      // You could add a toast notification here
    } catch (error) {
      console.error('Failed to copy invite code:', error);
    }
  };

  const copyInviteLink = async () => {
    const inviteUrl = `${window.location.origin}/join?invite=${geofence.invite_code}`;
    try {
      await navigator.clipboard.writeText(inviteUrl);
      // You could add a toast notification here
    } catch (error) {
      console.error('Failed to copy invite link:', error);
    }
  };

  const handleShare = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onShare) {
      onShare(geofence);
    }
  };

  return (
    <div 
      className="bg-white overflow-hidden shadow rounded-lg border border-gray-200 hover:border-indigo-300 hover:shadow-md transition-all duration-200 cursor-pointer relative"
      onClick={() => onViewDetails?.(geofence.id_geofence)}
    >
      {/* Card Header */}
      <div className="px-4 py-5 sm:p-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3 min-w-0 flex-1">
            <div className="flex-shrink-0">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                isOwner ? 'bg-indigo-100' : 'bg-green-100'
              }`}>
                {isOwner ? (
                  <StarIcon className="w-5 h-5 text-indigo-600" />
                ) : (
                  <MapPinIcon className="w-5 h-5 text-green-600" />
                )}
              </div>
            </div>
            
            <div className="min-w-0 flex-1">
              <h3 className="text-lg font-medium text-gray-900 truncate">
                {geofence.name}
              </h3>
              <div className="flex items-center text-sm text-gray-500 space-x-4">
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  isOwner 
                    ? 'bg-indigo-100 text-indigo-800' 
                    : 'bg-green-100 text-green-800'
                }`}>
                  {isOwner ? 'Owner' : 'Member'}
                </span>
                <span>Created {createdDate}</span>
              </div>
            </div>
          </div>

          {/* Share Button for Owners */}
          { isOwner && onShare && (
            <button
              onClick={handleShare}
              className="flex items-center gap-2 px-3 py-2 text-sm bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition-colors"
              title="Share invitation"
            >
              <ShareIcon className="h-4 w-4" />
              Share
            </button>
          )}
        </div>

        {/* Card Stats */}
        <div className="mt-4 flex items-center justify-between">
          <div className="flex items-center text-sm text-gray-500">
            <UserGroupIcon className="flex-shrink-0 mr-1.5 h-4 w-4" />
            <span>
              {geofence.member_count} {geofence.member_count === 1 ? 'member' : 'members'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
} 