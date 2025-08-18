'use client';

import React from 'react';
import { 
  UserIcon, 
  UserGroupIcon, 
  ClockIcon,
  StarIcon
} from '@heroicons/react/24/outline';
import { GeofenceMemberWithUser } from '../../(lib)/types';

interface MemberListProps {
  members: GeofenceMemberWithUser[];
  isLoading?: boolean;
  currentUserId?: string;
}

interface MemberCardProps {
  member: GeofenceMemberWithUser;
  isCurrentUser: boolean;
}

function MemberCard({ member, isCurrentUser }: MemberCardProps) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'IN_ROOM':
        return 'text-green-400 bg-green-400/10 border-green-400/20';
      case 'AWAY':
        return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
      default:
        return 'text-gray-400 bg-gray-400/10 border-gray-400/20';
    }
  };

  const getStatusText = (status: string) => {
    switch (status) {
      case 'IN_ROOM':
        return 'In Room';
      case 'AWAY':
        return 'Away';
      default:
        return 'Unknown';
    }
  };

  const formatLastUpdate = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  return (
    <div className={`bg-gray-700 rounded-lg p-4 transition-colors ${
      isCurrentUser ? 'ring-2 ring-indigo-500' : ''
    }`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-full flex items-center justify-center ${
            isCurrentUser ? 'bg-indigo-600' : 'bg-gray-600'
          }`}>
            <UserIcon className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-white font-medium">
                {member.users?.full_name || 'Unknown User'}
              </h3>
              {isCurrentUser && (
                <span className="text-xs bg-indigo-600 text-white px-2 py-1 rounded-full">
                  You
                </span>
              )}
              {member.role === 'owner' && (
                <StarIcon className="h-4 w-4 text-yellow-400" title="Owner" />
              )}
            </div>
            <p className="text-gray-400 text-sm capitalize">
              {member.role}
            </p>
          </div>
        </div>
        
        <div className={`px-3 py-1 rounded-full border text-sm font-medium ${getStatusColor(member.status)}`}>
          {getStatusText(member.status)}
        </div>
      </div>

      <div className="flex items-center justify-between text-xs text-gray-400">
        <div className="flex items-center gap-1">
          <ClockIcon className="h-3 w-3" />
          <span>Last update: {formatLastUpdate(member.last_updated)}</span>
        </div>
        
        {member.joined_at && (
          <span>
            Joined {formatLastUpdate(member.joined_at)}
          </span>
        )}
      </div>
    </div>
  );
}

export function MemberList({ members, isLoading = false, currentUserId }: MemberListProps) {
  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3 mb-4">
          <UserGroupIcon className="h-6 w-6 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">Members</h3>
        </div>
        
        {[...Array(3)].map((_, i) => (
          <div key={i} className="bg-gray-700 rounded-lg p-4 animate-pulse">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-full bg-gray-600"></div>
              <div className="flex-1">
                <div className="h-4 bg-gray-600 rounded w-24 mb-1"></div>
                <div className="h-3 bg-gray-600 rounded w-16"></div>
              </div>
              <div className="h-6 bg-gray-600 rounded-full w-16"></div>
            </div>
            <div className="h-3 bg-gray-600 rounded w-32"></div>
          </div>
        ))}
      </div>
    );
  }

  if (members.length === 0) {
    return (
      <div className="text-center py-8">
        <UserGroupIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
        <h3 className="text-lg font-semibold text-white mb-2">No members yet</h3>
        <p className="text-gray-400">
          Share your invitation link to get people to join!
        </p>
      </div>
    );
  }

  // Sort members: owner first, then by name
  const sortedMembers = [...members].sort((a, b) => {
    if (a.role === 'owner' && b.role !== 'owner') return -1;
    if (b.role === 'owner' && a.role !== 'owner') return 1;
    
    const nameA = a.users?.full_name || 'Unknown';
    const nameB = b.users?.full_name || 'Unknown';
    return nameA.localeCompare(nameB);
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <UserGroupIcon className="h-6 w-6 text-gray-400" />
          <h3 className="text-lg font-semibold text-white">Members</h3>
          <span className="bg-gray-600 text-gray-300 px-2 py-1 rounded-full text-sm">
            {members.length}
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {sortedMembers.map((member) => (
          <MemberCard
            key={`${member.id_geofence}-${member.id_user}`}
            member={member}
            isCurrentUser={member.id_user === currentUserId}
          />
        ))}
      </div>
    </div>
  );
} 