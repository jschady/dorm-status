// TypeScript definitions for the Tiger Dorm Dashboard application

// Member interface representing a dorm roommate
export interface Member {
  id_member: string;
  name: string;
  status: StatusKey;
  last_updated: string;
}

// Available status options for roommates
export type StatusKey = 'IN_ROOM' | 'STUDYING' | 'AT_GYM' | 'SLEEPING' | 'AWAY';

// Status option configuration interface
export interface StatusOption {
  text: string;
  icon: React.ComponentType;
  color: string;
}

// =============================================================================
// GEOFENCE SYSTEM TYPES (New for Epic-2)
// =============================================================================

// Core geofence interface matching database schema
export interface Geofence {
  id_geofence: string;
  id_user: string;
  name: string;
  invite_code: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  hysteresis_meters: number;
  created_at: string;
  updated_at: string;
}

// Geofence member interface matching database schema
export interface GeofenceMember {
  id_geofence: string;
  id_user: string;
  role: 'owner' | 'member';
  status: 'IN_ROOM' | 'AWAY';
  last_updated: string;
  last_gps_update?: string;
  joined_at: string;
}

// Extended geofence member with user details for display
export interface GeofenceMemberWithUser extends GeofenceMember {
  users?: {
    full_name: string;
    email: string;
  };
}

// User interface for authenticated users
export interface User {
  id_user: string;
  email: string;
  full_name?: string;
  created_at: string;
  updated_at: string;
}

// Geofence creation request interface
export interface CreateGeofenceRequest {
  name: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  hysteresis_meters: number;
}

// Geofence creation response interface
export interface CreateGeofenceResponse {
  id_geofence: string;
  name: string;
  invite_code: string;
  center_latitude: number;
  center_longitude: number;
  radius_meters: number;
  hysteresis_meters: number;
  created_at: string;
}

// Geofence list item for dashboard display
export interface GeofenceListItem {
  id_geofence: string;
  name: string;
  member_count: number;
  created_at: string;
  invite_code: string;
  role: 'owner' | 'member';
}

// Geofence with member details for detailed view
export interface GeofenceWithMembers extends Geofence {
  members: Array<{
    id_user: string;
    full_name?: string;
    email: string;
    role: 'owner' | 'member';
    status: 'IN_ROOM' | 'AWAY';
    last_updated: string;
    joined_at: string;
  }>;
}

// Database schema types for Supabase
export interface Database {
  public: {
    Tables: {
      users: {
        Row: User;
        Insert: Omit<User, 'created_at' | 'updated_at'> & { 
          created_at?: string; 
          updated_at?: string; 
        };
        Update: Partial<Omit<User, 'id_user'>>;
      };
      geofences: {
        Row: Geofence;
        Insert: Omit<Geofence, 'id_geofence' | 'created_at' | 'updated_at'> & {
          id_geofence?: string;
          created_at?: string;
          updated_at?: string;
        };
        Update: Partial<Omit<Geofence, 'id_geofence'>>;
      };
      geofence_members: {
        Row: GeofenceMember;
        Insert: Omit<GeofenceMember, 'last_updated' | 'joined_at'> & {
          last_updated?: string;
          joined_at?: string;
        };
        Update: Partial<Omit<GeofenceMember, 'id_geofence' | 'id_user'>>;
      };
      // Keep existing members table for backward compatibility
      members: {
        Row: Member;
        Insert: Omit<Member, 'id_member'> & { id_member?: string };
        Update: Partial<Omit<Member, 'id_member'>>;
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      [_ in never]: never;
    };
    Enums: {
      [_ in never]: never;
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
}

// Enhanced error handling types
export interface SupabaseError {
  message: string;
  details: string;
  hint?: string;
  code?: string;
}

export interface DatabaseResult<T> {
  data: T | null;
  error: SupabaseError | null;
}

// Connection status for real-time updates
export type ConnectionStatus = 'connecting' | 'connected' | 'disconnected';

// Supabase real-time payload types
export interface RealtimePayload<T> {
  eventType: 'INSERT' | 'UPDATE' | 'DELETE';
  new: T | null;
  old: T | null;
}

// =============================================================================
// COMPONENT PROP INTERFACES
// =============================================================================

// Legacy component props (preserved for backward compatibility)
export interface StatusCardProps {
  member: Member;
}

export interface StatusUpdateModalProps {
  currentUser: Member;
  onClose: () => void;
  onStatusUpdate: (statusKey: StatusKey) => Promise<void>;
  isUpdating: boolean;
}

export interface UserSelectionModalProps {
  members: Member[];
  onSelectUser: (member: Member) => void;
  onClose: () => void;
  isSwitchingUser?: boolean;
}

export interface IOSInstallModalProps {
  onClose: () => void;
}

// New geofence component props
export interface GeofenceCardProps {
  geofence: GeofenceListItem;
  onEdit?: (geofence: GeofenceListItem) => void;
  onDelete?: (geofenceId: string) => void;
  onViewDetails?: (geofenceId: string) => void;
  onShare?: (geofence: GeofenceListItem) => void;
}

export interface GeofenceListProps {
  geofences: GeofenceListItem[];
  isLoading?: boolean;
  onCreateNew?: () => void;
  onRefresh?: () => void;
  onShare?: (geofence: GeofenceListItem) => void;
}

export interface CreateGeofenceFormProps {
  onSubmit: (data: CreateGeofenceRequest) => Promise<void>;
  isLoading?: boolean;
  onCancel?: () => void;
}

export interface CreateGeofenceModalProps {
  isOpen: boolean;
  onClose: () => void;
  onGeofenceCreated?: (geofence: CreateGeofenceResponse) => void;
}

export interface GeofenceDetailsProps {
  geofence: GeofenceWithMembers;
  currentUserId: string;
  onStatusUpdate?: (status: 'IN_ROOM' | 'AWAY') => Promise<void>;
  onEditGeofence?: () => void;
  onDeleteGeofence?: () => void;
  onManageMembers?: () => void;
} 

// Invitation System Types (Epic 3)
export interface InviteValidationResponse {
  valid: boolean;
  geofence?: {
    id_geofence: string;
    name: string;
    owner_name: string;
    member_count: number;
    created_at: string;
  };
  error?: string;
}

export interface JoinGeofenceRequest {
  invite_code: string;
  id_user: string; // From Clerk auth
}

export interface JoinGeofenceResponse {
  success: boolean;
  geofence: {
    id_geofence: string;
    name: string;
    role: 'member';
  };
  message?: string;
}

export interface ShareableInvite {
  url: string;
  invite_code: string;
  qr_code?: string; // Base64 encoded QR code
  expires_at?: string; // Future enhancement
}

export interface InviteShareModalProps {
  isOpen: boolean;
  onClose: () => void;
  geofence: {
    id_geofence: string;
    name: string;
    invite_code: string;
  };
} 