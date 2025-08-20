-- Tiger Dorm Database Schema (Final Version with Anti-Recursion RLS)

-- Enable UUID extension for generating UUIDs
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable Row Level Security
SET row_security = on;

-- =============================================================================
-- TABLES
-- =============================================================================

-- Users table - stores Clerk user data
CREATE TABLE users (
  id_user TEXT PRIMARY KEY, -- Clerk User ID
  email TEXT UNIQUE NOT NULL,
  full_name TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Geofences table - dorm room locations with ownership
CREATE TABLE geofences (
  id_geofence UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  id_user TEXT REFERENCES users(id_user) ON DELETE CASCADE,
  name TEXT NOT NULL,
  invite_code TEXT UNIQUE NOT NULL,
  center_latitude DECIMAL(10,8) NOT NULL,
  center_longitude DECIMAL(11,8) NOT NULL,
  radius_meters INTEGER NOT NULL DEFAULT 50,
  hysteresis_meters INTEGER NOT NULL DEFAULT 10,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Geofence members table - user membership in geofences with status
CREATE TABLE geofence_members (
  id_geofence UUID REFERENCES geofences(id_geofence) ON DELETE CASCADE,
  id_user TEXT REFERENCES users(id_user) ON DELETE CASCADE,
  role TEXT CHECK (role IN ('owner', 'member')) NOT NULL,
  status TEXT CHECK (status IN ('IN_ROOM', 'AWAY')) DEFAULT 'AWAY',
  last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_gps_update TIMESTAMP WITH TIME ZONE,
  joined_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  PRIMARY KEY (id_geofence, id_user)
);

-- Device mappings table - GPS device tracking for users (one device per user)
CREATE TABLE device_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id TEXT UNIQUE NOT NULL,
  id_user TEXT UNIQUE REFERENCES users(id_user) ON DELETE CASCADE, -- Unique constraint enforces one device per user
  enabled BOOLEAN DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  last_location_update TIMESTAMP WITH TIME ZONE
);

-- =============================================================================
-- INDEXES FOR PERFORMANCE
-- =============================================================================
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_geofences_owner ON geofences(id_user);
CREATE INDEX idx_geofences_invite_code ON geofences(invite_code);
CREATE INDEX idx_geofence_members_user ON geofence_members(id_user);
CREATE INDEX idx_geofence_members_geofence ON geofence_members(id_geofence);
CREATE INDEX idx_device_mappings_user ON device_mappings(id_user);
CREATE INDEX idx_device_mappings_device ON device_mappings(device_id);

-- =============================================================================
-- RLS POLICIES (Using Clerk JWT & Helper Function)
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE geofences ENABLE ROW LEVEL SECURITY;
ALTER TABLE geofence_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_mappings ENABLE ROW LEVEL SECURITY;

-- Users table policies
CREATE POLICY "Users can view their own record" ON users
  FOR SELECT USING (get_current_user_id() = id_user);

CREATE POLICY "Users can update their own record" ON users
  FOR UPDATE USING (get_current_user_id() = id_user);

-- Allow authenticated users to insert their own records
CREATE POLICY "Users can create their own record" ON users
  FOR INSERT WITH CHECK (get_current_user_id() = id_user);

-- Geofences table policies
CREATE POLICY "Users can view geofences they are a member of" ON geofences
  FOR SELECT USING (id_geofence IN (SELECT geofence_id FROM get_current_user_geofences()));

CREATE POLICY "Authenticated users can create geofences" ON geofences
  FOR INSERT WITH CHECK (id_user = get_current_user_id());

CREATE POLICY "Owners can update their geofences" ON geofences
  FOR UPDATE USING (id_user = get_current_user_id());

CREATE POLICY "Owners can delete their geofences" ON geofences
  FOR DELETE USING (id_user = get_current_user_id());

-- Geofence members table policies
CREATE POLICY "Members can view other members of the same geofence" ON geofence_members
  FOR SELECT USING (id_geofence IN (SELECT geofence_id FROM get_current_user_geofences()));
  
CREATE POLICY "Users can update their own member status" ON geofence_members
  FOR UPDATE USING (id_user = get_current_user_id());
  
CREATE POLICY "Owners can remove other members" ON geofence_members
  FOR DELETE USING (
    id_user != get_current_user_id() AND
    id_geofence IN (SELECT geofence_id FROM get_current_user_geofences() WHERE role = 'owner')
  );

CREATE POLICY "Members can leave a geofence" ON geofence_members
  FOR DELETE USING (id_user = get_current_user_id() AND role = 'member');

-- Allow authenticated users to join geofences
CREATE POLICY "Users can join geofences" ON geofence_members
  FOR INSERT WITH CHECK (id_user = get_current_user_id());

-- Device mappings table policies
CREATE POLICY "Users can manage their own device mappings" ON device_mappings
  FOR ALL USING (id_user = get_current_user_id());


-- =============================================================================
-- FUNCTIONS AND TRIGGERS
-- =============================================================================

-- Function to extract current user ID from Clerk JWT token
CREATE OR REPLACE FUNCTION get_current_user_id()
RETURNS TEXT AS $$
BEGIN
  -- Extract user ID from JWT token claims set by Supabase
  RETURN COALESCE(
    current_setting('request.jwt.claims', true)::json ->> 'sub',
    current_setting('request.jwt.claim.sub', true)
  );
EXCEPTION
  WHEN OTHERS THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to get geofences that the current user is a member of
CREATE OR REPLACE FUNCTION get_current_user_geofences()
RETURNS TABLE(geofence_id UUID, role TEXT) AS $$
DECLARE
  current_user_id TEXT;
BEGIN
  -- Get the current user ID
  current_user_id := get_current_user_id();
  
  -- Return empty if no user ID
  IF current_user_id IS NULL THEN
    RETURN;
  END IF;
  
  -- Return geofences where this user is a member
  RETURN QUERY
  SELECT gm.id_geofence, gm.role
  FROM geofence_members gm
  WHERE gm.id_user = current_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers for updated_at timestamps
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

CREATE TRIGGER update_geofences_updated_at BEFORE UPDATE ON geofences
    FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

-- Function to automatically add owner as member when geofence is created
CREATE OR REPLACE FUNCTION add_owner_as_member()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO geofence_members (id_geofence, id_user, role, status)
    VALUES (NEW.id_geofence, NEW.id_user, 'owner', 'AWAY');
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger to add owner as member
CREATE TRIGGER add_owner_as_member_trigger
    AFTER INSERT ON geofences
    FOR EACH ROW EXECUTE PROCEDURE add_owner_as_member();

-- =============================================================================
-- REALTIME SUBSCRIPTIONS
-- =============================================================================

ALTER publication supabase_realtime ADD TABLE geofence_members;
ALTER publication supabase_realtime ADD TABLE geofences;
ALTER publication supabase_realtime ADD TABLE device_mappings;