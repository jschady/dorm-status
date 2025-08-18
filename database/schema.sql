-- Tiger Dorm Database Schema
-- Multi-user dorm status tracking with geofences and real-time updates

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

-- Users table indexes
CREATE INDEX idx_users_email ON users(email);

-- Geofences table indexes
CREATE INDEX idx_geofences_owner ON geofences(id_user);
CREATE INDEX idx_geofences_invite_code ON geofences(invite_code);

-- Geofence members table indexes
CREATE INDEX idx_geofence_members_user ON geofence_members(id_user);
CREATE INDEX idx_geofence_members_geofence ON geofence_members(id_geofence);
CREATE INDEX idx_geofence_members_last_updated ON geofence_members(last_updated);

-- Device mappings table indexes
CREATE INDEX idx_device_mappings_user ON device_mappings(id_user);
CREATE INDEX idx_device_mappings_device ON device_mappings(device_id);

-- =============================================================================
-- ROW LEVEL SECURITY POLICIES
-- =============================================================================

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE geofences ENABLE ROW LEVEL SECURITY;
ALTER TABLE geofence_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_mappings ENABLE ROW LEVEL SECURITY;

-- Users table policies
CREATE POLICY "Users can view own record" ON users
  FOR SELECT USING (auth.uid()::text = id_user);

CREATE POLICY "Users can update own record" ON users
  FOR UPDATE USING (auth.uid()::text = id_user);

-- Note: User creation/deletion is handled by webhooks with service role

-- Geofences table policies
CREATE POLICY "Users can view accessible geofences" ON geofences
  FOR SELECT USING (
    id_user = auth.uid()::text OR
    id_geofence IN (
      SELECT id_geofence FROM geofence_members
      WHERE id_user = auth.uid()::text
    )
  );

CREATE POLICY "Users can create own geofences" ON geofences
  FOR INSERT WITH CHECK (id_user = auth.uid()::text);

CREATE POLICY "Owners can update geofences" ON geofences
  FOR UPDATE USING (id_user = auth.uid()::text);

CREATE POLICY "Owners can delete geofences" ON geofences
  FOR DELETE USING (id_user = auth.uid()::text);

-- Geofence members table policies
CREATE POLICY "Members can view geofence members" ON geofence_members
  FOR SELECT USING (
    id_geofence IN (
      SELECT id_geofence FROM geofence_members AS gm2
      WHERE gm2.id_user = auth.uid()::text
    )
  );


CREATE POLICY "Users can update own status" ON geofence_members
  FOR UPDATE USING (id_user = auth.uid()::text);

-- Owners can manage members (handled by service role for complex operations)
CREATE POLICY "Service role can manage members" ON geofence_members
  FOR ALL USING (auth.role() = 'service_role');

-- Device mappings table policies
CREATE POLICY "Users can view own devices" ON device_mappings
  FOR SELECT USING (id_user = auth.uid()::text);

CREATE POLICY "Users can manage own devices" ON device_mappings
  FOR ALL USING (id_user = auth.uid()::text);

-- =============================================================================
-- FUNCTIONS AND TRIGGERS
-- =============================================================================

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
    INSERT INTO geofence_members (id_geofence, id_user, role)
    VALUES (NEW.id_geofence, NEW.id_user, 'owner');
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

-- Enable realtime for status updates
ALTER publication supabase_realtime ADD TABLE geofence_members;
ALTER publication supabase_realtime ADD TABLE geofences;
ALTER publication supabase_realtime ADD TABLE device_mappings;