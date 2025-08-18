# Tiger Dorm - Supabase Database Setup Guide

## 🎉 EPIC1-002 Progress: Supabase Database Integration

This guide will help you set up the complete Supabase database integration for Tiger Dorm's multi-user authentication system.

### ✅ What's Been Implemented

- **Complete Database Schema**: Users, geofences, members, and device mappings
- **Row Level Security**: Multi-user data isolation policies  
- **Clerk-Supabase Integration**: JWT token authentication
- **Webhook System**: Automatic user lifecycle synchronization
- **Database Service Layer**: Type-safe operations with RLS enforcement
- **Admin Database Service**: Webhook and system-level operations

## 🔧 Prerequisites

Before starting, ensure you have:
- ✅ **EPIC1-001 Complete**: Authentication foundation must be working
- ✅ **Clerk Account**: With publishable and secret keys configured
- ✅ **Supabase Account**: Free tier is sufficient for development

## 📋 Step 1: Create Supabase Project

1. **Sign up at [Supabase](https://supabase.com)**
2. **Create a new project**:
   - Organization: Choose or create
   - Project Name: `tiger-dorm` (or your preference)
   - Database Password: Generate a secure password
   - Region: Choose closest to your users

3. **Wait for project setup** (usually 2-3 minutes)

## 🗄️ Step 2: Set Up Database Schema

### Option A: Using SQL Editor (Recommended)

1. **Go to SQL Editor** in Supabase dashboard
2. **Create a new query**
3. **Copy and paste** the complete schema from [`database/schema.sql`](database/schema.sql)
4. **Run the query** - this will create:
   - All tables with proper relationships
   - Row Level Security policies
   - Indexes for performance  
   - Triggers and functions
   - Real-time subscriptions

### Option B: Using Table Editor

If you prefer the GUI approach:
1. Go to **Table Editor**
2. Create tables manually following the schema in [`database/schema.sql`](database/schema.sql)
3. Don't forget to enable RLS and create policies!

## 🔑 Step 3: Configure Environment Variables

Add these to your `.env.local` file:

```env
# Existing Clerk variables...
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...

# Supabase Configuration
NEXT_PUBLIC_SUPABASE_URL=https://your-project-ref.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Service Role Key (KEEP SECRET - server-side only!)
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Webhook Configuration (we'll set this up next)
WEBHOOK_SECRET=whsec_...
```

### 🔍 Where to Find Supabase Keys

1. **Go to Project Settings** → **API**
2. **Copy these values**:
   - **Project URL** → `NEXT_PUBLIC_SUPABASE_URL`
   - **anon public key** → `NEXT_PUBLIC_SUPABASE_ANON_KEY`  
   - **service_role secret key** → `SUPABASE_SERVICE_ROLE_KEY`

⚠️ **Security Warning**: Never commit the service role key to version control!

## 🔗 Step 4: Set Up Clerk JWT Integration

### Configure Clerk JWT Template

1. **Go to Clerk Dashboard** → **JWT Templates**
2. **Create new template**:
   - Name: `supabase`
   - Template: Select "Supabase" from presets
3. **Save the template**

### Verify Integration

The integration is already coded! The system will:
- ✅ Automatically include Clerk JWT tokens in Supabase requests
- ✅ Enforce Row Level Security based on authenticated user
- ✅ Handle token refresh automatically

## 🔄 Step 5: Set Up Clerk Webhooks

### Create Webhook in Clerk

1. **Go to Clerk Dashboard** → **Webhooks**
2. **Create Endpoint**:
   - **Endpoint URL**: `https://yourdomain.com/api/webhooks/clerk`
   - **Events**: Select these events:
     - ✅ `user.created`
     - ✅ `user.updated`  
     - ✅ `user.deleted`

3. **Copy the Signing Secret** → Add to `.env.local` as `WEBHOOK_SECRET`

### For Development (Using ngrok)

```bash
# Install ngrok globally
npm install -g ngrok

# Start your dev server
npm run dev

# In another terminal, expose localhost:3000
ngrok http 3000

# Use the ngrok URL for webhook endpoint
# Example: https://abc123.ngrok.io/api/webhooks/clerk
```

## 🧪 Step 6: Test the Integration

### 1. Start Development Server
```bash
npm run dev
```

### 2. Test User Creation
1. **Sign up a new user** via your app (`http://localhost:3000`)
2. **Check Supabase** → **Table Editor** → **users** table
3. **Verify** the user record was created automatically

### 3. Test Authentication
```bash
# Check webhook logs
curl -X POST http://localhost:3000/api/webhooks/clerk \
  -H "Content-Type: application/json" \
  -d '{"type": "test"}'
```

### 4. Test Database Operations
The system includes a complete database service layer:
- User profile management
- Geofence CRUD operations  
- Member status updates
- Real-time subscriptions

## 📊 Database Tables Overview

| Table | Purpose | Key Features |
|-------|---------|-------------|
| `users` | Clerk user data | Synced via webhooks |
| `geofences` | Dorm room locations | Owner-based with invite codes |
| `geofence_members` | User memberships | Role-based (owner/member) |
| `device_mappings` | GPS device tracking | For future location features |

## 🔒 Row Level Security (RLS) Policies

The system enforces strict data isolation:

### Users
- ✅ Users can only see/edit their own profile
- ✅ Creation/deletion handled by webhooks only

### Geofences  
- ✅ Users can see geofences they own or are members of
- ✅ Only owners can modify geofence settings
- ✅ Invite codes are unique and secure

### Members
- ✅ Users can see members of geofences they belong to
- ✅ Users can only update their own status
- ✅ Owners have additional management permissions

## 🛠️ Development Tools

### Database Service Usage

```typescript
'use client';
import { useDatabase } from '@/app/(dashboard)/(lib)/database-client';

export function MyComponent() {
  const db = useDatabase();
  
  useEffect(() => {
    // Get user's geofences
    const loadGeofences = async () => {
      const geofences = await db.getUserGeofences();
      console.log('User geofences:', geofences);
    };
    
    loadGeofences();
  }, [db]);
}
```

### Admin Operations (Server-side)

```typescript
// app/api/my-route/route.ts
import { adminDb } from '@/app/(dashboard)/(lib)/supabase-admin';

export async function GET() {
  // Admin operations bypass RLS
  const user = await adminDb.getUserById('user_123');
  return Response.json(user);
}
```

## 🚨 Troubleshooting

### Webhook Not Working?
- ✅ Check webhook URL is accessible
- ✅ Verify signing secret matches
- ✅ Check server logs for errors
- ✅ Test with ngrok for local development

### RLS Blocking Queries?
- ✅ Ensure user is properly authenticated
- ✅ Check JWT token is included in requests
- ✅ Verify RLS policies are correct
- ✅ Use service role client for admin operations

### Build Failing?
- ✅ All environment variables are set
- ✅ Supabase keys are correct
- ✅ No TypeScript errors in database files

### Database Connection Issues?
- ✅ Check Supabase project is running
- ✅ Verify database URL and keys
- ✅ Check network connectivity
- ✅ Review Supabase dashboard for errors

## 🎯 What's Next?

With EPIC1-002 complete, you now have:
- ✅ **Secure Database Layer**: Multi-user data isolation
- ✅ **User Lifecycle Management**: Automatic sync with Clerk
- ✅ **Type-Safe Operations**: Full TypeScript support
- ✅ **Real-Time Ready**: Foundation for status updates
- ✅ **Geofence System**: Ready for location features

### Next Epic: Enhanced Dashboard
The next story will enhance the dashboard to:
- Display user profile information
- Show geofence management interface
- Enable basic status updates
- Prepare for real-time features

## 📁 Files Created

- `database/schema.sql` - Complete database schema
- `app/(dashboard)/(lib)/supabase-admin.ts` - Admin database service
- `app/(dashboard)/(lib)/database-client.ts` - Client database service
- `app/api/webhooks/clerk/route.ts` - Webhook handler
- `SUPABASE-SETUP.md` - This setup guide

## 🔐 Security Checklist

- [ ] Service role key is in `.env.local` only (not committed)
- [ ] Webhook signing secret is properly configured
- [ ] RLS policies are enabled on all tables
- [ ] JWT template is configured in Clerk
- [ ] Database schema matches the architecture spec
- [ ] All foreign key constraints are in place
- [ ] Test user can only see their own data 