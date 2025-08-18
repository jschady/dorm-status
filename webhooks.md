# Clerk Webhooks for Tiger Dorm

This document outlines all the Clerk webhooks required for syncing user data between Clerk's authentication service and our Supabase database.

## Overview

Clerk webhooks are essential for maintaining data consistency between Clerk's authentication service and our Supabase database. When users perform actions in Clerk (sign up, update profile, delete account), we need to mirror these changes in our `users` table and handle cascading effects on related data.

## Webhook Endpoint URL

The Clerk webhooks will hit this endpoint in your Next.js application:

**Development**: `http://localhost:3000/api/webhooks/clerk` (via ngrok)
**Production**: `https://yourdomain.com/api/webhooks/clerk`

## Required Dependencies

```bash
npm install svix
```

## Environment Variables

Add to your `.env.local`:

```env
WEBHOOK_SECRET=whsec_your_webhook_signing_secret_from_clerk
```

## Webhook Endpoint Structure

Create the following file in your Next.js project to handle incoming webhooks:

**File Path**: `app/api/webhooks/clerk/route.ts`
**URL Route**: `/api/webhooks/clerk`

```typescript
import { Webhook } from 'svix'
import { headers } from 'next/headers'
import { WebhookEvent } from '@clerk/nextjs/server'
import { createServiceRoleClient } from '@/lib/supabase-admin'

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET

export async function POST(req: Request) {
  if (!WEBHOOK_SECRET) {
    throw new Error('Please add WEBHOOK_SECRET from Clerk Dashboard to .env.local')
  }

  // Get headers
  const headerPayload = headers()
  const svix_id = headerPayload.get('svix-id')
  const svix_timestamp = headerPayload.get('svix-timestamp')
  const svix_signature = headerPayload.get('svix-signature')

  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response('Error: Missing svix headers', { status: 400 })
  }

  // Get body
  const payload = await req.json()
  const body = JSON.stringify(payload)

  // Verify webhook
  const wh = new Webhook(WEBHOOK_SECRET)
  let evt: WebhookEvent

  try {
    evt = wh.verify(body, {
      'svix-id': svix_id,
      'svix-timestamp': svix_timestamp,
      'svix-signature': svix_signature,
    }) as WebhookEvent
  } catch (err) {
    console.error('Error verifying webhook:', err)
    return new Response('Error: Verification failed', { status: 400 })
  }

  // Handle events
  try {
    switch (evt.type) {
      case 'user.created':
        await handleUserCreated(evt)
        break
      case 'user.updated':
        await handleUserUpdated(evt)
        break
      case 'user.deleted':
        await handleUserDeleted(evt)
        break
      default:
        console.log(`Unhandled event type: ${evt.type}`)
    }
  } catch (error) {
    console.error('Error processing webhook:', error)
    return new Response('Error: Processing failed', { status: 500 })
  }

  return new Response('OK', { status: 200 })
}
```

## Webhook Event Handlers

### 1. User Created (`user.created`)

**Purpose**: Create a new user record in Supabase when someone signs up via Clerk.

**Triggered When**:
- User signs up with email/password
- User signs up via OAuth (Google, GitHub, etc.)
- Admin creates a user in Clerk Dashboard

**Handler Implementation**:

```typescript
async function handleUserCreated(evt: WebhookEvent) {
  const { id, email_addresses, first_name, last_name } = evt.data
  
  const primaryEmail = email_addresses.find(email => email.id === evt.data.primary_email_address_id)?.email_address
  
  if (!primaryEmail) {
    throw new Error('No primary email address found')
  }

  const supabase = createServiceRoleClient()
  
  const { error } = await supabase
    .from('users')
    .insert({
      id_user: id,
      email: primaryEmail,
      full_name: `${first_name || ''} ${last_name || ''}`.trim() || null,
    })

  if (error) {
    console.error('Error creating user:', error)
    throw error
  }

  console.log(`User created: ${id} (${primaryEmail})`)
}
```

**Database Changes**:
- ✅ Inserts new record in `users` table
- ✅ Sets `id_user` to Clerk user ID
- ✅ Stores primary email address
- ✅ Combines first_name + last_name into full_name

### 2. User Updated (`user.updated`)

**Purpose**: Update user information when profile changes are made in Clerk.

**Triggered When**:
- User updates their profile (name, email)
- Admin updates user details in Clerk Dashboard
- Email address verification status changes

**Handler Implementation**:

```typescript
async function handleUserUpdated(evt: WebhookEvent) {
  const { id, email_addresses, first_name, last_name } = evt.data
  
  const primaryEmail = email_addresses.find(email => email.id === evt.data.primary_email_address_id)?.email_address
  
  if (!primaryEmail) {
    throw new Error('No primary email address found')
  }

  const supabase = createServiceRoleClient()
  
  const { error } = await supabase
    .from('users')
    .update({
      email: primaryEmail,
      full_name: `${first_name || ''} ${last_name || ''}`.trim() || null,
      updated_at: new Date().toISOString(),
    })
    .eq('id_user', id)

  if (error) {
    console.error('Error updating user:', error)
    throw error
  }

  console.log(`User updated: ${id} (${primaryEmail})`)
}
```

**Database Changes**:
- ✅ Updates email if changed
- ✅ Updates full_name if changed
- ✅ Updates updated_at timestamp

### 3. User Deleted (`user.deleted`)

**Purpose**: Clean up all user-related data when a user account is deleted.

**Triggered When**:
- User deletes their own account
- Admin deletes user in Clerk Dashboard
- Account deletion via API

**Handler Implementation**:

```typescript
async function handleUserDeleted(evt: WebhookEvent) {
  const { id } = evt.data
  
  const supabase = createServiceRoleClient()

  // Start a transaction-like cleanup process
  try {
    // 1. Delete device mappings
    await supabase
      .from('device_mappings')
      .delete()
      .eq('id_user', id)

    // 2. Delete geofence memberships
    await supabase
      .from('geofence_members')
      .delete()
      .eq('id_user', id)

    // 3. Handle owned geofences
    const { data: ownedGeofences } = await supabase
      .from('geofences')
      .select('id_geofence')
      .eq('id_user', id)

    if (ownedGeofences && ownedGeofences.length > 0) {
      // Delete all members from owned geofences
      for (const geofence of ownedGeofences) {
        await supabase
          .from('geofence_members')
          .delete()
          .eq('id_geofence', geofence.id_geofence)
      }

      // Delete the geofences themselves
      await supabase
        .from('geofences')
        .delete()
        .eq('id_user', id)
    }

    // 4. Finally, delete the user record
    await supabase
      .from('users')
      .delete()
      .eq('id_user', id)

    console.log(`User and all related data deleted: ${id}`)
  } catch (error) {
    console.error('Error during user deletion cleanup:', error)
    throw error
  }
}
```

**Database Changes**:
- 🗑️ Deletes from `device_mappings` where `id_user` matches
- 🗑️ Deletes from `geofence_members` where `id_user` matches  
- 🗑️ Deletes from `geofences` where `id_user` matches (owned geofences)
- 🗑️ Deletes all members from owned geofences
- 🗑️ Deletes from `users` where `id_user` matches

## Supabase Admin Client

Create `lib/supabase-admin.ts` for service role access:

```typescript
import { createClient } from '@supabase/supabase-js'

export function createServiceRoleClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!, // Note: Service role key, not anon key
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  )
}
```

**Required Environment Variable**:
```env
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key_from_supabase
```

## Webhook Configuration in Clerk Dashboard

### Setup Steps:

1. **Navigate to Webhooks**:
   - Go to Clerk Dashboard → Configure → Webhooks
   - Click "Create Webhook"

2. **Configure Endpoint**:
   - **Endpoint URL**: 
     - **Production**: `https://yourdomain.com/api/webhooks/clerk`
     - **Development**: Use ngrok tunnel URL like `https://abc123.ngrok-free.app/api/webhooks/clerk`
   - **Description**: "Sync user data to Supabase"

3. **Select Events**:
   - ✅ `user.created`
   - ✅ `user.updated` 
   - ✅ `user.deleted`

4. **Copy Signing Secret**:
   - Save the `whsec_...` signing secret to your `.env.local`

## Error Handling & Monitoring

### Retry Logic
Clerk uses Svix for webhook delivery with automatic retries:
- **Initial delivery**: Immediate
- **Retry schedule**: Exponential backoff
- **Max attempts**: 5 attempts over 5 days
- **Timeout**: 15 seconds per attempt

### Monitoring Webhooks
1. **Clerk Dashboard**: View webhook delivery logs and failures
2. **Application Logs**: Monitor console outputs and errors
3. **Supabase Logs**: Check for database constraint violations

### Common Failure Scenarios

**Scenario 1: Duplicate User Creation**
```typescript
// Handle race conditions
const { error } = await supabase
  .from('users')
  .insert({
    id_user: id,
    email: primaryEmail,
    full_name: fullName,
  })

if (error && error.code === '23505') { // Unique violation
  console.log(`User ${id} already exists, skipping creation`)
  return // Don't throw error for duplicates
}
```

**Scenario 2: Orphaned Data Cleanup**
```typescript
// Periodic cleanup job (separate from webhooks)
async function cleanupOrphanedData() {
  const supabase = createServiceRoleClient()
  
  // Find geofence_members without corresponding users
  const { data } = await supabase
    .from('geofence_members')
    .select('id_user')
    .not('id_user', 'in', `(SELECT id_user FROM users)`)
  
  // Delete orphaned records
  if (data && data.length > 0) {
    const orphanedUserIds = data.map(row => row.id_user)
    await supabase
      .from('geofence_members')
      .delete()
      .in('id_user', orphanedUserIds)
  }
}
```

## Testing Webhooks

### Local Development with ngrok

1. **Install ngrok**: `npm install -g ngrok`
2. **Start your dev server**: `npm run dev`
3. **Expose localhost**: `ngrok http 3000`
4. **Use ngrok URL**: `https://abc123.ngrok.io/api/webhooks/clerk`

### Test Cases

**Test User Creation**:
1. Sign up a new user in your app
2. Check Supabase `users` table for new record
3. Verify `id_user` matches Clerk user ID

**Test User Updates**:
1. Update user profile in Clerk Dashboard
2. Check that Supabase record is updated
3. Verify `updated_at` timestamp changes

**Test User Deletion**:
1. Delete user in Clerk Dashboard
2. Verify all related data is cleaned up:
   - User record deleted
   - Device mappings removed
   - Geofence memberships removed
   - Owned geofences and their members removed

## Security Considerations

1. **Webhook Verification**: Always verify webhook signatures using Svix
2. **Service Role Key**: Keep service role key secure, never expose to client
3. **Rate Limiting**: Consider rate limiting the webhook endpoint
4. **Database Constraints**: Use proper foreign key constraints and cascades
5. **Audit Logging**: Log all webhook events for debugging and compliance

## Deployment Checklist

- [ ] Environment variables configured in production
- [ ] Webhook endpoint URL updated in Clerk Dashboard  
- [ ] Service role key added to production environment
- [ ] Database constraints and RLS policies in place
- [ ] Monitoring and alerting configured
- [ ] Backup and recovery procedures tested 