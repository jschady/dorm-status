import { Webhook } from 'svix';
import { headers } from 'next/headers';
import { WebhookEvent } from '@clerk/nextjs/server';
import { adminDb } from '@/app/(dashboard)/(lib)/supabase-admin';

const WEBHOOK_SECRET = process.env.CLERK_WEBHOOK_SECRET;

export async function POST(req: Request) {
  if (!WEBHOOK_SECRET) {
    console.error('Missing CLERK_WEBHOOK_SECRET environment variable');
    return new Response('Error: Missing webhook secret configuration', { 
      status: 500 
    });
  }

  // Get headers
  const headerPayload = await headers();
  const svix_id = headerPayload.get('svix-id');
  const svix_timestamp = headerPayload.get('svix-timestamp');
  const svix_signature = headerPayload.get('svix-signature');

  if (!svix_id || !svix_timestamp || !svix_signature) {
    console.error('Missing svix headers');
    return new Response('Error: Missing svix headers', { status: 400 });
  }

  // Get body
  const payload = await req.json();
  const body = JSON.stringify(payload);

  // Verify webhook signature
  const wh = new Webhook(WEBHOOK_SECRET);
  let evt: WebhookEvent;

  try {
    evt = wh.verify(body, {
      'svix-id': svix_id,
      'svix-timestamp': svix_timestamp,
      'svix-signature': svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error('Error verifying webhook:', err);
    return new Response('Error: Verification failed', { 
      status: 400 
    });
  }

  // Handle different webhook events
  try {
    switch (evt.type) {
      case 'user.created':
        await handleUserCreated(evt);
        console.log(`✅ User created: ${evt.data.id}`);
        break;
        
      case 'user.updated':
        await handleUserUpdated(evt);
        console.log(`✅ User updated: ${evt.data.id}`);
        break;
        
      case 'user.deleted':
        await handleUserDeleted(evt);
        console.log(`✅ User deleted: ${evt.data.id}`);
        break;
        
      default:
        console.log(`ℹ️  Unhandled event type: ${evt.type}`);
    }
  } catch (error) {
    console.error(`❌ Error processing webhook ${evt.type}:`, error);
    return new Response('Error: Processing failed', { 
      status: 500 
    });
  }

  return new Response('OK', { status: 200 });
}

/**
 * Handle user creation webhook
 * Creates corresponding user record in Supabase
 */
async function handleUserCreated(evt: WebhookEvent) {
  // Type assertion for user creation event
  const userData = evt.data as any;
  const { id, email_addresses, first_name, last_name, primary_email_address_id } = userData;
  
  // Get primary email address
  const primaryEmail = email_addresses?.find(
    (email: any) => email.id === primary_email_address_id
  )?.email_address;
  
  if (!primaryEmail) {
    throw new Error('No primary email address found for user');
  }

  // Create full name from first and last name
  const fullName = [first_name, last_name].filter(Boolean).join(' ') || undefined;

  try {
    await adminDb.createUser({
      id_user: id as string,
      email: primaryEmail as string,
      full_name: fullName,
    });
    
    console.log(`User created in database: ${id} (${primaryEmail})`);
  } catch (error) {
    // Check if it's a duplicate key error (user already exists)
    if (error && typeof error === 'object' && 'code' in error && error.code === '23505') {
      console.log(`User ${id} already exists in database, skipping creation`);
      return;
    }
    throw error;
  }
}

/**
 * Handle user update webhook
 * Updates user information in Supabase
 */
async function handleUserUpdated(evt: WebhookEvent) {
  // Type assertion for user update event
  const userData = evt.data as any;
  const { id, email_addresses, first_name, last_name, primary_email_address_id } = userData;
  
  // Get primary email address
  const primaryEmail = email_addresses?.find(
    (email: any) => email.id === primary_email_address_id
  )?.email_address;
  
  if (!primaryEmail) {
    throw new Error('No primary email address found for user');
  }

  // Create full name from first and last name
  const fullName = [first_name, last_name].filter(Boolean).join(' ') || undefined;

  await adminDb.updateUser(id as string, {
    email: primaryEmail as string,
    full_name: fullName || undefined,
  });
  
  console.log(`User updated in database: ${id} (${primaryEmail})`);
}

/**
 * Handle user deletion webhook
 * Removes user and all related data from Supabase
 */
async function handleUserDeleted(evt: WebhookEvent) {
  const userData = evt.data as any;
  const { id } = userData;
  
  await adminDb.deleteUser(id as string);
  
  console.log(`User and all related data deleted: ${id}`);
} 