import { createClient } from '@supabase/supabase-js';

/**
 * Service Role Supabase Client
 * 
 * This client uses the service role key and bypasses RLS policies.
 * ONLY use this for:
 * - Webhook operations (user lifecycle management)
 * - Admin operations that require elevated permissions
 * - Server-side operations that need to access data across users
 * 
 * NEVER expose this client to the browser or client-side code!
 */
export function createServiceRoleClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error(
      'Missing required Supabase environment variables. Please check:\n' +
      '- NEXT_PUBLIC_SUPABASE_URL\n' +
      '- SUPABASE_SERVICE_ROLE_KEY'
    );
  }

  return createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    },
    db: {
      schema: 'public'
    }
  });
}

/**
 * Type-safe database operations for admin/webhook use
 * These operations bypass RLS and should only be used server-side
 */
export class AdminDatabaseService {
  private supabase = createServiceRoleClient();

  async createUser(userData: {
    id_user: string;
    email: string;
    full_name?: string;
  }) {
    const { data, error } = await this.supabase
      .from('users')
      .insert(userData)
      .select()
      .single();

    if (error) {
      console.error('Error creating user:', error);
      throw error;
    }

    return data;
  }

  async updateUser(id_user: string, updates: {
    email?: string;
    full_name?: string;
  }) {
    const { data, error } = await this.supabase
      .from('users')
      .update({
        ...updates,
        updated_at: new Date().toISOString()
      })
      .eq('id_user', id_user)
      .select()
      .single();

    if (error) {
      console.error('Error updating user:', error);
      throw error;
    }

    return data;
  }

  async deleteUser(id_user: string) {
    // Delete user - CASCADE will handle related records
    const { error: userError } = await this.supabase
      .from('users')
      .delete()
      .eq('id_user', id_user);

    if (userError) {
      console.error('Error deleting user:', userError);
      throw userError;
    }

    console.log(`User ${id_user} and all related data deleted successfully`);
  }

  async getUserById(id_user: string) {
    const { data, error } = await this.supabase
      .from('users')
      .select('*')
      .eq('id_user', id_user)
      .single();

    if (error && error.code !== 'PGRST116') { // Not found is OK
      console.error('Error getting user:', error);
      throw error;
    }

    return data;
  }
}

// Export singleton instance
export const adminDb = new AdminDatabaseService(); 