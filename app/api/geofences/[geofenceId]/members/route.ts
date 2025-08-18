import { NextRequest } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { createClient } from '@supabase/supabase-js';

// Create Supabase client with service role key to bypass RLS
const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!, // Service role bypasses RLS
  {
    auth: {
      autoRefreshToken: false,
      persistSession: false
    }
  }
);

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ geofenceId: string }> }
) {
  try {
    // Authenticate the user
    const { userId } = await auth();
    if (!userId) {
      return Response.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { geofenceId } = await params;
    
    // First, verify the user has access to this geofence with a simpler query
    const { data: membershipCheck, error: membershipError } = await supabaseAdmin
      .from('geofence_members')
      .select('role')
      .eq('id_geofence', geofenceId)
      .eq('id_user', userId)
      .maybeSingle();
    
    if (membershipError) {
      console.error('Membership check error:', membershipError);
      return Response.json({ 
        error: 'Failed to verify access to this geofence' 
      }, { status: 500 });
    }
    
    if (!membershipCheck) {
      return Response.json({ 
        error: 'You do not have access to this geofence' 
      }, { status: 403 });
    }

    // Fetch all members of the geofence with user details
    const { data: members, error: membersError } = await supabaseAdmin
      .from('geofence_members')
      .select(`
        *,
        users!inner(
          full_name,
          email
        )
      `)
      .eq('id_geofence', geofenceId)
      .order('joined_at', { ascending: true });

    if (membersError) {
      console.error('Error fetching members:', membersError);
      return Response.json({ 
        error: 'Failed to fetch members' 
      }, { status: 500 });
    }

    return Response.json({ members: members || [] });

  } catch (error) {
    console.error('API Error:', error);
    return Response.json({ 
      error: 'Internal server error' 
    }, { status: 500 });
  }
} 