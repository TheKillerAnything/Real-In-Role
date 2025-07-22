
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL || 'https://placeholder.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || 'placeholder-key';

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_ANON_KEY) {
  console.warn('⚠️ PERINGATAN: Environment variables Supabase belum di-set!');
  console.warn('Silakan set SUPABASE_URL dan SUPABASE_ANON_KEY di Secrets');
}

const supabase = createClient(supabaseUrl, supabaseAnonKey);

module.exports = supabase;
