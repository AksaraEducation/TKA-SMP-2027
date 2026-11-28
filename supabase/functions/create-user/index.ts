import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  if (req.method !== "POST") return json({ error: "Metode tidak diizinkan." }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
    const serviceKey = Deno.env.get("AKSARA_SERVICE_ROLE_KEY");
    if (!serviceKey) return json({ error: "Secret AKSARA_SERVICE_ROLE_KEY belum dipasang pada Edge Function." }, 500);

    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return json({ error: "Sesi login tidak ditemukan. Silakan login kembali." }, 401);

    // Verifikasi identitas pemanggil menggunakan token login yang dikirim browser.
    const callerClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: callerData, error: callerError } = await callerClient.auth.getUser();
    if (callerError || !callerData.user) return json({ error: "Sesi login tidak valid. Silakan login kembali." }, 401);

    const { data: callerProfile, error: profileError } = await callerClient
      .from("profiles").select("role").eq("id", callerData.user.id).single();
    if (profileError || callerProfile?.role !== "admin") {
      return json({ error: "Akses ditolak. Hanya administrator yang dapat membuat akun." }, 403);
    }

    const body = await req.json();
    const fullName = String(body.full_name ?? "").trim();
    const email = String(body.email ?? "").trim().toLowerCase();
    const password = String(body.password ?? "");
    const role = String(body.role ?? "");

    if (!fullName || !email || !password) return json({ error: "Nama, email, dan kata sandi wajib diisi." }, 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Format email tidak valid." }, 400);
    if (password.length < 8) return json({ error: "Kata sandi awal minimal 8 karakter." }, 400);
    if (!["teacher", "student"].includes(role)) return json({ error: "Peran yang dapat dibuat hanya Guru atau Siswa." }, 400);

    const adminClient = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName },
    });
    if (createError || !created.user) return json({ error: createError?.message ?? "Akun gagal dibuat." }, 400);

    // Trigger database membuat profil awal sebagai student; fungsi tepercaya mengatur peran yang dipilih admin.
    const { error: updateError } = await adminClient.from("profiles")
      .update({ full_name: fullName, role })
      .eq("id", created.user.id);
    if (updateError) {
      await adminClient.auth.admin.deleteUser(created.user.id);
      return json({ error: "Akun tidak dapat diselesaikan: " + updateError.message }, 500);
    }

    return json({ success: true, message: "Akun " + (role === "teacher" ? "Guru" : "Siswa") + " berhasil dibuat." });
  } catch (error) {
    return json({ error: error instanceof Error ? error.message : "Terjadi kesalahan pada server." }, 500);
  }
});
