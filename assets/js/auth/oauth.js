// ============================================================
//  auth.js  –  Social Login Providers
//  Edit AXI_CONFIG to configure each provider.
// ============================================================

// (function () {
const AXI_CONFIG = {
  google: {},
  microsoft: {},
  supabase: {},
};

var signupModalEl;

async function loadSettings() {
  try {
    if (!window.CONFIG) return;
    AXI_CONFIG.google = CONFIG.AxiPortal.OAuth.google;
    AXI_CONFIG.microsoft = CONFIG.AxiPortal.OAuth.microsoft;
    AXI_CONFIG.supabase = CONFIG.AxiPortal.OAuth.supabase;
  } catch (e) {
    console.warn("appsettings.json not found (OAuth):", e);
  }
}

// ── Supabase lazy init ──────────────────────────────────────
let _sb = null;
function getSupabase() {
  if (!_sb && window.supabase)
    _sb = supabase.createClient(
      AXI_CONFIG.supabase.url,
      AXI_CONFIG.supabase.publicKey,
    );
  return _sb;
}

// ── Social router  (add new providers here) ─────────────────
function axiSocialLogin(provider, authMode) {
  const isLogin = authMode === "login";
  const handlers = {
    google: () => _googleLogin(isLogin),
    microsoft: () => _msLogin(isLogin),
    github: () => _githubLogin(isLogin),
    linkedin: () => _linkedinLogin(isLogin),
  };
  const fn = handlers[provider];
  if (fn) fn();
  else axiToast("Unknown provider: " + provider);
}

// ── Google ──────────────────────────────────────────────────
function _googleLogin(isLogin) {
  if (!window.google?.accounts)
    return axiToast("Google Sign-In not ready. Please refresh.");

  google.accounts.oauth2
    .initTokenClient({
      client_id: AXI_CONFIG.google.clientId,
      scope: "openid email profile",
      callback: async ({ error, access_token }) => {
        if (error) return console.error("[Google]", error);
        try {
          const info = await fetch(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            { headers: { Authorization: "Bearer " + access_token } },
          ).then((r) => r.json());
          await axiHandleSocialUser(
            {
              name: info.name,
              email: info.email,
              isEmailVerified: info.email_verified,
              accessToken: access_token,
              sub: info.sub,
            },
            "google",
            isLogin,
          );
        } catch {
          axiToast("Could not fetch Google profile. Try again.");
        }
      },
    })
    .requestAccessToken();
}

// ── Microsoft (MSAL v3) ──────────────────────────────────────
let _msal = null;
async function _getMsal() {
  if (_msal) return _msal;
  if (typeof msal === "undefined") {
    console.error("MSAL not loaded");
    return null;
  }
  _msal = new msal.PublicClientApplication({
    auth: {
      clientId: AXI_CONFIG.microsoft.clientId,
      authority:
        "https://login.microsoftonline.com/" +
        (AXI_CONFIG.microsoft.tenantId || "common"),
      redirectUri: window.location.origin,
    },
    cache: { cacheLocation: "sessionStorage" },
  });
  await _msal.initialize();
  return _msal;
}
async function _msLogin(isLogin) {
  const inst = await _getMsal();
  if (!inst) return;
  try {
    const res = await inst.loginPopup({
      scopes: ["openid", "email", "profile", "User.Read"],
    });
    await axiHandleSocialUser(
      {
        name: res.account.name,
        email: res.account.username,
        accessToken: res.accessToken,
        sub: res.account?.idTokenClaims?.sub,
      },
      "microsoft",
      isLogin,
    );
  } catch (e) {
    console.error("[MSAL]", e);
  }
}

// ── GitHub & LinkedIn (Supabase OAuth) ──────────────────────
async function _githubLogin(isLogin) {
  await _supabaseOAuth("github", isLogin);
}
async function _linkedinLogin(isLogin) {
  await _supabaseOAuth("linkedin_oidc", isLogin);
}

async function _supabaseOAuth(provider, isLogin) {
  const sb = getSupabase();
  // Store isLogin so the auth state listener can use it after redirect
  sessionStorage.setItem("axi_oauth_mode", isLogin ? "login" : "signup");
  const { error } = await sb.auth.signInWithOAuth({
    provider,
    options: { redirectTo: window.location.origin + "/" },
  });
  if (error) {
    console.error("[Supabase OAuth]", error.message);
    axiToast("Sign-in failed. Please try again.");
  }
}

// ── Supabase auth state listener (handles OAuth redirect) ────
function _initSupabaseListener() {
  signupModalEl = document.getElementById("signupform");
  const sb = getSupabase();
  if (!sb) return;
  sb.auth.onAuthStateChange((event, session) => {
    if (
      event === "SIGNED_IN" &&
      session?.user &&
      !sessionStorage.getItem("axi_social_user")
    ) {
      const u = session.user;
      const isLogin = sessionStorage.getItem("axi_oauth_mode") === "login";
      sessionStorage.removeItem("axi_oauth_mode");
      axiHandleSocialUser(
        {
          name:
            u.user_metadata.given_name ||
            u.user_metadata.user_name ||
            u.user_metadata.full_name ||
            "User",
          fullName: u.user_metadata.name || "",
          email: u.email,
          isEmailVerified: !!u.email_confirmed_at,
          accessToken: session.access_token,
          sub: u.user_metadata.sub,
        },
        u.app_metadata.provider || "supabase-oauth",
        isLogin,
      );
      if (window.history.replaceState)
        window.history.replaceState(null, null, window.location.pathname);
    }
  });
}
window.addEventListener("load", _initSupabaseListener);

// ── After any successful social auth ────────────────────────
//    Saves the user and hands off to the signup wizard (auth.js)
const _SUPABASE_PROVIDERS = new Set([
  "github",
  "linkedin_oidc",
  "supabase-oauth",
]);

async function _clearProviderSession(provider) {
  try {
    if (_SUPABASE_PROVIDERS.has(provider)) {
      await getSupabase()?.auth.signOut();
    } else {
      // Google / Microsoft — clear MSAL cache and session tokens
      sessionStorage.clear();
    }
  } catch (e) {
    console.warn("Session clear failed:", e);
  }
}

async function axiHandleSocialUser(user, provider, isLogin) {
  window.ui.setLoading(
    signupModalEl,
    "axi-signup-loader",
    "axi-signup-loader-text",
    true,
    "Checking email…",
  );
  try {
    const isValid = await _validateSocialEmail(user.email, isLogin);
    if (!isValid) {
      await _clearProviderSession(provider);
      axiToast(
        isLogin
          ? "No account found with this email. Please sign up first."
          : "This email is already registered. Please log in instead.",
      );
      return;
    }

    sessionStorage.setItem(
      "axi_social_user",
      JSON.stringify({ ...user, provider }),
    );

    if (isLogin) {
      window.triggerSuccessRedirect("Login successful", "");
    } else {
      setTimeout(
        () =>
          typeof openCompanyDetailsModal === "function" &&
          openCompanyDetailsModal(),
        400,
      );
    }
  } catch (err) {
    console.error("[axiHandleSocialUser]", err);
    axiToast("Something went wrong. Please try again.");
  } finally {
    window.ui.setLoading(
      signupModalEl,
      "axi-signup-loader",
      "axi-signup-loader-text",
      false,
    );
  }
}

// ── Toast helper ─────────────────────────────────────────────
function axiToast(msg) {
  let el = document.getElementById("axi-toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "axi-toast";
    Object.assign(el.style, {
      position: "fixed",
      top: "28px",
      left: "50%",
      transform: "translateX(-50%)",
      background: "#1a1a2e",
      color: "#ff4d33",
      padding: "13px 22px",
      borderRadius: "10px",
      zIndex: "999999",
      fontSize: "14px",
      maxWidth: "400px",
      textAlign: "center",
      boxShadow: "0 6px 20px rgba(0,0,0,.35)",
      lineHeight: "1.5",
      border: "1.5px solid #3a3e4f",
    });
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.style.display = "block";
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.style.display = "none"), 5500);
}

async function _validateSocialEmail(email, isLogin) {
  const response = await window.api.emailCheck(email);
  const rows = response?.["AXI Email Check"]?.rows;
  const emailExists = Array.isArray(rows) && rows.length > 0;
  // Signup: email must NOT exist. Login: email MUST exist.
  return isLogin ? emailExists : !emailExists;
}

window.addEventListener("axi:config-ready", loadSettings);
