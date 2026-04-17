// ============================================================
//  auth.js  –  Social Login Providers
//  Edit AXI_CONFIG to configure each provider.
// ============================================================

const AXI_CONFIG = {
  google: {
    clientId:
      "130828479208-e57k5lnicfu4h2hcbeqva5vs733j4t0e.apps.googleusercontent.com",
  },
  microsoft: {
    clientId: "5bc83ad8-59f6-4e6b-aa42-069b6c44c79f",
    tenantId: "0b1513a2-8f4d-4478-ab27-28da7a534984",
  },
  supabase: {
    url: "https://cictsmygarchinmbajmf.supabase.co",
    publicKey: "sb_publishable_vj0-UPrA4Zq_nhKw1bDfTA_7tjemf0N",
  },
};

const signupModalEl = document.getElementById("signupform");

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
let isLogin = false;
function axiSocialLogin(provider) {
  const handlers = {
    google: _googleLogin,
    microsoft: _msLogin,
    github: _githubLogin,
    linkedin: _linkedinLogin,
  };
  // isLogin = authMode == "login";
  const fn = handlers[provider];
  if (fn) fn();
  else axiToast("Unknown provider: " + provider);
}

// ── Google ──────────────────────────────────────────────────
function _googleLogin() {
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
          console.log("from google:");
          console.log(info);
          axiHandleSocialUser(
            {
              name: info.name,
              email: info.email,
              isEmailVerified: info.email_verified,
              accessToken: access_token,
              sub: info.sub,
            },
            "google",
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
async function _msLogin() {
  const inst = await _getMsal();
  if (!inst) return;
  try {
    const res = await inst.loginPopup({
      scopes: ["openid", "email", "profile", "User.Read"],
    });
    console.log("from ms:");
    console.log(res);
    axiHandleSocialUser(
      {
        name: res.account.name,
        email: res.account.username,
        accessToken: res.accessToken,
        sub: res.account?.idTokenClaims?.sub,
      },
      "microsoft",
    );
  } catch (e) {
    console.error("[MSAL]", e);
  }
}

// ── GitHub & LinkedIn (Supabase OAuth) ──────────────────────
async function _githubLogin() {
  await _supabaseOAuth("github");
}
async function _linkedinLogin() {
  await _supabaseOAuth("linkedin_oidc");
}

async function _supabaseOAuth(provider) {
  const sb = getSupabase();
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
  const sb = getSupabase();
  if (!sb) return;
  sb.auth.onAuthStateChange((event, session) => {
    if (session?.user && !sessionStorage.getItem("axi_social_user")) {
      const u = session.user;
      console.log("from sb:");
      console.log(session);
      axiHandleSocialUser(
        {
          name:
            u.user_metadata.given_name ||
            u.user_metadata.user_name ||
            u.user_metadata.full_name ||
            "User0",
          fullName: u.user_metadata.name || "",
          email: u.email,
          isEmailVerified: u.user_metadata.email_verified,
          accessToken: session.access_token,
          sub: u.user_metadata.sub,
        },
        u.app_metadata.provider || "supabase-oauth",
      );
      if (window.history.replaceState)
        window.history.replaceState(null, null, window.location.pathname);
    }
  });
}
window.addEventListener("load", _initSupabaseListener);

// ── After any successful social auth ────────────────────────
//    Saves the user and hands off to the signup wizard (signup.js)
async function axiHandleSocialUser(user, provider) {
  try {
    window.ui.setLoading(
      signupModalEl,
      "axi-signup-loader",
      "axi-signup-loader-text",
      true,
      "Checking email…",
    );

    const validateEmail = await validateSocialEmail(user, isLogin);

    if (!validateEmail) {
      if (
        provider === "supabase-oath" ||
        provider === "github" ||
        provider === "linkedin_oidc"
      ) {
        const sb = getSupabase();
        await sb.auth.signOut();
      }

      if ((provider === "microsoft" && _msal) || provider === "google") {
        sessionStorage.clear();
      }

      axiToast("Email Already Exists Please Login using Axi Account Id ");
      return;
    }
    sessionStorage.setItem(
      "axi_social_user",
      JSON.stringify({ ...user, provider }),
    );
    // openCompanyDetailsModal is exposed globally by signup.js
    setTimeout(
      () =>
        typeof openCompanyDetailsModal === "function" &&
        openCompanyDetailsModal(),
      400,
    );
  } catch (err) {
    axiToast("Something went wrong, please try again later");
    console.log(err?.message);
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
