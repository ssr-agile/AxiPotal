// ============================================================
//  auth.js  –  Signup wizard, Login wizard, ARM API layer
//  Depends on: oauth.js (social providers), intl-tel-input
// ============================================================
(function () {
  "use strict";

  /* ═══════════════════════════════════════════════════════════
     1. SETTINGS  –  loaded from appsettings.json at boot
  ═══════════════════════════════════════════════════════════ */
  const APP = { axappurl: "", axarmurl: "", AxiClientAPI: "" };
  const SECRETS = {
    createAccount: "",
    emailCheck: "",
    accountDetails: "",
    accountCheck: "",
    createUser: "",
  };
  const Region = {
    city: "",
    state: "",
    country: "",
  };
  window.CONFIG = {};
  async function loadSettings() {
    try {
      const res = await fetch("axiglobalconfig.json");
      if (!res.ok) return;
      CONFIG = await res.json();
      APP.axappurl = CONFIG.AxiPortal.axappurl || "";
      APP.axarmurl = CONFIG.AxiPortal.axarmurl || "";
      APP.AxiClientAPI = CONFIG.AxiClientAPI || "";
      SECRETS.createAccount = CONFIG.AxiPortal.SECRETS.createAccount;
      SECRETS.emailCheck = CONFIG.AxiPortal.SECRETS.emailCheck;
      SECRETS.accountDetails = CONFIG.AxiPortal.SECRETS.accountDetails;
      SECRETS.accountCheck = CONFIG.AxiPortal.SECRETS.accountCheck;
      SECRETS.createUser = CONFIG.AxiPortal.SECRETS.createUser;

      window.dispatchEvent(new Event("axi:config-ready"));

      const regiondata = await fetch("https://ipapi.co/json/");
      if (!regiondata.ok) return;
      const region = await regiondata.json();
      Region.city = region.city;
      Region.state = region.region;
      Region.country = region.country;
    } catch (e) {
      console.warn("appsettings.json not found, using defaults:", e);
    }
  }

  /* ═══════════════════════════════════════════════════════════
     2. ARM API LAYER
  ═══════════════════════════════════════════════════════════ */

  // ARM URLs resolve after settings load
  function armUrl(path) {
    const base = APP.axarmurl || "";
    return base.replace(/\/$/, "") + "/" + path;
  }

  function axiClientApiUrl(path) {
    const base = APP.AxiClientAPI || "";
    return base.replace(/\/$/, "") + "/" + path;
  }



  // Encrypted-key cache (one encrypt call per raw secret per session)
  const _encCache = new Map();
  async function _getEncKey(rawSecret) {
    if (_encCache.has(rawSecret)) return _encCache.get(rawSecret);
    const p = _post(armUrl("ARMGetEncryptedSecret"), {
      SecretKey: rawSecret,
    }).then((r) => {
      const enc =
        r.EncryptedSecretKey ||
        r.encryptedSecretKey ||
        r.EncryptedSecret ||
        r.encryptedSecret ||
        r.SecretKey ||
        r.secretKey ||
        r.result ||
        r.Result ||
        r.raw;
      if (!enc)
        throw new Error(
          "ARMGetEncryptedSecret: cannot read encrypted key (check response)",
        );
      return enc;
    });
    _encCache.set(rawSecret, p);
    return p;
  }

  async function _armExecute(publickey, submitdata, rawSecret) {
    const SecretKey = await _getEncKey(rawSecret);
    return _post(armUrl("ARMExecuteAPI"), {
      SecretKey,
      publickey,
      project: "axiadmin",
      submitdata,
    });
  }

  async function _armSql(publickey, sqlparams, rawSecret) {
    const SecretKey = await _getEncKey(rawSecret);
    return _post(armUrl("ARMExecuteAPI"), {
      SecretKey,
      publickey,
      Project: "axiadmin",
      getsqldata: {},
      sqlparams: sqlparams || {},
    });
  }

  async function _post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      json = { raw: text };
    }
    if (!res.ok)
      throw new Error(
        json.message || json.error || json.raw || "HTTP " + res.status,
      );
    return json;
  }

  // Domain-specific API calls
  window.api = {
    axiUserValidate: (emailId) => {
      const axiUserValidateUrl = axiClientApiUrl("api/AxiClient/AxiUserValidate");
      console.log(axiUserValidateUrl);
      return _post(axiUserValidateUrl, {
        userName: emailId
      });


    },
    emailCheck: (emailid) =>
      _armSql("AXIEMailCheck", { emailid }, SECRETS.emailCheck),
    accountCheck: (axiaccid) =>
      _armSql("AXIAccountCheck", { axiaccid }, SECRETS.accountCheck),
    accountDetails: (axiaccid) =>
      _armSql("AXIAccountDetails", { axiaccid }, SECRETS.accountDetails),

    createAccount(payload) {
      return _armExecute(
        "CreateAXIAccount",
        {
          trace: "false",
          keyfield: "",
          dataarray: {
            data: {
              mode: "new",
              keyvalue: "",
              recordid: "0",
              dc1: {
                row1: {
                  state: payload.state,
                  country: payload.country,
                  addr: payload.addr,
                  contactpername: payload.contactpername,
                  mobno: payload.mobno,
                  taxno: payload.taxno,
                  cntrycode: payload.cntrycode,
                  emailid: payload.email,
                  orgname: payload.orgname,
                  axiaccid: payload.axiaccid,
                },
              },
            },
          },
        },
        SECRETS.createAccount,
      );
    },

    createAxiUsers(payload) {
      return _armExecute(
        "CreateAXIUsers",
        {
          trace: "false",
          keyfield: "",
          dataarray: {
            data: {
              mode: "new",
              keyvalue: "",
              recordid: "0",
              dc1: {
                row1: {
                  username: payload.UserName,
                  email: payload.EmailId,
                  orgname: payload.OrgName,
                  region: payload?.Region,
                  isactive: payload.IsActive ?? "False",
                  isverified: payload.IsVerified ?? "False",
                },
              },

              dc2: {
                row1: {
                  authprovider: payload?.AuthProvider,
                  ssoid: payload?.SSOId,
                  passwordmd5: payload?.PasswordMd5,
                  passwordhash: payload?.PasswordHash,
                  passwordsalt: payload?.PasswordSalt,
                  isprimary: payload.IsPrimary ?? "False",
                },
              },

              dc3: {
                row1: {
                  appname: payload?.AppName,
                  schemaname: payload?.SchemaName,
                  role: payload.Role ?? "OWNER",
                  maxusers: payload.MaxUsers ?? 2,
                  expirydays: payload.ExpiryDays ?? 15,
                  expireon: payload?.ExpireOn || "",
                  isactiveapp: payload.AppIsActive ?? "True",
                },
              },
            },
          },
        },
        SECRETS.createUser,
      );
    },

    sendQueue(email, orgname, axiaccid) {
      return _post(armUrl("ARMPushToQueue"), {
        queuename: "axiadminqueue",
        apiname: "axiadmin",
        queuedata: JSON.stringify({
          axiadmin: { emailid: email, orgname, axiaccid },
        }),
        timespandelay: "0",
      });
    },
  };

  /* ═══════════════════════════════════════════════════════════
     3. STORAGE HELPERS  (localStorage)
  ═══════════════════════════════════════════════════════════ */
  function _store(key, val) {
    try {
      localStorage.setItem(key, JSON.stringify(val));
    } catch { }
  }
  function _load(key, fallback) {
    try {
      return JSON.parse(localStorage.getItem(key)) ?? fallback;
    } catch {
      return fallback;
    }
  }

  const storage = {
    getAuth: () => _load("axiAuth", {}),
    setAuth: (v) => _store("axiAuth", v),
    getLastId: () => localStorage.getItem("axiLastLoginAccountId") || "",
    setLastId: (v) =>
      v
        ? localStorage.setItem("axiLastLoginAccountId", v)
        : localStorage.removeItem("axiLastLoginAccountId"),
  };

  /* ═══════════════════════════════════════════════════════════
     4. VALIDATION
  ═══════════════════════════════════════════════════════════ */
  const validate = {
    email: (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v).toLowerCase()),
    axiId: (v) => /^[A-Z0-9]{5}[0-9]{3}$/.test(String(v || "").toUpperCase()),
    mobile: (v) => !v || /^[0-9+\-\s]{7,20}$/.test(v),
  };

  // function generateAxiId(orgName, existingIds = []) {
  //   const cleaned =
  //     (orgName || "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase() || "axixx";
  //   const prefix = cleaned.substring(0, 5).padEnd(5, "X");
  //   let id,
  //     tries = 0;
  //   do {
  //     id = prefix + String(Math.floor(Math.random() * 1000)).padStart(3, "0");
  //   } while (existingIds.includes(id) && ++tries < 2000);

  //   return id;
  // }

  /**
   * Phase 1: The String Generator
   * Creates a formatted ID and checks against a local list.
   */
  function generateAxiId(orgName, existingIds = []) {
    const cleaned =
      (orgName || "").replace(/[^a-zA-Z0-9]/g, "").toLowerCase() || "axixx";
    const prefix = cleaned.substring(0, 5).padEnd(5, "X");

    let id,
      tries = 0;

    do {
      id = prefix + String(Math.floor(Math.random() * 1000)).padStart(3, "0");
    } while (existingIds.includes(id) && ++tries < 2000);

    if (tries >= 2000) {
      return null; // Return null so the caller knows local generation failed
    }

    return id;
  }

  /**
   * Phase 2: The Orchestrator
   * This is the main logic you run when the user triggers the action.
   */
  async function handleIdAssignment(
    orgNameInput,
    accountIdInput,
    companyAccountErrEl,
  ) {
    let foundValidId = false;
    let generatedAccId = "";

    // Try the whole process up to 4 times
    for (let i = 0; i < 4; i++) {
      generatedAccId = generateAxiId(orgNameInput?.value || []);

      if (!generatedAccId) break; // Exit if local generation hit 2000 limit

      // Check availability against the live database via API
      const response = await api.accountCheck(generatedAccId);
      const rows = response?.["AXI Account Check"]?.rows;

      if (response?.success === true && rows?.length === 0) {
        if (accountIdInput && !accountIdInput.value) {
          accountIdInput.value = generatedAccId;
        }
        foundValidId = true;
        break; // Success! Exit the loop.
      }
    }

    // Show the modal regardless, but handle the error if no ID was found
    // window.ui.showModal("axiCompanyDetailsModal");

    if (!foundValidId) {
      window.ui.showErr(
        companyAccountErrEl,
        "Unable to generate a unique Axi Account Id. Please try with a different name",
      );
    }
  }

  // Checks if an ARM SQL response indicates a row already exists
  function _rowExists(resp) {
    const rows =
      resp?.rows ||
      resp?.Rows ||
      resp?.data ||
      resp?.Data ||
      resp?.result ||
      resp?.getsqldata?.data;
    if (Array.isArray(rows)) return rows.length > 0;
    const s = JSON.stringify(resp || "");
    if (/already.exist|exists|not.available|duplicate/i.test(s)) return true;
    if (/not.found|no.data|0.row/i.test(s)) return false;
    return false;
  }

  function _axiEmailExists(resp) {
    const rows = resp?.["AXI Email Check"]?.rows;
    return Array.isArray(rows) && rows.length > 0;
  }
  function _axiAccountExists(resp) {
    const rows = resp?.["AXI Account Check"]?.rows;
    return Array.isArray(rows) && rows.length > 0;
  }

  function _extractRecordId(resp) {
    return (
      (String(resp?.result || "").match(/recordid\s*=\s*(\d+)/i) || [])[1] ||
      null
    );
  }

  function _friendlyError(err) {
    const m = String(err?.message || err || "");
    if (/Duplicate.*emailid/i.test(m))
      return "This email is already registered. Please log in instead.";
    if (/Duplicate.*axiaccid/i.test(m))
      return "This AXI Account ID is taken. Click Regenerate.";
    if (/Duplicate.*mobno/i.test(m))
      return "This mobile number is already registered.";
    if (/Duplicate/i.test(m))
      return "This value is already in use. Please try a different one.";
    if (/Failed to fetch|NetworkError|Load failed/i.test(m))
      return "Network error. Check your connection and try again.";
    return "Something went wrong. Please try again.";
  }

  /* ═══════════════════════════════════════════════════════════
     5. UI HELPERS
  ═══════════════════════════════════════════════════════════ */
  window.ui = {
    showErr(el, msg) {
      if (!el) return;
      el.textContent = msg;
      el.classList.remove("d-none");
    },
    clearErr(el) {
      if (!el) return;
      el.textContent = "";
      el.classList.add("d-none");
    },
    setLoading(modalEl, loaderId, textId, on, text) {
      if (!modalEl) return;
      const loader = document.getElementById(loaderId);
      const textEl = document.getElementById(textId);
      if (!loader) return;
      loader.classList.toggle("d-none", !on);
      if (textEl && text) textEl.textContent = text;
      modalEl
        .querySelectorAll("input, select, textarea, button")
        .forEach((el) => {
          if (!loader.contains(el)) el.disabled = !!on;
        });
    },
    getModal(id) {
      const el = document.getElementById(id);
      if (!el || !window.bootstrap) return null;
      return (
        window.bootstrap.Modal.getInstance(el) || new window.bootstrap.Modal(el)
      );
    },
    showModal(id) {
      window.ui.getModal(id)?.show();
    },
    hideModal(id) {
      window.ui.getModal(id)?.hide();
    },
  };

  /* ═══════════════════════════════════════════════════════════
     6. SUCCESS & WAIT
  ═══════════════════════════════════════════════════════════ */
  function triggerSignupSuccessPopup() {
    window.ui.hideModal("axiCompanyDetailsModal");
    window.ui.showModal("setupProgressModal");
  }
  /* ═══════════════════════════════════════════════════════════
     6. REDIRECT & SUCCESS
  ═══════════════════════════════════════════════════════════ */
  window.triggerSuccessRedirect = (msg, axiaccid) => {
    const msgEl = document.getElementById("redirectModalMessage");
    if (msgEl) msgEl.innerText = msg;
    window.ui.showModal("redirectModal");
    setTimeout(() => {
      let url = APP.axappurl || "/";
      url += url.includes("?") ? "&" : "?";
      window.location.href = url + axiaccid;
    }, 2000);
  };

  /* ═══════════════════════════════════════════════════════════
     7. SIGNUP WIZARD
         Step 1 – email validate  (#signupform)
         Step 2 – company details (#axiCompanyDetailsModal)
  ═══════════════════════════════════════════════════════════ */
  function initSignup() {
    const signupModalEl = document.getElementById("signupform");
    const companyModalEl = document.getElementById("axiCompanyDetailsModal");
    if (!signupModalEl || !companyModalEl) return;

    // ── DOM refs ──────────────────────────────────────────
    const emailInput = document.getElementById("axi-email");
    const signupNextBtn = document.getElementById("axi-signup-next-btn");
    const signupErrEl = document.getElementById("axi-account-error");

    const companyForm = document.getElementById("axi-company-form");
    const companyErrEl = document.getElementById("axi-company-error");
    const accountErrEl = document.getElementById("axi-account-error"); // re-used in company modal
    const orgNameInput = document.getElementById("axi-company-org-name");
    const countryInput = document.getElementById("axi-country");
    const stateInput = document.getElementById("axi-state");
    const addressInput = document.getElementById("axi-address");
    const contactInput = document.getElementById("axi-contact-person");
    const taxNoInput = document.getElementById("axi-tax-no");
    const mobileInput = document.getElementById("axi-mobile");
    const accountIdInput = document.getElementById("axi-account-id");
    const regenerateBtn = document.getElementById("axi-regenerate-id");
    const checkIdBtn = document.getElementById("axi-check-id");
    const companyAccountErrEl = document.getElementById("axi-company-error"); // alias

    // ── intl-tel-input ────────────────────────────────────
    let iti = null;
    if (mobileInput && window.intlTelInput) {
      iti = window.intlTelInput(mobileInput, {
        initialCountry: "in",
        separateDialCode: true,
        nationalMode: true,
        countrySearch: true,
        dropdownContainer: companyModalEl || document.body,
        utilsScript:
          "https://cdn.jsdelivr.net/npm/intl-tel-input@23.8.0/build/js/utils.js",
      });
      // Sync country name → country text field
      const syncCountry = () => {
        try {
          if (countryInput)
            countryInput.value = iti.getSelectedCountryData()?.name || "";
        } catch { }
      };
      mobileInput.addEventListener("countrychange", () => {
        mobileInput.value = "";
        syncCountry();
      });
      syncCountry();
    }

    // ── Reset loaders when modals close ──────────────────
    signupModalEl.addEventListener("hidden.bs.modal", () =>
      window.ui.setLoading(
        signupModalEl,
        "axi-signup-loader",
        "axi-signup-loader-text",
        false,
      ),
    );
    companyModalEl.addEventListener("hidden.bs.modal", () =>
      window.ui.setLoading(
        companyModalEl,
        "axi-companydetails-loader",
        "axi-companydetails-loader-text",
        false,
      ),
    );

    // ── Expose globally so auth.js social handler can call it ──
    window.openCompanyDetailsModal = async function () {
      window.ui.hideModal("signupform");
      // Pre-fill email from social session if available
      const social = _getSocialUser();
      if (social?.email && emailInput) emailInput.value = social.email;
      // Auto-generate an AXI ID placeholder
      window.ui.showModal("axiCompanyDetailsModal");
    };
    // window.openCompanyDetailsModal = async function () {
    //   let generatedAccId = "";
    //   window.ui.hideModal("signupform");
    //   // Pre-fill email from social session if available
    //   const social = _getSocialUser();
    //   if (social?.email && emailInput) emailInput.value = social.email;
    //   // Auto-generate an AXI ID placeholder

    //   let foundValidId = false;

    //   for (let i = 0; i < 4; i++) {
    //     generatedAccId = generateAxiId(orgNameInput?.value || "");

    //     const response = await api.accountCheck(generatedAccId);
    //     const rows = response?.["AXI Account Check"]?.rows;
    //     if (response?.success === true && rows?.length === 0) {
    //       if (accountIdInput && !accountIdInput.value) {
    //         accountIdInput.value = generatedAccId;
    //       }

    //       foundValidId = true;
    //       break;
    //     }
    //   }

    //   window.ui.showModal("axiCompanyDetailsModal");

    //   if (!foundValidId) {
    //     window.ui.showErr(
    //       companyAccountErrEl,
    //       "Unable generate a unique Axi Account Id. Please try regenerating",
    //     );
    //   }
    // };

    // ── Step 1: email validation → open company modal ─────
    if (emailInput) {
      emailInput.addEventListener("input", () => {
        window.ui.clearErr(signupErrEl);
        if (signupNextBtn)
          signupNextBtn.disabled = !validate.email(emailInput.value.trim());
      });
      if (signupNextBtn) signupNextBtn.disabled = true; // off by default
    }

    signupModalEl.addEventListener("shown.bs.modal", () => {
      window.ui.clearErr(signupErrEl);
      // if (emailInput) emailInput.focus();
    });

    document
      .getElementById("axi-account-form")
      ?.addEventListener("submit", async (e) => {
        e.preventDefault();
        window.ui.clearErr(signupErrEl);
        const email = emailInput.value.trim();
        if (!validate.email(email)) {
          window.ui.showErr(signupErrEl, "Please enter a valid email address.");
          return emailInput.focus();
        }
        try {
          window.ui.setLoading(
            signupModalEl,
            "axi-signup-loader",
            "axi-signup-loader-text",
            true,
            "Checking email…",
          );
          const resp = await api.emailCheck(email);
          if (_axiEmailExists(resp)) {
            window.ui.showErr(
              signupErrEl,
              "This email is already registered. Please log in.",
            );
            return;
          }
          window.openCompanyDetailsModal();
        } catch (err) {
          window.ui.showErr(signupErrEl, _friendlyError(err));
        } finally {
          window.ui.setLoading(
            signupModalEl,
            "axi-signup-loader",
            "axi-signup-loader-text",
            false,
          );
        }
      });
    // ── Auto-generate AXI ID when org name is typed ───────
    orgNameInput?.addEventListener("blur", async () => {
      if (accountIdInput && !accountIdInput._manualEdit)
        try {
          window.ui.setLoading(
            companyModalEl,
            "axi-companydetails-loader",
            "axi-companydetails-loader-text",
            true,
            "Validating AXI ID...",
          );
          await handleIdAssignment(
            orgNameInput,
            accountIdInput,
            companyAccountErrEl,
          );
        } catch (err) {
          console.log(err?.message);
          ui.showErr(
            companyAccountErrEl,
            "Unable to generate a unique Axi Account Id. Please try regenerating",
          );
        } finally {
          window.ui.setLoading(
            companyModalEl,
            "axi-companydetails-loader",
            "axi-companydetails-loader-text",
            false,
          );
        }
    });
    accountIdInput?.addEventListener("input", () => {
      if (accountIdInput)
        accountIdInput._manualEdit = accountIdInput.value.length > 0;
      checkIdBtn.classList.remove("d-none");
    });
    // orgNameInput?.addEventListener("input", () => {
    //   if (accountIdInput && !accountIdInput._manualEdit)
    //     accountIdInput.value = generateAxiId(orgNameInput.value.trim());
    // });
    // accountIdInput?.addEventListener("input", () => {
    //   if (accountIdInput)
    //     accountIdInput._manualEdit = accountIdInput.value.length > 0;
    // });
    regenerateBtn?.addEventListener("click", async () => {
      if (!accountIdInput) return;
      try {
        window.ui.setLoading(
          companyModalEl,
          "axi-companydetails-loader",
          "axi-companydetails-loader-text",
          true,
          "Validating AXI ID...",
        );
        window.ui.clearErr(companyAccountErrEl); // ← clear previous error
        accountIdInput._manualEdit = false;
        checkIdBtn.classList.add("d-none");
        accountIdInput.value = generateAxiId(orgNameInput?.value.trim() || "");
        const response = await api.accountCheck(accountIdInput.value);
        if (_axiAccountExists(response)) {
          window.ui.showErr(
            companyAccountErrEl,
            "AXI Account ID already taken. Please regenerate.",
          );
        }
      } catch (err) {
        console.error(err);
        ui.showErr(
          companyAccountErrEl,
          "Unable to generate a unique AXI Account ID. Try again.",
        );
      } finally {
        window.ui.setLoading(
          companyModalEl,
          "axi-companydetails-loader",
          "axi-companydetails-loader-text",
          false,
        );
      }
    });

    // accountIdInput.addEventListener("blur", async (event) => {
    checkIdBtn.addEventListener("click", async (event) => {
      if (accountIdInput._manualEdit) {
        window.ui.setLoading(
          companyModalEl,
          "axi-companydetails-loader",
          "axi-companydetails-loader-text",
          true,
          "Validating AXI ID...",
        );
        window.ui.clearErr(companyAccountErrEl);
        const currentAccId = accountIdInput.value.trim();

        if (!currentAccId) {
          return;
        }

        try {
          const response = await api.accountCheck(currentAccId);
          if (_axiAccountExists(response)) {
            window.ui.showErr(
              companyAccountErrEl,
              "Axi Account Id Already Exists Please enter a new AxiAccountId",
            );
          } else {
            checkIdBtn.classList.add("d-none");
          }
        } catch (err) {
          console.log(err?.message);
          ui.showErr(
            companyAccountErrEl,
            "Something went wrong. Please try again",
          );
        } finally {
          window.ui.setLoading(
            companyModalEl,
            "axi-companydetails-loader",
            "axi-companydetails-loader-text",
            false,
          );
        }
      }
    });

    // ── Step 2: company details → create account ──────────
    companyForm?.addEventListener("submit", async (e) => {
      e.preventDefault();
      window.ui.clearErr(companyErrEl);

      const profile = _getSocialUser();

      const email = emailInput?.value.trim() || profile?.email || "";
      const axiaccid = (accountIdInput?.value || "").trim().toUpperCase();
      const orgname = orgNameInput?.value.trim() || "";
      const mobileRaw = mobileInput?.value?.trim() || "";

      // Validate AXI account ID
      if (!validate.axiId(axiaccid)) {
        window.ui.showErr(
          companyErrEl,
          "AXI Account ID must be 5 letters/numbers followed by 3 digits.",
        );
        return accountIdInput?.focus();
      }

      // Validate mobile (mandatory)
      if (!mobileRaw) {
        window.ui.showErr(companyErrEl, "Please enter your mobile number.");
        return mobileInput?.focus();
      }
      if (iti ? !iti.isValidNumber() : !validate.mobile(mobileRaw)) {
        window.ui.showErr(
          companyErrEl,
          "Please enter a valid mobile number for the selected country.",
        );
        return mobileInput?.focus();
      }

      // Extract dial code + national number
      let cntrycode = "",
        mobno = mobileRaw;
      if (iti) {
        cntrycode = iti.getSelectedCountryData()?.dialCode || "";
        const e164 = iti.getNumber() || "";
        mobno = e164
          .replace(/^\+/, "")
          .replace(new RegExp("^" + cntrycode), "");
      }

      const payload = {
        email,
        orgname,
        axiaccid: axiaccid?.toLowerCase() || "",
        country: countryInput?.value.trim() || "",
        state: stateInput?.value.trim() || "",
        addr: addressInput?.value.trim() || "",
        contactpername: contactInput?.value.trim() || "",
        taxno: taxNoInput?.value.trim() || "",
        cntrycode,
        mobno,
      };

      try {
        window.ui.setLoading(
          companyModalEl,
          "axi-companydetails-loader",
          "axi-companydetails-loader-text",
          true,
          "Creating your AXI account…",
        );

        // Check for duplicate AXI ID
        const idCheck = await api.accountCheck(axiaccid);
        if (_rowExists(idCheck))
          throw Object.assign(new Error("DUP_ID"), { code: "DUP_ID" });

        // Create account
        const newAccount = await api.createAccount(payload);
        const recordid = _extractRecordId(newAccount);

        // Cache auth record locally
        const auth = storage.getAuth();
        auth[axiaccid] = { recordid };
        const details = await api.accountDetails(axiaccid);
        auth[axiaccid].details = details;
        storage.setAuth(auth);

        // Send to admin queue
        await api.sendQueue(payload.email, payload.orgname, axiaccid);

        storage.setLastId(axiaccid);
        window.ui.setLoading(
          companyModalEl,
          "axi-companydetails-loader",
          "axi-companydetails-loader-text",
          false,
        );

        const userPayload = {
          // UserName: profile?.name || profile?.fullName || email,
          UserName: email,
          EmailId: email,
          OrgName: orgname,
          Region: Region.country,
          IsActive: "T",
          IsVerified: profile?.isEmailVerified == true ? "True" : "False",
          AuthProvider: profile?.provider || "Credential",
          SSOId: profile?.sub || "",
          PasswordMd5: "",
          PasswordHash: "",
          PasswordSalt: "",
          IsPrimary: "True",
          AppName: axiaccid?.toLowerCase() || "",
          SchemaName: axiaccid?.toLowerCase() || "",
          Role: "OWNER",
          MaxUsers: 2,
          ExpiryDays: 15,
          ExpireOn: "23/7/2027",
          // IsActive: true,
        };

        const createUser = await api.createAxiUsers(userPayload);

        // triggerSuccessFlow("Account created successfully!", axiaccid);
        triggerSignupSuccessPopup();
      } catch (err) {
        if (err.code === "DUP_ID")
          window.ui.showErr(
            companyErrEl,
            "This AXI Account ID is already taken. Click Regenerate.",
          );
        else window.ui.showErr(companyErrEl, _friendlyError(err));
      } finally {
        window.ui.setLoading(
          companyModalEl,
          "axi-companydetails-loader",
          "axi-companydetails-loader-text",
          false,
        );
      }
    });
  }

  function _getSocialUser() {
    try {
      return JSON.parse(sessionStorage.getItem("axi_social_user"));
    } catch {
      return null;
    }
  }

  /* ═══════════════════════════════════════════════════════════
     8. LOGIN FLOW
         Step 1 – AXI Account ID  →  verify exists via API
         Step 2 – Password        →  redirect to app
         (Real credential check is delegated to the AXI app)
  ═══════════════════════════════════════════════════════════ */
  function initLogin() {
    const loginModalEl = document.getElementById("staticBackdrop");
    if (!loginModalEl) return;

    const loginForm = document.getElementById("axi-login-form");
    const loginErrEl = document.getElementById("axi-login-error");
    const emailInput = document.getElementById("axi-login-email-id");
    // const idInput = document.getElementById("axi-login-account-id");
    // const passwordInput = document.getElementById("axi-login-password");
    // const rememberChk = document.getElementById("axi-login-remember");
    const step1 = document.getElementById("axi-login-step-1");
    // const step2 = document.getElementById("axi-login-step-2");
    const continueBtn = document.getElementById("axi-login-continue");
    // const backBtn = document.getElementById("axi-login-back");

    function showStep(n) {
      window.ui.clearErr(loginErrEl);
      step1?.classList.toggle("d-none", n !== 1);
      // step2?.classList.toggle("d-none", n !== 2);
      // if (n === 1) idInput?.focus();
      // if (n === 2) {
      //   if (passwordInput) passwordInput.value = "";
      //   passwordInput?.focus();
      // }
    }

    // Pre-fill saved account ID when modal opens
    loginModalEl.addEventListener("shown.bs.modal", () => {
      showStep(1);
      // const saved = storage.getLastId();
      // if (saved && idInput) idInput.value = saved;
    });

    // ── Step 1 Continue: verify account exists ────────────
    continueBtn?.addEventListener("click", async () => {
      window.ui.clearErr(loginErrEl);
      const email = emailInput?.value.trim().toLowerCase() || "";
      if (!email)
        return window.ui.showErr(loginErrEl, "Please enter your email.");
      if (!validate.email(email)) {
        window.ui.showErr(loginErrEl, "Please enter a valid email address.");
        return emailInput?.focus();
      }

      continueBtn.disabled = true;
      // Inside continueBtn click handler, replace the try block:
      try {
        window.ui.setLoading(
          loginModalEl,
          "axi-login-loader",
          "axi-login-loader-text",
          true,
          "Checking email…",
        );
        // const emailCheckResp = await api.emailCheck(email);
        // if (!_axiEmailExists(emailCheckResp)) {
        //   window.ui.showErr(
        //     loginErrEl,
        //     "No account found with this email. Please sign up first.",
        //   );

        // }


          const response = await api.axiUserValidate(email);

          if (!response || !response.Success) {
            window.ui.showErr(loginErrEl, "Error: " + response?.message);
            return;
          }

          let schemas = [];

          schemas = JSON.parse(response.JSON || []);

          if (schemas.length === 0) {
            window.ui.showErr(loginErrEl, "No Schemas found for username: " + email);
            return;
          }

          // if (schemas.length === 1) {
          //   window.ui.hideMo
          // }

          window.ui.hideModal("staticBackdrop")

          renderSchemaSelection(schemas);
          window.ui.showModal("axiSchemaModal");



        // triggerSuccessRedirect("Login successful.", "");
      } catch (err) {
        window.ui.showErr(loginErrEl, _friendlyError(err));
      } finally {
        continueBtn.disabled = false;
        window.ui.setLoading(
          loginModalEl,
          "axi-login-loader",
          "axi-login-loader-text",
          false,
        );
      }
    });

    // backBtn?.addEventListener("click", () => showStep(1));

    // ── Step 2 Submit: redirect to AXI app ───────────────
    //    The AXI app handles real credential verification.
    // loginForm?.addEventListener("submit", (e) => {
    //   e.preventDefault();
    //   window.ui.clearErr(loginErrEl);
    //   const accountId = idInput?.value.trim().toUpperCase() || "";
    //   const password = passwordInput?.value || "";

    //   if (!accountId || !password)
    //     return window.ui.showErr(loginErrEl, "Please complete all fields.");
    //   if (!validate.axiId(accountId))
    //     return window.ui.showErr(loginErrEl, "Invalid AXI Account ID format.");

    //   if (!rememberChk || rememberChk.checked) storage.setLastId(accountId);
    //   else storage.setLastId("");

    //   window.ui.hideModal("staticBackdrop");
    //   triggerSuccessRedirect("Login successful! Welcome back.", accountId);
    // });
  }

  /* ═══════════════════════════════════════════════════════════
     9. Open from URL
  ═══════════════════════════════════════════════════════════ */
  function checkUrlIntent() {
    const params = new URLSearchParams(window.location.search);
    const hash = window.location.hash;

    if (params.has("login") || hash === "#login") {
      // Wait for Bootstrap to be ready
      setTimeout(() => ui.showModal("staticBackdrop"), 300);
      // Clean the URL so it doesn't re-trigger on refresh
      const clean = window.location.pathname;
      window.history.replaceState(null, "", clean);
    }

    if (params.has("signup") || hash === "#signup") {
      setTimeout(() => ui.showModal("signupform"), 300);
      window.history.replaceState(null, "", window.location.pathname);
    }
  }

  /* ═══════════════════════════════════════════════════════════
     10. BOOT
  ═══════════════════════════════════════════════════════════ */
  // In signup.js, at the bottom of the DOMContentLoaded callback:
  document.addEventListener("DOMContentLoaded", async () => {
    await loadSettings();
    initSignup();
    initLogin();
    checkUrlIntent(); // ← add this
  });

  // triggerSignupSuccessPopup();

  function renderSchemaSelection(schemas) {
    const selectElement = document.getElementById("axi-schema-select");

    if (!selectElement) {
      console.error("Missing #axi-schema-select in the DOM.");
      return;
    }

    selectElement.innerHTML = "";

    const defaultOption = document.createElement("option");

    defaultOption.value = "";
    defaultOption.text = "Select a Schema...";
    defaultOption.disabled = true;
    defaultOption.selected = true;
    selectElement.appendChild(defaultOption);

    schemas.forEach(schema => {
      const isValid = schema.status === "Valid";
      const option = document.createElement("option");

      option.value = schema.schemaname;
      option.text = `${schema.appname}`;

      option.dataset.appname = schema.appname;

      if (!isValid) {
        option.disabled = true;
        option.text += "- Invalid"
      }

      selectElement.appendChild(option);
    });
  }

  const schemaContinueBtn = document.getElementById("axi-schema-continue-btn");
  const schemaSelectElement = document.getElementById("axi-schema-select");

  if (schemaContinueBtn && schemaSelectElement) {
    schemaContinueBtn.addEventListener("click", () => {
      const selectedSchema = schemaSelectElement.value;

      if (!selectedSchema) {
        alert("Please select a schema to continue.");
        return;
      }

      const selectedOption = schemaSelectElement.options[schemaSelectElement.selectedIndex];
      const appName = selectedOption.dataset.appname || selectedSchema;

      window.ui.hideModal("axiSchemaModal");
      triggerSuccessRedirect(`Loading ${appName}....`, selectedSchema);

    })
  }


})();
