/**
 * Rocket Cartel Whitelist SPA
 * Handles Auth0 redirect flow, token storage, and username mapping.
 */
(function () {
    "use strict";

    var API_BASE = "http://localhost:8000";

    // --- State ---
    var accessToken = null;

    // --- DOM ---
    var loginSection = document.getElementById("login-section");
    var usernameSection = document.getElementById("username-section");
    var loginBtn = document.getElementById("login-btn");
    var logoutBtn = document.getElementById("logout-btn");
    var saveUsernameBtn = document.getElementById("save-username-btn");
    var changeUsernameBtn = document.getElementById("change-username-btn");
    var mcUsernameInput = document.getElementById("mc-username");
    var userEmail = document.getElementById("user-email");
    var userTier = document.getElementById("user-tier");
    var userExpires = document.getElementById("user-expires");
    var displayUsername = document.getElementById("display-username");
    var usernameFormArea = document.getElementById("username-form-area");
    var currentUsernameArea = document.getElementById("current-username");
    var messageDiv = document.getElementById("message");

    // --- Init ---
    function init() {
        // Check for token in URL fragment from Auth0 callback redirect
        var hash = window.location.hash;
        if (hash.indexOf("#token=") === 0) {
            accessToken = hash.substring(7);
            sessionStorage.setItem("access_token", accessToken);
            history.replaceState(null, "", "/");
        } else {
            accessToken = sessionStorage.getItem("access_token");
        }

        if (accessToken) {
            loadUserProfile();
        } else {
            showLogin();
        }

        loginBtn.addEventListener("click", handleLogin);
        logoutBtn.addEventListener("click", handleLogout);
        saveUsernameBtn.addEventListener("click", handleSaveUsername);
        changeUsernameBtn.addEventListener("click", function () {
            usernameFormArea.style.display = "block";
            currentUsernameArea.style.display = "none";
        });
    }

    // --- API ---
    function apiFetch(path, options) {
        options = options || {};
        var headers = {
            "Content-Type": "application/json"
        };
        if (accessToken) {
            headers["Authorization"] = "Bearer " + accessToken;
        }
        if (options.headers) {
            for (var key in options.headers) {
                headers[key] = options.headers[key];
            }
        }
        options.headers = headers;

        return fetch(API_BASE + path, options).then(function (resp) {
            if (resp.status === 401) {
                handleLogout();
                throw new Error("Session expired");
            }
            return resp;
        });
    }

    // --- Handlers ---
    function handleLogin() {
        fetch(API_BASE + "/api/login-url")
            .then(function (resp) { return resp.json(); })
            .then(function (data) {
                sessionStorage.setItem("auth_state", data.state);
                window.location.href = data.login_url;
            })
            .catch(function (e) {
                showMessage("Failed to start login: " + e.message, true);
            });
    }

    function handleLogout() {
        accessToken = null;
        sessionStorage.removeItem("access_token");
        showLogin();
    }

    function loadUserProfile() {
        apiFetch("/api/me")
            .then(function (resp) {
                if (!resp.ok) throw new Error("Failed to load profile");
                return resp.json();
            })
            .then(function (user) {
                userEmail.textContent = user.email;
                userTier.textContent = user.patreon_subscriber_tier || "None";
                userExpires.textContent = user.subscription_expires_at
                    ? new Date(user.subscription_expires_at).toLocaleDateString()
                    : "N/A";

                if (user.minecraft_username) {
                    displayUsername.textContent = user.minecraft_username;
                    mcUsernameInput.value = user.minecraft_username;
                    usernameFormArea.style.display = "none";
                    currentUsernameArea.style.display = "block";
                } else {
                    usernameFormArea.style.display = "block";
                    currentUsernameArea.style.display = "none";
                }

                showUsernameSection();
            })
            .catch(function (e) {
                showMessage("Failed to load profile: " + e.message, true);
                handleLogout();
            });
    }

    function handleSaveUsername() {
        var username = mcUsernameInput.value.trim();
        if (!username || username.length < 3) {
            showMessage("Username must be at least 3 characters.", true);
            return;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            showMessage("Username can only contain letters, numbers, and underscores.", true);
            return;
        }

        apiFetch("/api/map-username", {
            method: "POST",
            body: JSON.stringify({ minecraft_username: username })
        })
            .then(function (resp) {
                if (resp.ok) {
                    showMessage("Username saved successfully!", false);
                    loadUserProfile();
                } else {
                    return resp.json().then(function (err) {
                        showMessage(err.detail || "Failed to save username.", true);
                    });
                }
            })
            .catch(function (e) {
                showMessage("Error: " + e.message, true);
            });
    }

    // --- UI ---
    function showLogin() {
        loginSection.style.display = "block";
        usernameSection.style.display = "none";
    }

    function showUsernameSection() {
        loginSection.style.display = "none";
        usernameSection.style.display = "block";
    }

    function showMessage(text, isError) {
        messageDiv.textContent = text;
        messageDiv.className = "message " + (isError ? "error" : "success");
        messageDiv.style.display = "block";
        setTimeout(function () {
            messageDiv.style.display = "none";
        }, 5000);
    }

    init();
})();
