//! Password confirmation and revocation for sensitive account changes.
use super::{TestSite, ADMIN_EMAIL, ADMIN_PASSWORD};
use crate::db::users;
use axum::http::StatusCode;

async fn owner(site: &TestSite) -> crate::app::models::CurrentUser {
    let id = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
        .fetch_one(&site.pool)
        .await
        .unwrap();
    users::find(&site.pool, id).await.unwrap()
}

async fn setup_key(site: &mut TestSite) -> Vec<u8> {
    let page = site.get("/admin/profile/two-factor").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains("name=\"password\""));
    let displayed = page
        .body
        .split("<code class=\"two-factor-key\">")
        .nth(1)
        .unwrap()
        .split("</code>")
        .next()
        .unwrap();
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut secret = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0);
    for character in displayed.chars().filter(|c| !c.is_whitespace()) {
        buffer = (buffer << 5) | alphabet.find(character).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            secret.push((buffer >> bits) as u8);
        }
    }
    secret
}

pub(super) fn authenticator_code(secret: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    let step = chrono::Utc::now().timestamp() as u64 / 30;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(secret).unwrap();
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 15) as usize;
    let value = u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
    format!("{:06}", value % 1_000_000)
}

#[tokio::test]
async fn a_stolen_cookie_and_setup_code_cannot_enable_two_factor() {
    let mut site = TestSite::with_owner().await;
    let me = owner(&site).await;
    let original_cookie = site.cookie.clone();
    site.new_visitor();
    assert_eq!(
        site.sign_in(ADMIN_EMAIL, ADMIN_PASSWORD).await.location(),
        "/admin"
    );
    let secret = setup_key(&mut site).await;
    for password in [None, Some("wrong")] {
        let code = authenticator_code(&secret);
        let mut fields = vec![("code", code.as_str())];
        if let Some(password) = password {
            fields.push(("password", password));
        }
        let result = site.post("/admin/profile/two-factor", &fields).await;
        assert_eq!(result.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(result.body.contains("Your current password isn"));
        assert!(
            result.body.contains("two-factor-key"),
            "allow a retry with the same setup key"
        );
        assert!(users::two_factor(&site.pool, me.id).await.is_none());
        assert_eq!(users::recovery_codes_left(&site.pool, me.id).await, 0);
        assert_eq!(owner(&site).await.session_version, me.session_version);
    }
    let setup_cookie = site.cookie.clone();
    site.cookie = original_cookie.clone();
    assert_eq!(site.get("/admin").await.status, StatusCode::OK);
    site.cookie = setup_cookie;
    let result = site
        .post(
            "/admin/profile/two-factor",
            &[
                ("code", &authenticator_code(&secret)),
                ("password", ADMIN_PASSWORD),
            ],
        )
        .await;
    assert_eq!(result.status, StatusCode::OK);
    assert!(result.body.contains("<li><code>"));
    assert!(users::two_factor(&site.pool, me.id).await.is_some());
    assert_eq!(users::recovery_codes_left(&site.pool, me.id).await, 10);
    assert_eq!(site.get("/admin").await.status, StatusCode::OK);
    site.cookie = original_cookie;
    assert_eq!(site.get("/admin").await.location(), "/admin/login");
}

#[tokio::test]
async fn recovery_code_replacement_requires_the_current_password() {
    let mut site = TestSite::with_owner().await;
    let id = owner(&site).await.id;
    let old_code = "abcde-fghjk";
    sqlx::query("UPDATE users SET totp_secret = ?")
        .bind(crate::app::security::to_hex(b"12345678901234567890"))
        .execute(&site.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)")
        .bind(id)
        .bind(crate::app::security::hash_recovery_code(old_code))
        .execute(&site.pool)
        .await
        .unwrap();
    let old_cookie = site.cookie.clone();
    for fields in [vec![], vec![("password", "wrong")]] {
        let result = site
            .post("/admin/profile/two-factor/recovery", &fields)
            .await;
        assert_eq!(result.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(!result.body.contains("<li><code>"));
        assert_eq!(
            crate::db::users::recovery_codes_left(&site.pool, id).await,
            1
        );
    }
    let result = site
        .post(
            "/admin/profile/two-factor/recovery",
            &[("password", ADMIN_PASSWORD)],
        )
        .await;
    assert_eq!(result.status, StatusCode::OK);
    assert!(result.body.contains("<li><code>"));
    assert_eq!(
        crate::db::users::recovery_codes_left(&site.pool, id).await,
        10
    );
    assert!(!crate::db::users::use_recovery_code(&site.pool, id, old_code).await);
    assert_eq!(site.get("/admin").await.status, StatusCode::OK);
    site.cookie = old_cookie;
    assert_eq!(site.get("/admin").await.location(), "/admin/login");
}

#[tokio::test]
async fn stale_two_factor_changes_cannot_reissue_credentials() {
    let site = TestSite::with_owner().await;
    let id = owner(&site).await.id;
    let secret = b"12345678901234567890";
    let hashes = vec![crate::app::security::hash_recovery_code("abcde-fghjk")];
    assert_eq!(
        crate::db::users::enable_two_factor(&site.pool, id, secret, 1, &hashes, 0)
            .await
            .unwrap(),
        Some(1)
    );
    assert_eq!(
        crate::db::users::enable_two_factor(&site.pool, id, b"another secret", 2, &[], 0)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        crate::db::users::set_recovery_codes(&site.pool, id, &[], 0)
            .await
            .unwrap(),
        None
    );
    assert!(
        !crate::db::users::disable_two_factor_if_current(&site.pool, id, Some(0))
            .await
            .unwrap()
    );
    assert_eq!(
        crate::db::users::recovery_codes_left(&site.pool, id).await,
        1
    );
    assert_eq!(
        crate::db::users::two_factor(&site.pool, id)
            .await
            .unwrap()
            .0,
        secret
    );
}

#[tokio::test]
async fn email_changes_require_password_but_name_and_language_changes_do_not() {
    let mut site = TestSite::with_owner().await;
    let me = owner(&site).await;
    assert!(site
        .get("/admin/profile")
        .await
        .body
        .contains("To change your email, enter your current password."));
    for password in [None, Some("wrong")] {
        let mut fields = vec![
            ("name", "Attacker"),
            ("email", "attacker@example.com"),
            ("language", "lt"),
        ];
        if let Some(password) = password {
            fields.push(("current_password", password));
        }
        let response = site.post("/admin/profile", &fields).await;
        assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(response.body.contains("Your current password isn't right."));
        let unchanged = owner(&site).await;
        assert_eq!(unchanged.email, me.email);
        assert_eq!(unchanged.name, me.name);
        assert_eq!(unchanged.lang.code(), "en");
    }
    let response = site
        .post(
            "/admin/profile",
            &[
                ("name", "Renamed"),
                ("email", ADMIN_EMAIL),
                ("language", "lt"),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(owner(&site).await.name, "Renamed");
    assert_eq!(owner(&site).await.lang.code(), "lt");
    let response = site
        .post(
            "/admin/profile",
            &[
                ("name", "Renamed"),
                ("email", "new@example.com"),
                ("current_password", ADMIN_PASSWORD),
            ],
        )
        .await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(owner(&site).await.email, "new@example.com");
}

#[tokio::test]
async fn expired_two_factor_forms_return_to_sign_in() {
    let mut site = TestSite::with_owner().await;
    let me = owner(&site).await;
    sqlx::query("UPDATE users SET session_version = session_version + 1 WHERE id = ?")
        .bind(me.id)
        .execute(&site.pool)
        .await
        .unwrap();
    let cookie = site.cookie.clone();
    for path in [
        "/admin/profile/two-factor",
        "/admin/profile/two-factor/recovery",
    ] {
        site.cookie = cookie.clone();
        assert_eq!(
            site.post(path, &[("password", ADMIN_PASSWORD), ("code", "000000")])
                .await
                .location(),
            "/admin/login"
        );
    }
    site.cookie = cookie;
    let response = site
        .send(
            axum::http::Request::post("/admin/profile/two-factor/off")
                .header("hx-request", "true")
                .header("sec-fetch-site", "same-origin"),
            axum::body::Body::empty(),
        )
        .await;
    assert_eq!(response.header("hx-redirect"), "/admin/login");
}
