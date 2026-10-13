//! Revocation of emailed links and of requests authenticated before a change.
use super::{TestSite, ADMIN_EMAIL, ADMIN_PASSWORD};
use crate::db::users;
use crate::handlers::admin::password_reset::{create_link, create_link_if_current};
use axum::body::Body;
use axum::http::Request;

async fn owner(site: &TestSite) -> crate::app::models::CurrentUser {
    let id = sqlx::query_scalar("SELECT id FROM users LIMIT 1")
        .fetch_one(&site.pool)
        .await
        .unwrap();
    users::find(&site.pool, id).await.unwrap()
}

async fn has_link(site: &TestSite, token: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM password_resets WHERE token_hash = ?")
        .bind(crate::app::security::hash_token(token))
        .fetch_one(&site.pool)
        .await
        .unwrap()
        == 1
}

#[tokio::test]
async fn password_changes_cancel_links_and_reject_stale_updates() {
    let mut site = TestSite::with_owner().await;
    let me = owner(&site).await;
    let token = create_link(&site.pool, me.id).await.unwrap();
    let new_password = "Changed-Good-Password-8";
    let result = site
        .post(
            "/admin/profile/password",
            &[
                ("current_password", ADMIN_PASSWORD),
                ("new_password", new_password),
                ("confirm_password", new_password),
            ],
        )
        .await;
    assert!(result.body.contains("Password updated."));
    assert!(!has_link(&site, &token).await);
    let new_link = create_link(&site.pool, me.id).await.unwrap();
    assert!(
        users::change_password(&site.pool, me.id, "stale hash", Some(me.session_version))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        users::update_profile(&site.pool, &me, "Attacker", "attacker@example.com", "")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        create_link_if_current(&site.pool, me.id, me.session_version)
            .await
            .unwrap()
            .is_none()
    );
    assert!(has_link(&site, &new_link).await);
    site.new_visitor();
    assert_eq!(
        site.sign_in(ADMIN_EMAIL, new_password).await.location(),
        "/admin"
    );
}

#[tokio::test]
async fn email_changes_cancel_links_and_old_sessions() {
    let mut site = TestSite::with_owner().await;
    let me = owner(&site).await;
    let token = create_link(&site.pool, me.id).await.unwrap();
    let old_cookie = site.cookie.clone();
    site.new_visitor();
    site.sign_in(ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let result = site
        .post(
            "/admin/profile",
            &[
                ("name", "Owner"),
                ("email", "new@example.com"),
                ("current_password", ADMIN_PASSWORD),
            ],
        )
        .await;
    assert_eq!(result.status, axum::http::StatusCode::OK);
    assert!(!has_link(&site, &token).await);
    assert_eq!(site.get("/admin").await.status, axum::http::StatusCode::OK);
    let replacement = create_link(&site.pool, me.id).await.unwrap();
    assert!(
        create_link_if_current(&site.pool, me.id, me.session_version)
            .await
            .unwrap()
            .is_none()
    );
    assert!(has_link(&site, &replacement).await);
    site.cookie = old_cookie;
    let result = site
        .send(
            Request::post("/admin/profile")
                .header("hx-request", "true")
                .header("sec-fetch-site", "same-origin")
                .header("content-type", "application/x-www-form-urlencoded"),
            Body::from("name=Owner&email=new%40example.com"),
        )
        .await;
    assert_eq!(result.header("hx-redirect"), "/admin/login");
    assert_eq!(
        site.post("/admin/profile/two-factor/recovery", &[])
            .await
            .location(),
        "/admin/login"
    );
}

#[tokio::test]
async fn revocation_failure_rolls_back_password_and_email_changes() {
    let site = TestSite::with_owner().await;
    let me = owner(&site).await;
    let token = create_link(&site.pool, me.id).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_revocation BEFORE DELETE ON password_resets BEGIN SELECT RAISE(ABORT, 'test failure'); END").execute(&site.pool).await.unwrap();
    assert!(users::set_password(&site.pool, me.id, "new hash")
        .await
        .is_err());
    assert!(
        users::update_profile(&site.pool, &me, "Changed", "new@example.com", "tr")
            .await
            .is_err()
    );
    let unchanged = owner(&site).await;
    assert_eq!(unchanged.email, me.email);
    assert_eq!(unchanged.session_version, me.session_version);
    assert!(has_link(&site, &token).await);
}

#[tokio::test]
async fn reset_link_replacement_is_atomic() {
    let site = TestSite::with_owner().await;
    let me = owner(&site).await;
    let (a, b) = tokio::join!(
        create_link(&site.pool, me.id),
        create_link(&site.pool, me.id)
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_ne!(has_link(&site, &a).await, has_link(&site, &b).await);
    let survivor = if has_link(&site, &a).await { a } else { b };
    sqlx::query("CREATE TRIGGER fail_insert BEFORE INSERT ON password_resets BEGIN SELECT RAISE(ABORT, 'test failure'); END").execute(&site.pool).await.unwrap();
    assert!(create_link(&site.pool, me.id).await.is_err());
    assert!(has_link(&site, &survivor).await);
}

#[tokio::test]
async fn password_changes_revoke_pending_two_factor_logins() {
    let mut site = TestSite::with_owner().await;
    let me = owner(&site).await;
    sqlx::query("UPDATE users SET totp_secret = ? WHERE id = ?")
        .bind(crate::app::security::to_hex(b"12345678901234567890"))
        .bind(me.id)
        .execute(&site.pool)
        .await
        .unwrap();
    let code = "abcde-fghjk";
    sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)")
        .bind(me.id)
        .bind(crate::app::security::hash_recovery_code(code))
        .execute(&site.pool)
        .await
        .unwrap();
    site.new_visitor();
    assert_eq!(
        site.sign_in(ADMIN_EMAIL, ADMIN_PASSWORD).await.location(),
        "/admin/login/code"
    );
    users::set_password(
        &site.pool,
        me.id,
        &crate::app::security::hash_password("Replacement-Password-7").unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        site.post("/admin/login/code", &[("code", code)])
            .await
            .location(),
        "/admin/login"
    );
    assert_eq!(users::recovery_codes_left(&site.pool, me.id).await, 1);
}
#[tokio::test]
async fn a_stale_password_change_cannot_replace_the_password_or_restore_its_session() {
    let mut site = TestSite::with_owner().await;
    let new_password = "Owner-New-Password-8";
    let hash = crate::app::security::hash_password(new_password).unwrap();
    let mut tx = site.pool.begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query("UPDATE users SET password_hash = ?, session_version = session_version + 1")
        .bind(&hash)
        .execute(&mut *tx)
        .await
        .unwrap();
    // WAL readers can still check the old password while the owner holds
    // this write lock. The conditional update must reject that stale result.
    let request = site.post(
        "/admin/profile/password",
        &[
            ("current_password", ADMIN_PASSWORD),
            ("new_password", "Stale-Request-Password-9"),
            ("confirm_password", "Stale-Request-Password-9"),
        ],
    );
    let (result, _) = tokio::join!(request, async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        tx.commit().await.unwrap();
    });
    assert!(!result.body.contains("Password updated."));
    assert_eq!(result.header("hx-redirect"), "/admin/login");
    assert_eq!(result.status, axum::http::StatusCode::OK);
    assert!(result.body.contains("Sign in"));
    assert_eq!(site.get("/admin").await.location(), "/admin/login");
    let (stored, version): (String, i64) =
        sqlx::query_as("SELECT password_hash, session_version FROM users")
            .fetch_one(&site.pool)
            .await
            .unwrap();
    assert_eq!(stored, hash);
    assert_eq!(version, 1);
    assert_eq!(
        site.sign_in(ADMIN_EMAIL, new_password).await.location(),
        "/admin"
    );
}
