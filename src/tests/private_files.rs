//! Database and backup permissions on Unix.

#[cfg(unix)]
use super::TestSite;
#[cfg(unix)]
#[tokio::test]
async fn databases_and_backup_archives_are_private_including_existing_files() {
    use std::os::unix::fs::PermissionsExt;
    let site = TestSite::with_owner().await;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    for suffix in ["", "-wal", "-shm"] {
        assert_eq!(
            mode(std::path::Path::new(&format!(
                "{}{suffix}",
                site.database.display()
            ))),
            0o600
        );
    }
    let folder = std::env::temp_dir().join(format!(
        "bloogla-private-test-{}",
        crate::app::security::random_hex(8)
    ));
    let backup = folder.join("backup.db");
    crate::services::backup::backup_to(&site.pool, &backup)
        .await
        .unwrap();
    assert_eq!(mode(&folder), 0o700);
    assert_eq!(mode(&backup), 0o600);
    // Opening an old, permissively-created database tightens it as well.
    std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o644)).unwrap();
    let pool = crate::db::connect(&format!("sqlite://{}?mode=rwc", backup.display()))
        .await
        .unwrap();
    assert_eq!(mode(&backup), 0o600);
    pool.close().await;
    let original = std::fs::read(&backup).unwrap();
    assert!(crate::services::backup::backup_to(&site.pool, &backup)
        .await
        .is_err());
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        original,
        "backups cannot overwrite existing files"
    );
    let uploads = folder.join("uploads");
    std::fs::create_dir_all(&uploads).unwrap();
    std::fs::write(uploads.join("picture.png"), b"test picture").unwrap();
    let archive = crate::services::backup::download_archive(&site.pool, &uploads)
        .await
        .unwrap();
    assert_eq!(mode(&archive), 0o600);
    assert_eq!(
        mode(std::path::Path::new(crate::services::backup::BACKUP_DIR)),
        0o700
    );
    let mut zip = zip::ZipArchive::new(std::fs::File::open(&archive).unwrap()).unwrap();
    assert_eq!(zip.len(), 2);
    // Permissions must not depend on the database's archive path.
    for index in 0..zip.len() {
        assert_eq!(
            zip.by_index(index).unwrap().unix_mode().unwrap() & 0o777,
            0o600
        );
    }
    drop(zip);
    std::fs::remove_file(archive).unwrap();
    std::fs::remove_dir_all(folder).unwrap();
}
