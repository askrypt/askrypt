//! End-to-end exercise of the server-backed [`VaultStorage`] against a real
//! `askrypt-server`, mirroring the Phase 4 gate in `server/PLAN.md`: log in,
//! upload a real vault, read it back byte-identical, prove the ETag conflict
//! check bites, rename, and clean up.
//!
//! This is an example rather than a test on purpose. A test crate linking both
//! `askrypt-core` and `askrypt-server` would put the crypto core in the
//! server's build graph, and the server's whole premise is that it never links
//! it.
//!
//! ```text
//! cargo run -p askrypt-server &
//! curl -sX POST localhost:8080/api/v1/auth/register \
//!   -H 'content-type: application/json' \
//!   -d '{"email":"me@example.com","password":"correct-horse"}'
//! cargo run -p askrypt-core --features server-storage --example server_roundtrip \
//!   -- http://localhost:8080 me@example.com correct-horse
//! ```

use askrypt::{AskryptFile, SecretEntry, ServerClient, ServerStorage, StorageError, VaultStorage};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, base_url, email, password] = args.as_slice() else {
        eprintln!("usage: server_roundtrip <base-url> <email> <password>");
        std::process::exit(2);
    };

    let name = format!("roundtrip-{}.askrypt", std::process::id());

    println!("signing in to {base_url} as {email}");
    let client = Arc::new(ServerClient::login(
        base_url,
        email,
        password,
        Some("server_roundtrip example"),
    )?);

    let storage = ServerStorage::by_name(Arc::clone(&client), &name);
    assert!(!storage.exists(), "{name} already exists on the server");

    // A real vault, encrypted here on the client. The server only ever sees
    // the bytes this produces.
    let vault = AskryptFile::create(
        vec!["Favourite city?".into(), "First pet?".into()],
        vec!["Kyiv".into(), "Fluffy".into()],
        vec![SecretEntry {
            name: "example".into(),
            user_name: "user".into(),
            secret: "password123".into(),
            url: "https://example.com".into(),
            notes: "written by the server_roundtrip example".into(),
            entry_type: "password".into(),
            tags: vec![],
            created: 1_704_067_200,
            modified: 1_704_067_200,
            hidden: false,
            card: Default::default(),
        }],
        Some(6_000),
        false,
        None,
    )?;

    println!("uploading {name}");
    storage.save_vault(&vault)?;
    let vault_id = storage.vault_id().expect("upload should assign an id");
    println!("  -> id {vault_id}");
    assert!(storage.exists());

    println!("downloading it back");
    let loaded = storage.load_vault()?;
    assert_eq!(loaded, vault, "vault did not survive the round trip");

    // And it still decrypts, which is the only proof that matters.
    let questions_data = loaded.get_questions_data("Kyiv".into())?;
    let secrets = loaded.decrypt(&questions_data, vec!["Fluffy".into()])?;
    println!("  -> decrypted {} entry/entries", secrets.len());

    println!("checking conflict detection");
    // A second handle that has never read, so it holds the *original* ETag
    // while the first handle writes a newer version.
    let listed = client.list()?;
    let stale = ServerStorage::existing(
        Arc::clone(&client),
        listed
            .iter()
            .find(|vault| vault.name == name)
            .expect("vault should be listed"),
    );
    storage.save_vault(&vault)?; // bumps the stored ETag behind `stale`'s back
    match stale.save_vault(&vault) {
        Err(StorageError::Conflict(message)) => println!("  -> rejected as expected: {message}"),
        Err(e) => return Err(format!("expected a conflict, got {e}").into()),
        Ok(()) => return Err("stale write was accepted — conflict detection is broken".into()),
    }

    println!("renaming");
    let renamed = format!("renamed-{name}");
    client.rename(&vault_id, &renamed)?;
    assert!(client.list()?.iter().any(|vault| vault.name == renamed));

    println!("deleting");
    client.delete(&vault_id)?;
    assert!(!client.list()?.iter().any(|vault| vault.name == renamed));

    // `logout` consumes the client, so release the storage handles that share it.
    drop(storage);
    drop(stale);
    Arc::try_unwrap(client)
        .expect("client should not be shared any more")
        .logout()?;

    println!("\nround trip complete");
    Ok(())
}
