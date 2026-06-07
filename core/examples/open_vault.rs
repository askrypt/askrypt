//! Dev tool: open a vault file with given answers and print decrypted entries.
//! Used to verify Dart-created vaults open in the Rust core (interop check).
//! Run: `cargo run -p askrypt-core --example open_vault -- <path> <a0> <a1> ...`

use askrypt::AskryptFile;

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().expect("usage: open_vault <path> <answers...>");
    let answers: Vec<String> = args.collect();
    assert!(!answers.is_empty(), "need at least one answer");

    let file = AskryptFile::load_from_file(&path).expect("load vault");
    let qd = file
        .get_questions_data(answers[0].clone())
        .expect("decrypt questions (wrong first answer?)");
    let entries = file
        .decrypt(&qd, answers[1..].to_vec())
        .expect("decrypt entries (wrong answers?)");

    println!("opened {path}: {} entries", entries.len());
    for e in &entries {
        println!(
            "  - name={:?} user={:?} secret={:?} tags={:?} hidden={}",
            e.name, e.user_name, e.secret, e.tags, e.hidden
        );
    }
}
