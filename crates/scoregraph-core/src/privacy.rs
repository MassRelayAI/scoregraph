//! `scoregraph privacy-check`: fail when any file of the repository holds a private word, a personal path or a real email.
//!
//! Three checks over every tracked file (and every untracked file git does not ignore), contents and paths:
//! 1. **Deny-list words.** `.privacy-denylist` holds sha-256 HASHES of lowercase words, never the words. Text is lower-cased and
//!    split into runs of `[a-z0-9]`; each run is hashed and compared. Add a word with `scoregraph privacy-check --hash <word>`.
//! 2. **Machine paths.** A drive-letter path (`X:\`, `X:/`) or a home folder (`/home/<name>`, `/Users/<name>`) other than the
//!    neutral `user`, `you`, `runner`.
//! 3. **Emails.** Any address outside the reserved example domains (`example.com`, `example.org`, `example.net`, RFC 2606) and
//!    the `noreply` sender of commit trailers.
//!
//! A hit names the file and line and the check, never the word.
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

pub const DENYLIST: &str = ".privacy-denylist";

pub fn sha(word: &str) -> String {
    Sha256::digest(word.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn is_hex64(l: &str) -> bool {
    l.len() == 64 && l.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn load_denylist(root: &Path) -> Result<HashSet<String>, String> {
    let path = root.join(DENYLIST);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let mut out = HashSet::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if !is_hex64(line) {
            return Err(format!("{DENYLIST}: not a sha256 hex line"));
        }
        out.insert(line.to_string());
    }
    Ok(out)
}

fn files(root: &Path) -> Result<Vec<String>, String> {
    let o = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !o.status.success() {
        return Err(format!("git ls-files failed in {}: {}", root.display(), String::from_utf8_lossy(&o.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&o.stdout).split('\0').filter(|p| !p.is_empty()).map(str::to_string).collect())
}

pub fn scan_words(text: &str, deny: &HashSet<String>) -> bool {
    let low = text.to_lowercase();
    low.split(|c: char| !(c.is_ascii_lowercase() || c.is_ascii_digit())).filter(|w| !w.is_empty()).any(|w| deny.contains(&sha(w)))
}

fn path_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(^|[^A-Za-z0-9])[A-Za-z]:[\\/][A-Za-z0-9._-]|/(home|Users)/([A-Za-z0-9._-]+)").unwrap())
}

fn email_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})").unwrap())
}

/// A machine path in a line (drive letter, or a home folder that is not a neutral name).
pub fn scan_paths(line: &str) -> bool {
    path_re().captures_iter(line).any(|c| match c.get(3) {
        Some(name) => !matches!(name.as_str(), "user" | "you" | "runner" | "<name>"),
        None => true,
    })
}

/// An email outside the example domains.
pub fn scan_emails(line: &str) -> bool {
    email_re().captures_iter(line).any(|c| {
        let domain = c[2].to_lowercase();
        let reserved = ["example.com", "example.org", "example.net"].iter().any(|d| domain == *d || domain.ends_with(&format!(".{d}")));
        !(reserved || (c[1].eq_ignore_ascii_case("noreply") && domain == "anthropic.com"))
    })
}

/// `file:line (check)` or `file (path)` of every hit; no word is ever returned.
pub fn check(root: &Path, deny: &HashSet<String>) -> Result<Vec<String>, String> {
    let mut hits = vec![];
    for rel in files(root)? {
        if rel == DENYLIST {
            continue;
        }
        if scan_words(&rel, deny) {
            hits.push(format!("{rel} (path: deny-listed word)"));
            continue;
        }
        let p = root.join(&rel);
        if !p.is_file() {
            continue;
        }
        let Ok(data) = std::fs::read(&p) else { continue };
        let text = String::from_utf8_lossy(&data);
        for (n, line) in text.lines().enumerate() {
            let what = if scan_words(line, deny) {
                "deny-listed word"
            } else if scan_paths(line) {
                "machine path"
            } else if scan_emails(line) {
                "email"
            } else {
                continue;
            };
            hits.push(format!("{rel}:{} ({what})", n + 1));
        }
    }
    Ok(hits)
}

/// The command: 0 clean, 1 hit, 2 cannot run.
pub fn run(root: &Path, hash: Option<&str>) -> i32 {
    if let Some(w) = hash {
        println!("{}", sha(&w.trim().to_lowercase()));
        return 0;
    }
    let hits = match load_denylist(root).and_then(|d| check(root, &d)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("privacy: {e}");
            return 2;
        }
    };
    for h in &hits {
        println!("privacy: {h}");
    }
    if hits.is_empty() {
        println!("privacy: clean");
        0
    } else {
        println!("privacy: {} hit(s); use neutral names (example-web, builder-1, /srv/repos, someone@example.com)", hits.len());
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_with(files: &[(&str, &str)], words: &[&str]) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_path_buf();
        assert!(Command::new("git").args(["init", "-q"]).arg(&root).status().unwrap().success());
        std::fs::write(root.join(DENYLIST), words.iter().map(|w| sha(w) + "\n").collect::<String>()).unwrap();
        for (rel, text) in files {
            let p = root.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        (d, root)
    }

    fn hits(root: &Path) -> Vec<String> {
        let mut h = check(root, &load_denylist(root).unwrap()).unwrap();
        h.sort();
        h
    }

    #[test]
    fn the_repository_is_clean() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert_eq!(hits(&root), Vec::<String>::new());
    }

    #[test]
    fn the_denylist_holds_hashes_only() {
        let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(DENYLIST)).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        assert!(lines.len() >= 3);
        assert!(lines.iter().all(|l| is_hex64(l)));
    }

    #[test]
    fn a_word_in_a_file_or_a_path_is_found_and_never_printed() {
        let (_d, root) = repo_with(&[("a/b.txt", "fine\nhost secretname here\n"), ("dir-secretname/x.txt", "clean")], &["secretname"]);
        let h = hits(&root);
        assert_eq!(h, vec!["a/b.txt:2 (deny-listed word)", "dir-secretname/x.txt (path: deny-listed word)"]);
        assert!(!h.concat().contains("secretname x"));
    }

    #[test]
    fn case_and_punctuation_do_not_hide_a_word() {
        let (_d, root) = repo_with(&[("x.log", "ssh SecretName-01\n"), ("y.toml", "name = \"SECRETNAME\"\n"), ("z.txt", "secretnames and xsecretname\n")], &["secretname"]);
        assert_eq!(hits(&root), vec!["x.log:1 (deny-listed word)", "y.toml:1 (deny-listed word)"]);
    }

    #[test]
    fn machine_paths_and_real_emails_are_found() {
        // built at run time, so this source file itself stays clean
        let (q, at) = ("Q:", "@");
        let p = format!("build in {q}\\work\\x\nor {q}/work/x\nsee https://example.com/a and /home/runner/x and /Users/you/x\n");
        let h = format!("cd /{}/alice/src\n", "home");
        let e = format!("write to someone{at}example.com or noreply{at}anthropic.com\nor real.person{at}mail-provider.io\n");
        let (_d, root) = repo_with(&[("p.md", &p), ("h.md", &h), ("e.md", &e)], &["secretname"]);
        assert_eq!(hits(&root), vec!["e.md:2 (email)", "h.md:1 (machine path)", "p.md:1 (machine path)", "p.md:2 (machine path)"]);
    }

    #[test]
    fn a_clean_tree_passes_and_exit_codes_hold() {
        let (_d, root) = repo_with(&[("a.txt", "builder-1 host-a /srv/repos example-web")], &["secretname"]);
        assert_eq!(hits(&root), Vec::<String>::new());
        assert_eq!(run(&root, None), 0);
        let (_d2, dirty) = repo_with(&[("a.txt", "secretname")], &["secretname"]);
        assert_eq!(run(&dirty, None), 1);
        std::fs::write(dirty.join(DENYLIST), "not-a-hash\n").unwrap();
        assert_eq!(run(&dirty, None), 2);
        assert_eq!(sha("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
