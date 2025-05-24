use std::{
    io::BufWriter,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Sender},
        Arc,
    },
    thread,
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::Parser;
use dotenvy::dotenv;
use human_bytes::human_bytes;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MOVE_CURSOR_UP: &str = "\x1B[1A";
const CLEAR_LINE: &str = "\x1B[2K";

#[derive(Debug, Parser)]
struct Args {
    #[clap(index = 1, help = "GreyCat server to download files from")]
    url: String,
    #[clap(long, help = "Output directory", default_value = "files")]
    outdir: PathBuf,
    #[clap(
        long,
        help = "GreyCat user name to connect with",
        requires = "password",
        env = "USERNAME"
    )]
    username: Option<String>,
    #[clap(long, help = "GreyCat user password to connect with", env = "PASSWORD")]
    password: Option<String>,
    #[clap(
        long,
        help = "Won't actually download the files, just print stats",
        default_value = "false"
    )]
    dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct File {
    path: String,
    size: Option<usize>,
}

#[derive(Debug, Serialize)]
struct Entry {
    url: String,
    filepath: PathBuf,
    size: Option<usize>,
}

fn main() -> Result<()> {
    env_logger::init();
    dotenv().ok();

    let args = Args::parse();

    let token = if let (Some(username), Some(password)) = (args.username, args.password) {
        let server_root = if args.url.ends_with('/') {
            args.url.clone()
        } else {
            format!("{}/", args.url)
        };
        Some(get_token(&server_root, &username, &password)?)
    } else {
        None
    };

    let files_root = if args.url.ends_with('/') {
        format!("{}files/", args.url)
    } else {
        format!("{}/files/", args.url)
    };
    let files_root = Arc::new(files_root);
    let outdir = args.outdir.to_string_lossy();

    let mut files = Vec::with_capacity(1024);

    let (tx, rx) = mpsc::channel();

    println!("Listing files from {files_root}\n");
    let files_root_clone = Arc::clone(&files_root);
    thread::spawn(move || {
        visit_dir(files_root_clone, "", 0, tx.clone()).expect("les problemes");
    });

    rx.iter().for_each(|file| {
        let url = format!("{files_root}{}", file.path);
        let filepath = format!("{outdir}/{}", file.path);
        let n = files.len() + 1;
        print!("{MOVE_CURSOR_UP}{CLEAR_LINE}");
        println!("{n:6} {filepath}");
        let filepath = PathBuf::from(filepath);
        files.push(Entry {
            url,
            filepath,
            size: file.size,
        });
    });

    let total_files = files.len();

    if args.dry_run {
        let total_size = files.iter().fold(0, |acc, f| acc + f.size.unwrap_or(0));
        println!(
            "Found {total_files} files to download which account for {}",
            human_bytes(total_size as f64)
        );
        return Ok(());
    }

    println!("Found {} files to download...\n", total_files);
    let remaining = AtomicUsize::new(total_files);
    files
        .par_iter()
        .for_each(|entry| match download_file(entry, token.as_deref()) {
            Ok(_) => {
                let n = remaining.fetch_sub(1, Ordering::Relaxed) - 1;
                println!(
                    "{MOVE_CURSOR_UP}{CLEAR_LINE}{n:6}/{total_files} {}",
                    entry.filepath.to_string_lossy()
                );
            }
            Err(err) => {
                remaining.fetch_sub(1, Ordering::Relaxed);
                println!(
                    "{CLEAR_LINE}[ERROR][{}] {err}\n",
                    entry.filepath.to_string_lossy()
                )
            }
        });

    print!("{MOVE_CURSOR_UP}{CLEAR_LINE}");
    println!("Downloaded {} files", total_files);

    Ok(())
}

fn visit_dir(root: Arc<String>, dirpath: &str, depth: usize, tx: Sender<File>) -> Result<()> {
    let url = format!("{root}{dirpath}");
    let mut res = ureq::get(&url).call()?;
    let entries: Vec<File> = res.body_mut().read_json()?;
    for file in entries {
        let tx = tx.clone();
        if file.path.ends_with('/') {
            let root = Arc::clone(&root);
            if depth == 0 {
                thread::spawn(move || {
                    visit_dir(root, &file.path, depth + 1, tx).expect("les problemes");
                });
            } else {
                visit_dir(root, &file.path, depth + 1, tx)?;
            }
        } else {
            tx.send(file)?;
        }
    }
    Ok(())
}

fn download_file(entry: &Entry, token: Option<&str>) -> Result<()> {
    std::fs::create_dir_all(entry.filepath.parent().unwrap())?;
    let mut file = BufWriter::new(std::fs::File::create(&entry.filepath)?);
    let mut req = ureq::get(&entry.url);
    if let Some(token) = token {
        req = req.header("Authorization", token);
    }
    let mut body = req.call()?.into_body();
    let mut reader = body.as_reader();
    std::io::copy(&mut reader, &mut file)?;
    Ok(())
}

fn get_token(url: &str, username: &str, password: &str) -> Result<String> {
    // Compute SHA-256 hash of the password
    let hash = Sha256::digest(password.as_bytes());
    // Hex encode the hashed password
    let hash_hex = hex::encode(hash);
    // Encode username:hash in Base64 (URL-safe, no padding)
    let credentials = format!("{}:{}", username, hash_hex);
    let encoded = STANDARD_NO_PAD.encode(credentials);

    let token = ureq::post(&format!("{url}runtime::User::login"))
        .send_json(serde_json::json!([encoded, false]))
        .context("failed to send request")?
        .body_mut()
        .read_json::<String>()
        .context("failed to read response")?;

    Ok(token)
}
