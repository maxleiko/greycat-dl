use std::{
    io::BufWriter,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use clap::Parser;
use dotenvy::dotenv;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use human_bytes::human_bytes;

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

    let mut files = Vec::with_capacity(1024);
    println!("Listing files from {files_root}\n");
    visit_dir(&args.outdir.to_string_lossy(), &files_root, "", &mut files)?;
    let total_files = files.len();
    print!("{MOVE_CURSOR_UP}{CLEAR_LINE}");

    if args.dry_run {
        let total_size = files.iter().fold(0, |acc, f| acc + f.size.unwrap_or(0));
        println!("Found {total_files} files to download which account for {}", human_bytes(total_size as f64));
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

fn visit_dir(outdir: &str, root: &str, dirpath: &str, files: &mut Vec<Entry>) -> Result<()> {
    let url = format!("{root}{dirpath}");
    let mut res = ureq::get(&url).call()?;
    let entries: Vec<File> = res.body_mut().read_json()?;
    for entry in entries {
        if entry.path.ends_with('/') {
            visit_dir(outdir, root, &entry.path, files)?;
        } else {
            let url = format!("{root}{}", entry.path);
            let filepath = format!("{outdir}/{}", entry.path);
            let n = files.len();
            print!("{MOVE_CURSOR_UP}{CLEAR_LINE}");
            println!("{n:6} {filepath}");
            let filepath = PathBuf::from(filepath);
            files.push(Entry {
                url,
                filepath,
                size: entry.size,
            });
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
