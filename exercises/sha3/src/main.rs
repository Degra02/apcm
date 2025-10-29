use std::{fs, path::PathBuf};

use sha3::sha3::ShaVariant;
use clap::{Parser};

/// Compute SHA3 hashes
#[derive(Parser, Debug)]
struct Args {
    /// Input file to hash
    #[clap(short, long, default_value = "")]
    file: PathBuf,

    /// SHA3 variant to use (224, 256, 384, 512)
    #[clap(short, long, default_value_t = ShaVariant::V256)]
    variant: ShaVariant
}

fn main() -> std::io::Result<()>{
    let args = Args::parse();

    let path = &args.file;
    let data = fs::read(path)?;
    let mut hasher = sha3::sha3::SHA3::new(args.variant);

    hasher.update(&data);
    let digest = hasher.finalize();

    println!("SHA3-{}: {} - {}", args.variant, digest, path.display());
    Ok(())
}
