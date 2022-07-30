#![deny(
    missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications
)]

//! Validates that a flux repo will not cause issues when deployed using flux.
//!
//! Checks for:
//! 1. Duplicate names. Only checks deployments.
//! 2. KMS keys used. Will only return the kms keys used.
//!   * Can also rotate kms keys using sops.
//!
//! ### Future plans
//! 1. Flags any references to other clusters
//!    * Useful when copying form one cluster to another

use clap::{ArgGroup, CommandFactory, Parser};
use clap_complete::{generate, Generator, Shell};
use eyre::{eyre, Result};
use futures::future::{try_join, try_join3};
use libs::flux::*;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use termtree::Tree;

#[derive(Parser, Debug)]
#[clap(name = "flux-validator",
       author,
       version = "0.1",
       about = "Validates a direcotory for usage with Flux.",
       long_about = None)]
#[clap(group(
    ArgGroup::new("kms")
        .args(&["rotate"])
        .requires_all(&[ "kms-arn", "dir"])
))]
struct Args {
    /// Rotate the KMS key
    #[clap(short, long)]
    rotate: bool,

    /// The KMS ARN
    #[clap(long = "kms", value_parser, env = "SOPS_KMS_ARN")]
    kms_arn: Option<String>,

    /// The directory to check.
    dir: Option<PathBuf>,

    /// Generate shell completion
    #[clap(short, long)]
    gen: Option<Shell>,
}

// Needs to be improved. Right now it is broken and doesn't complete file paths. :(
fn print_completions<G: Generator>(gen: G, cmd: &mut clap::App) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(generator) = args.gen {
        print_completions(generator, &mut Args::into_app());
        return Ok(());
    };

    let dir = args
        .dir
        .ok_or_else(|| eyre!("User did not specify directory"))?;

    let paths = paths_to_vec(glob::glob(&format!(
        "{}/**/*-sops.yml",
        dir.to_str().unwrap()
    ))?)?;

    let keys_used: HashMap<String, HashSet<PathBuf>>;
    let documents: HashMap<Document, HashSet<PathBuf>>;
    if args.rotate {
        (keys_used, documents, _) = try_join3(
            get_kms_keys(&paths),
            get_dup_documents(&paths),
            rotate_kms_keys(&args.kms_arn.expect("A kms arn"), &paths),
        )
        .await?;
    } else {
        (keys_used, documents) = try_join(get_kms_keys(&paths), get_dup_documents(&paths)).await?;
    };

    // Maybe turn this also into a function
    let mut key_tree = Tree::new("kms_keys".to_string());
    for (key, files) in keys_used {
        let mut key_branch = Tree::new(key);
        let s_files: HashSet<String> = files
            .iter()
            .map(|p| p.to_str().unwrap().to_string())
            .collect();
        key_branch.extend(s_files);
        key_tree.push(key_branch);
    }

    // This as well?
    let mut dup_tree = Tree::new("duped documents".to_string());
    for (doc, path) in documents {
        if path.len() <= 1 {
            continue;
        };
        let mut name_branch = Tree::new(doc.get_meta().get_name().to_string());
        let s_files: HashSet<String> = path
            .iter()
            .map(|p| p.to_str().unwrap().to_string())
            .collect();
        name_branch.extend(s_files);
        dup_tree.push(name_branch);
    }

    println!("Duped names");
    println!("{dup_tree}");
    println!("kms keys used");
    println!("{key_tree}");

    Ok(())
}
