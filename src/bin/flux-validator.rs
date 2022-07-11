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
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    path::PathBuf,
    process::Command,
};
use termtree::Tree;

#[derive(Parser, Debug)]
#[clap(name = "flux-validator",
       author,
       version,
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

fn print_completions<G: Generator>(gen: G, cmd: &mut clap::App) {
    generate(gen, cmd, cmd.get_name().to_string(), &mut std::io::stdout());
}

fn main() -> Result<(), Error> {
    let args = Args::parse();

    if let Some(generator) = args.gen {
        print_completions(generator, &mut Args::into_app());
        return Ok(());
    };

    let dir = args.dir.ok_or(Error::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "Need to specify the directory to check",
    )))?;

    let mut keys_used = HashMap::<String, HashSet<PathBuf>>::new();
    let mut documents = HashMap::<Document, HashSet<PathBuf>>::new();
    let mut rotated = HashSet::<PathBuf>::new();

    // Loop through `*-sops.yml` files in the directory, recursively
    for f in glob::glob(&format!("{}/**/*-sops.yml", dir.to_str().unwrap())).map_err(Error::new)? {
        let path = f.map_err(Error::new)?;
        let f = std::fs::File::open(path.clone()).map_err(Error::new)?;

        // Loop through all the documents inthe file
        for s in serde_yaml::Deserializer::from_reader(f) {
            let d = Document::deserialize(s).map_err(Error::new)?;

            // Get KMS keys
            if let Some(sops) = &d.sops {
                // Rotate the kms key if the flag is enabled and the file has not been affected yet.
                if args.rotate && rotated.insert(path.clone()) {
                    // If the file contains multiple documents, it will be rotated once for each document. Need to fix...
                    println!("Rotating keys for {}", path.to_str().unwrap());
                    // decrypt the file
                    Command::new("sops")
                        .args(["-d", "-i", path.to_str().unwrap()])
                        .output()
                        .unwrap();

                    // Encrypt the file
                    Command::new("sops")
                        .args([
                            "-e",
                            "-i",
                            "-k",
                            &args.kms_arn.clone().unwrap(),
                            path.to_str().unwrap(),
                        ])
                        .output()
                        .unwrap();
                }

                // Get the kms used in the directory
                if let Some(docs) = keys_used.get_mut(&sops.arn) {
                    // Key already found, add to the set of files using it
                    docs.insert(path.clone());
                } else {
                    // Key not used before, create a new set and add it.
                    let mut docs = HashSet::<PathBuf>::new();
                    docs.insert(path.clone());
                    keys_used.insert(sops.arn.clone(), docs);
                };
            };

            // Get duped documents
            if let Some(docs) = documents.get_mut(&d) {
                // Document already found, add path to the set
                // Probably means the document is duped
                docs.insert(path.clone());
            } else {
                // Document not found before, create a new set and add path
                let mut docs = HashSet::<PathBuf>::new();
                docs.insert(path.clone());
                documents.insert(d, docs);
            };
        }
    }

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

    let mut dup_tree = Tree::new("duped documents".to_string());
    for (doc, path) in documents {
        if path.len() <= 1 {
            continue;
        };
        let mut name_branch = Tree::new(doc.meta.name);
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

/// A struct representing a k8s document.
/// Stores the kind, name, namespace, and sops information.
/// Should be equal when the kind, metadata information, and sops data is the same.
/// There is a potential bug if two items have the same name but encrypted differently.
/// Should manually implement Eq and Hash in that case.
#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
struct Document {
    /// The kind of the document, usually a "deployment"
    kind: String,
    /// Metadata, name and namespace
    #[serde(rename = "metadata")]
    meta: Metadata,
    /// SOPS encryption, can be absent.
    sops: Option<Sops>,
}

/// Metadata helper struct
/// No straight forward way to indicate a nested field.
#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
struct Metadata {
    name: String,
    namespace: Option<String>,
}

/// SOPS helper struct
#[derive(Debug, serde_query::Deserialize, Eq, PartialEq, Hash, Clone)]
struct Sops {
    #[query(".kms.[0].arn")]
    arn: String,
}

/// custom error struct
/// Need a way return a single error type.
#[derive(Debug)]
struct Error {
    err: Box<dyn std::error::Error>,
}

impl std::error::Error for Error {}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Error: {}", self.err)
    }
}

impl Error {
    fn new<E: 'static>(err: E) -> Self
    where
        E: std::error::Error,
    {
        Error { err: Box::new(err) }
    }
}
