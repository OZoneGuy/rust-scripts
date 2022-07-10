#![allow(unused_variables)]
use clap::{ArgGroup, Parser};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::process::Command;
use termtree::Tree;

/// Validates that a flux repo will not cause issues when deployed using flux
///
/// Checks for:
/// 1. Duplicate names. Only checks deployments.
/// 2. KMS keys used. Will only return the kms keys used.
///   * Can also rotate kms keys using sops.
///
/// ### Future plans
/// 1. Flags any references to other clusters
///    * Useful when copying form one cluster to another

#[derive(Parser, Debug)]
#[clap(author, version, about = "Validates a direcotory for usage with Flux.", long_about = None)]
#[clap(group(
    ArgGroup::new("kms")
        .args(&["rotate"])
        .requires("kms-arn")
))]
struct Args {
    /// Rotate the KMS key
    #[clap(short, long)]
    rotate: bool,

    /// The KMS ARN
    #[clap(long = "kms", value_parser, env = "KMS_ARN")]
    kms_arn: Option<String>,

    /// The directory to check.
    dir: String,
}

fn main() -> std::result::Result<(), Error> {
    let args = Args::parse();
    let mut keys_used = HashMap::<String, HashSet<std::path::PathBuf>>::new();
    let mut documents = HashMap::<Document, HashSet<std::path::PathBuf>>::new();
    for f in glob::glob(&format!("{}/**/*-sops.yml", args.dir)).map_err(Error::new)? {
        let path = f.map_err(Error::new)?;
        let f = std::fs::File::open(path.clone()).map_err(Error::new)?;
        for s in serde_yaml::Deserializer::from_reader(f) {
            let d = Document::deserialize(s).map_err(Error::new)?;

            // Get KMS keys
            if let Some(sops) = &d.sops {
                if !args.rotate {
                    if let Some(docs) = keys_used.get_mut(&sops.arn) {
                        docs.insert(path.clone());
                    } else {
                        let mut docs = HashSet::<std::path::PathBuf>::new();
                        docs.insert(path.clone());
                        keys_used.insert(sops.arn.clone(), docs);
                    };
                } else {
                    println!("Rotating keys for {}", path.to_str().unwrap());
                    // decrypt the file
                    Command::new("sops")
                        .args(["-d", "-i", path.to_str().unwrap()])
                        .output()
                        .map_err(Error::new)?;

                    // Encrypt the file
                    Command::new("sops")
                        .args([
                            "-e",
                            "-i",
                            &format!(
                                "{}",
                                args.kms_arn
                                    .as_ref()
                                    .expect("KMS Key should have been defined")
                            ),
                        ])
                        .output()
                        .map_err(Error::new)?;
                }
            };

            // Get duped documents
            if let Some(docs) = documents.get_mut(&d) {
                docs.insert(path.clone());
            } else {
                let mut docs = HashSet::<std::path::PathBuf>::new();
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

#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
struct Document {
    kind: String,
    #[serde(rename = "metadata")]
    meta: Metadata,
    sops: Option<Sops>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
struct Metadata {
    name: String,
    namespace: Option<String>,
}

#[derive(Debug, serde_query::Deserialize, Eq, PartialEq, Hash, Clone)]
struct Sops {
    #[query(".kms.[0].arn")]
    arn: String,
}

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
