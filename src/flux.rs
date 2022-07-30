use eyre::Result;
use serde::Deserialize;
use serde_yaml::Deserializer;
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::PathBuf,
    process::Command,
};

type Paths = Vec<PathBuf>;

/// A struct representing a k8s document.
/// Stores the kind, name, namespace, and sops information.
/// Should be equal when the kind, metadata information, and sops data is the same.
/// There is a potential bug if two items have the same name but encrypted differently.
/// Should manually implement Eq and Hash in that case.
#[derive(Debug, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Document {
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
pub struct Metadata {
    name: String,
    namespace: Option<String>,
}

/// SOPS helper struct
#[derive(Debug, serde_query::Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct Sops {
    #[query(".kms.[0].arn")]
    arn: String,
}

impl Document {
    pub fn get_meta(&self) -> &Metadata {
        &self.meta
    }

    pub fn has_sops(&self) -> bool {
        self.sops.is_some()
    }

    pub fn get_sops(&self) -> &Option<Sops> {
        &self.sops
    }
}

impl Sops {
    pub fn get_arn(&self) -> &str {
        &self.arn
    }
}

impl Metadata {
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

pub fn paths_to_vec(paths: glob::Paths) -> Result<Vec<PathBuf>> {
    let mut v = vec![];
    for p in paths {
        v.push(p?)
    }
    Ok(v)
}

pub async fn get_kms_keys(paths: &Paths) -> Result<HashMap<String, HashSet<PathBuf>>> {
    let mut keys_used = HashMap::<String, HashSet<PathBuf>>::new();
    for path in paths {
        let f = File::open(path.clone())?;
        for s in Deserializer::from_reader(f) {
            let d = Document::deserialize(s)?;
            if let Some(sops) = d.sops {
                if let Some(docs) = keys_used.get_mut(sops.get_arn()) {
                    // Key already found, add to the set of files using it
                    docs.insert(path.clone());
                } else {
                    // Key not used before, create a new set and add it.
                    let mut docs = HashSet::<PathBuf>::new();
                    docs.insert(path.clone());
                    keys_used.insert(sops.get_arn().to_string(), docs);
                };
            }
        }
    }
    Ok(keys_used)
}

pub async fn rotate_kms_keys(key: &str, paths: &Paths) -> Result<()> {
    for path in paths {
        Command::new("sops")
            .args(["-d", "-i", path.to_str().unwrap()])
            .output()?;

        // Encrypt the file
        Command::new("sops")
            .args(["-e", "-i", "-k", key, path.to_str().unwrap()])
            .output()?;
    }
    Ok(())
}

pub async fn get_dup_documents(paths: &Paths) -> Result<HashMap<Document, HashSet<PathBuf>>> {
    let mut documents = HashMap::<Document, HashSet<PathBuf>>::new();
    for path in paths {
        let f = File::open(path.clone())?;
        for s in Deserializer::from_reader(f) {
            let d = Document::deserialize(s)?;
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

    Ok(documents)
}
