//! Content-addressed blob store: the seed of the torrent layer.
//!
//! Every blob is addressed by its BLAKE3 hash and verified on every
//! read, so a corrupted or tampered file is detected rather than
//! served. A `JobDescriptor` is the torrent-file analog: a small,
//! signed-by-structure listing of the content hashes (manifest, ELF,
//! input) needed to reconstruct a job anywhere. Once the network layer
//! exists, peers fetch descriptors, then blobs, from each other —
//! verification needs no trust in the serving peer.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContentId([u8; 32]);

impl From<ContentId> for [u8; 32] {
    fn from(id: ContentId) -> Self {
        id.0
    }
}

impl ContentId {
    pub fn from_data(data: &[u8]) -> Self {
        ContentId(*blake3::hash(data).as_bytes())
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 64 {
            return Err(format!("content id: bad length {}", s.len()));
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("content id: bad hex: {e}"))?;
        }
        Ok(ContentId(out))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// `root` holds `blobs/<2-hex-prefix>/<64-hex>` files.
    pub fn open(root: impl Into<PathBuf>) -> Result<Store, String> {
        let root = root.into();
        std::fs::create_dir_all(root.join("blobs")).map_err(|e| format!("store: {e}"))?;
        Ok(Store { root })
    }

    fn blob_path(&self, id: &ContentId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join("blobs").join(&hex[..2]).join(&hex)
    }

    /// Store `data`; idempotent (same bytes → same id, no rewrite).
    pub fn put(&self, data: &[u8]) -> Result<ContentId, String> {
        let id = ContentId::from_data(data);
        let path = self.blob_path(&id);
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| format!("store: {e}"))?;
            }
            // Write-then-verify: the stored file must hash back to its
            // own name before put() reports success.
            std::fs::write(&path, data).map_err(|e| format!("store: {e}"))?;
            let read_back = std::fs::read(&path).map_err(|e| format!("store: {e}"))?;
            if ContentId::from_data(&read_back) != id {
                return Err("store: written blob failed self-verification".into());
            }
        }
        Ok(id)
    }

    /// Read a blob and verify it against its address. Tampered or
    /// corrupted content is an error, never silent data.
    pub fn get(&self, id: &ContentId) -> Result<Vec<u8>, String> {
        let path = self.blob_path(id);
        let data = std::fs::read(&path).map_err(|e| format!("store: {e}"))?;
        if ContentId::from_data(&data) != *id {
            return Err(format!(
                "store: blob {} failed integrity check (corrupted or tampered)",
                id.to_hex()
            ));
        }
        Ok(data)
    }

    pub fn has(&self, id: &ContentId) -> Result<bool, String> {
        Ok(self.blob_path(id).exists())
    }

    /// Re-hash every blob in the store. Returns the count; the first
    /// mismatch is an error naming the blob.
    pub fn verify_all(&self) -> Result<usize, String> {
        let blobs = self.root.join("blobs");
        let mut count = 0usize;
        for prefix in std::fs::read_dir(&blobs).map_err(|e| format!("store: {e}"))? {
            let prefix = prefix.map_err(|e| format!("store: {e}"))?.path();
            for entry in std::fs::read_dir(&prefix).map_err(|e| format!("store: {e}"))? {
                let path = entry.map_err(|e| format!("store: {e}"))?.path();
                let data = std::fs::read(&path).map_err(|e| format!("store: {e}"))?;
                let id = ContentId::from_data(&data);
                if path.file_name().map(|f| f.to_string_lossy().to_string()).as_deref() != Some(id.to_hex().as_str()) {
                    return Err(format!(
                        "store: blob at {} does not match its content hash",
                        path.display()
                    ));
                }
                count += 1;
            }
        }
        Ok(count)
    }
}

/// The torrent-file analog: the content hashes needed to reconstruct a
/// job anywhere. Small, copyable, and its integrity is implied by the
/// hashes it contains.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct JobDescriptor {
    pub job_id: String,
    /// Content id of the raw job.json manifest bytes.
    pub manifest: String,
    pub elf: String,
    pub input: String,
}

/// Publish a job directory into the store: manifest, ELF, and input
/// become blobs; the returned descriptor reconstructs the job.
pub fn publish(job_dir: &Path, store: &Store) -> Result<JobDescriptor, String> {
    let manifest_bytes = std::fs::read(job_dir.join("job.json")).map_err(|e| format!("publish: {e}"))?;
    let manifest: jobfmt::JobManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| format!("publish: {e}"))?;
    let elf = std::fs::read(job_dir.join(&manifest.elf)).map_err(|e| format!("publish: {e}"))?;
    let input = std::fs::read(job_dir.join(&manifest.input)).map_err(|e| format!("publish: {e}"))?;

    Ok(JobDescriptor {
        job_id: manifest.id.clone(),
        manifest: store.put(&manifest_bytes)?.to_hex(),
        elf: store.put(&elf)?.to_hex(),
        input: store.put(&input)?.to_hex(),
    })
}

/// Reconstruct a job directory from a descriptor + store. Every byte
/// is hash-verified on the way out; the result is a normal job
/// directory that `jobfmt::load_dir` accepts.
pub fn materialize(
    desc: &JobDescriptor,
    store: &Store,
    out_dir: &Path,
) -> Result<(), String> {
    let manifest_bytes = store.get(&ContentId::from_hex(&desc.manifest)?)?;
    let manifest: jobfmt::JobManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|e| format!("materialize: {e}"))?;
    // The manifest is untrusted wire data: its file fields must be
    // plain names, or a crafted descriptor could write outside out_dir.
    jobfmt::confined_name(&manifest.elf)?;
    jobfmt::confined_name(&manifest.input)?;
    let elf = store.get(&ContentId::from_hex(&desc.elf)?)?;
    let input = store.get(&ContentId::from_hex(&desc.input)?)?;

    std::fs::create_dir_all(out_dir).map_err(|e| format!("materialize: {e}"))?;
    std::fs::write(out_dir.join("job.json"), manifest_bytes).map_err(|e| format!("materialize: {e}"))?;
    std::fs::write(out_dir.join(&manifest.elf), elf).map_err(|e| format!("materialize: {e}"))?;
    std::fs::write(out_dir.join(&manifest.input), input).map_err(|e| format!("materialize: {e}"))?;
    Ok(())
}

/// The descriptor's own identity: the hash of its canonical JSON. Two
/// parties holding descriptors with this hash hold identical listings.
pub fn descriptor_id(desc: &JobDescriptor) -> Result<ContentId, String> {
    let json = serde_json::to_vec(desc).map_err(|e| format!("descriptor: {e}"))?;
    Ok(ContentId::from_data(&json))
}
