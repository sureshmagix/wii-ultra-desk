//! Root-confined file operations for the native agent.
//!
//! Renderer supplied paths are never passed to the ambient filesystem. Local
//! setup canonicalizes explicitly approved roots once, and every later access
//! walks a `cap_std::fs::Dir` one component at a time with `O_NOFOLLOW` on
//! Unix. Symlinks, absolute paths, parent traversal, non-UTF-8 names and
//! special files are refused rather than followed or displayed.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use ambient_authority::ambient_authority;
use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AgentError, Result};

pub const MAX_FILE_ROOTS: usize = 8;
pub const MAX_LIST_ENTRIES: usize = 256;
pub const MAX_TRANSFER_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 32 * 1024;
pub const PART_RETENTION_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_TREE_ENTRIES: usize = 512;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRootsConfig {
    pub read_roots: Vec<String>,
    pub write_roots: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileManifest {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileSelection {
    pub is_directory: bool,
    /// Directory paths include the selected directory itself, so an empty
    /// selected directory can be recreated at the destination.
    pub directories: Vec<String>,
    pub manifests: Vec<FileManifest>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct PartMetadata {
    destination: String,
    size: u64,
    sha256: String,
}

pub struct RootedFileSystem {
    read_roots: Vec<Dir>,
    write_roots: Vec<Dir>,
}

pub struct WriteTransfer {
    destination: String,
    part_name: OsString,
    metadata_name: OsString,
    parent: Dir,
    expected: FileManifest,
    written: u64,
}

fn filesystem_error(message: impl Into<String>) -> AgentError {
    AgentError::FileTransfer(message.into())
}

fn io_error(context: &str, error: std::io::Error) -> AgentError {
    // Deliberately return a bounded operation category rather than an ambient
    // path, which could expose host layout through local diagnostics.
    let kind = match error.kind() {
        std::io::ErrorKind::NotFound => "not_found",
        std::io::ErrorKind::PermissionDenied => "permission_denied",
        std::io::ErrorKind::AlreadyExists => "already_exists",
        std::io::ErrorKind::StorageFull => "disk_full",
        std::io::ErrorKind::WriteZero | std::io::ErrorKind::UnexpectedEof => "io_incomplete",
        _ => "io_failed",
    };
    filesystem_error(format!("{context}:{kind}"))
}

fn valid_relative(value: &str) -> Result<Vec<OsString>> {
    if value.is_empty() || value.len() > 1_024 || value.contains('\0') {
        return Err(filesystem_error("invalid_relative_path"));
    }
    let path = Path::new(value);
    let mut output = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(name) if name.to_str().is_some_and(portable_component) => {
                output.push(name.to_os_string());
            }
            Component::CurDir if output.is_empty() => {}
            _ => return Err(filesystem_error("path_traversal_rejected")),
        }
    }
    Ok(output)
}

// A transfer can cross macOS, Windows and Linux. Refuse components that cannot
// be represented safely on one of those filesystems rather than silently
// changing a name at the destination. This also keeps control/newline-bearing
// names out of the renderer event stream.
fn portable_component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || value.ends_with('.')
        || value.ends_with(' ')
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*'
                )
        })
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(
        stem.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn root_path(value: &str) -> Result<PathBuf> {
    let candidate = Path::new(value);
    if !candidate.is_absolute() || value.len() > 2_048 {
        return Err(filesystem_error("root_must_be_absolute"));
    }
    let canonical = std::fs::canonicalize(candidate).map_err(|error| io_error("root", error))?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| io_error("root", error))?;
    if !metadata.is_dir() {
        return Err(filesystem_error("root_must_be_directory"));
    }
    Ok(canonical)
}

fn parse_virtual_path(value: &str) -> Result<(usize, Vec<OsString>)> {
    let (root, tail) = value
        .split_once('/')
        .ok_or_else(|| filesystem_error("missing_root_selector"))?;
    if root.is_empty() || root.len() > 2 || !root.bytes().all(|value| value.is_ascii_digit()) {
        return Err(filesystem_error("invalid_root_selector"));
    }
    let index = root
        .parse::<usize>()
        .map_err(|_| filesystem_error("invalid_root_selector"))?;
    Ok((index, valid_relative(tail)?))
}

fn nofollow_options(read: bool, write: bool, create_new: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(read).write(write).create_new(create_new);
    #[cfg(unix)]
    {
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
}

fn open_child_dir(parent: &Dir, name: &OsStr) -> Result<Dir> {
    let metadata = parent
        .symlink_metadata(name)
        .map_err(|error| io_error("path_component", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(filesystem_error("symlink_or_non_directory_rejected"));
    }
    let file = parent
        .open_with(name, &nofollow_options(true, false, false))
        .map_err(|error| io_error("path_component", error))?;
    Ok(Dir::from_std_file(file.into_std()))
}

fn open_parent(root: &Dir, components: &[OsString], create: bool) -> Result<(Dir, OsString)> {
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| filesystem_error("file_path_required"))?;
    let mut current = root.try_clone().map_err(|error| io_error("root", error))?;
    for component in parents {
        match current.symlink_metadata(component) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(filesystem_error("symlink_or_non_directory_rejected"));
                }
            }
            Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                current
                    .create_dir(component)
                    .or_else(|error| {
                        (error.kind() == std::io::ErrorKind::AlreadyExists)
                            .then_some(())
                            .ok_or(error)
                    })
                    .map_err(|error| io_error("create_parent", error))?;
            }
            Err(error) => return Err(io_error("path_component", error)),
        }
        current = open_child_dir(&current, component)?;
    }
    Ok((current, leaf.clone()))
}

fn sha256_file(file: &mut cap_std::fs::File) -> Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_error("seek", error))?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; MAX_CHUNK_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error("read", error))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or_else(|| filesystem_error("file_too_large"))?;
        if size > MAX_TRANSFER_BYTES {
            return Err(filesystem_error("file_too_large"));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((size, format!("{:x}", hasher.finalize())))
}

impl FileRootsConfig {
    pub fn canonicalize(read_roots: &[String], write_roots: &[String]) -> Result<Self> {
        if read_roots.len() > MAX_FILE_ROOTS || write_roots.len() > MAX_FILE_ROOTS {
            return Err(filesystem_error("too_many_roots"));
        }
        let canonicalize_all = |roots: &[String]| -> Result<Vec<String>> {
            let mut output = Vec::new();
            for root in roots {
                let root = root_path(root)?;
                let root = root
                    .to_str()
                    .ok_or_else(|| filesystem_error("non_utf8_root"))?
                    .to_owned();
                if !output.contains(&root) {
                    output.push(root);
                }
            }
            Ok(output)
        };
        Ok(Self {
            read_roots: canonicalize_all(read_roots)?,
            write_roots: canonicalize_all(write_roots)?,
        })
    }
}

impl RootedFileSystem {
    pub fn open(config: &FileRootsConfig) -> Result<Self> {
        let open_roots = |roots: &[String]| -> Result<Vec<Dir>> {
            roots
                .iter()
                .map(|root| {
                    Dir::open_ambient_dir(root, ambient_authority())
                        .map_err(|error| io_error("root_open", error))
                })
                .collect()
        };
        Ok(Self {
            read_roots: open_roots(&config.read_roots)?,
            write_roots: open_roots(&config.write_roots)?,
        })
    }

    fn root<'a>(roots: &'a [Dir], index: usize) -> Result<&'a Dir> {
        roots
            .get(index)
            .ok_or_else(|| filesystem_error("root_not_approved"))
    }

    pub fn list(&self, virtual_path: &str) -> Result<Vec<FileEntry>> {
        let (root_index, components) = parse_virtual_path(virtual_path)?;
        let root = Self::root(&self.read_roots, root_index)?;
        let directory = if components.is_empty() {
            root.try_clone().map_err(|error| io_error("root", error))?
        } else {
            let (parent, leaf) = open_parent(root, &components, false)?;
            open_child_dir(&parent, &leaf)?
        };
        let mut output = Vec::new();
        for entry in directory
            .read_dir(".")
            .map_err(|error| io_error("list", error))?
        {
            let entry = entry.map_err(|error| io_error("list", error))?;
            let name = match entry.file_name().into_string() {
                Ok(name) if portable_component(&name) => name,
                _ => continue,
            };
            let type_ = entry.file_type().map_err(|error| io_error("list", error))?;
            if type_.is_symlink() || !(type_.is_dir() || type_.is_file()) {
                continue;
            }
            let metadata = entry.metadata().map_err(|error| io_error("list", error))?;
            let path = if virtual_path.ends_with('/') {
                format!("{virtual_path}{name}")
            } else {
                format!("{virtual_path}/{name}")
            };
            output.push(FileEntry {
                name,
                path,
                kind: if type_.is_dir() { "directory" } else { "file" }.into(),
                size: metadata.len(),
            });
            if output.len() >= MAX_LIST_ENTRIES {
                break;
            }
        }
        output.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(output)
    }

    pub fn manifest(&self, virtual_path: &str) -> Result<FileManifest> {
        let (root_index, components) = parse_virtual_path(virtual_path)?;
        let root = Self::root(&self.read_roots, root_index)?;
        let (parent, leaf) = open_parent(root, &components, false)?;
        let metadata = parent
            .symlink_metadata(&leaf)
            .map_err(|error| io_error("source", error))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_TRANSFER_BYTES
        {
            return Err(filesystem_error("source_not_regular_file"));
        }
        let mut file = parent
            .open_with(&leaf, &nofollow_options(true, false, false))
            .map_err(|error| io_error("source", error))?;
        let (size, sha256) = sha256_file(&mut file)?;
        Ok(FileManifest {
            path: virtual_path.into(),
            size,
            sha256,
        })
    }

    pub fn selection(&self, virtual_path: &str) -> Result<FileSelection> {
        let (root_index, components) = parse_virtual_path(virtual_path)?;
        let root = Self::root(&self.read_roots, root_index)?;
        if components.is_empty() {
            let directory = root.try_clone().map_err(|error| io_error("root", error))?;
            let mut selection = FileSelection {
                is_directory: true,
                directories: vec![virtual_path.into()],
                manifests: Vec::new(),
            };
            self.collect_selection(&directory, virtual_path, &mut selection, &mut 0, &mut 0)?;
            return Ok(selection);
        }
        let (parent, leaf) = open_parent(root, &components, false)?;
        let metadata = parent
            .symlink_metadata(&leaf)
            .map_err(|error| io_error("source", error))?;
        if metadata.file_type().is_symlink() {
            return Err(filesystem_error("source_symlink_rejected"));
        }
        if metadata.is_file() {
            return Ok(FileSelection {
                is_directory: false,
                directories: Vec::new(),
                manifests: vec![self.manifest(virtual_path)?],
            });
        }
        if !metadata.is_dir() {
            return Err(filesystem_error("source_not_regular_file_or_directory"));
        }
        let directory = open_child_dir(&parent, &leaf)?;
        let mut selection = FileSelection {
            is_directory: true,
            directories: vec![virtual_path.into()],
            manifests: Vec::new(),
        };
        self.collect_selection(&directory, virtual_path, &mut selection, &mut 0, &mut 0)?;
        Ok(selection)
    }

    fn collect_selection(
        &self,
        directory: &Dir,
        base: &str,
        selection: &mut FileSelection,
        entries: &mut usize,
        total: &mut u64,
    ) -> Result<()> {
        for entry in directory
            .read_dir(".")
            .map_err(|error| io_error("list", error))?
        {
            let entry = entry.map_err(|error| io_error("list", error))?;
            let name = match entry.file_name().into_string() {
                Ok(name) if portable_component(&name) => name,
                _ => continue,
            };
            let type_ = entry.file_type().map_err(|error| io_error("list", error))?;
            if type_.is_symlink() || !(type_.is_dir() || type_.is_file()) {
                continue;
            }
            *entries = entries
                .checked_add(1)
                .ok_or_else(|| filesystem_error("tree_too_large"))?;
            if *entries > MAX_TREE_ENTRIES {
                return Err(filesystem_error("tree_too_large"));
            }
            let path = if base.ends_with('/') {
                format!("{base}{name}")
            } else {
                format!("{base}/{name}")
            };
            if type_.is_dir() {
                selection.directories.push(path.clone());
                let child = open_child_dir(directory, OsStr::new(&name))?;
                self.collect_selection(&child, &path, selection, entries, total)?;
            } else {
                let manifest = self.manifest(&path)?;
                *total = total
                    .checked_add(manifest.size)
                    .ok_or_else(|| filesystem_error("tree_too_large"))?;
                if *total > MAX_TRANSFER_BYTES {
                    return Err(filesystem_error("tree_too_large"));
                }
                selection.manifests.push(manifest);
            }
        }
        Ok(())
    }

    pub fn ensure_directory(&self, virtual_path: &str) -> Result<()> {
        let (root_index, components) = parse_virtual_path(virtual_path)?;
        let root = Self::root(&self.write_roots, root_index)?;
        let mut current = root.try_clone().map_err(|error| io_error("root", error))?;
        for component in components {
            match current.symlink_metadata(&component) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(filesystem_error(
                        "destination_symlink_or_non_directory_rejected",
                    ))
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => current
                    .create_dir(&component)
                    .map_err(|error| io_error("create_directory", error))?,
                Err(error) => return Err(io_error("directory", error)),
            }
            current = open_child_dir(&current, &component)?;
        }
        Ok(())
    }

    pub fn read_chunk(
        &self,
        manifest: &FileManifest,
        offset: u64,
        maximum: usize,
    ) -> Result<Vec<u8>> {
        if maximum == 0 || maximum > MAX_CHUNK_BYTES || offset > manifest.size {
            return Err(filesystem_error("invalid_chunk_request"));
        }
        let (root_index, components) = parse_virtual_path(&manifest.path)?;
        let root = Self::root(&self.read_roots, root_index)?;
        let (parent, leaf) = open_parent(root, &components, false)?;
        let mut file = parent
            .open_with(&leaf, &nofollow_options(true, false, false))
            .map_err(|error| io_error("source", error))?;
        let metadata = file.metadata().map_err(|error| io_error("source", error))?;
        if !metadata.is_file() || metadata.len() != manifest.size {
            return Err(filesystem_error("source_changed"));
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| io_error("seek", error))?;
        let mut bytes =
            vec![0_u8; maximum.min(usize::try_from(manifest.size - offset).unwrap_or(maximum))];
        let read = file
            .read(&mut bytes)
            .map_err(|error| io_error("read", error))?;
        bytes.truncate(read);
        Ok(bytes)
    }

    pub fn begin_write(&self, transfer_id: &str, manifest: FileManifest) -> Result<WriteTransfer> {
        if transfer_id.len() != 22
            || !transfer_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            || manifest.size > MAX_TRANSFER_BYTES
            || manifest.sha256.len() != 64
            || !manifest.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(filesystem_error("invalid_transfer_manifest"));
        }
        let (root_index, components) = parse_virtual_path(&manifest.path)?;
        let root = Self::root(&self.write_roots, root_index)?;
        let (parent, leaf) = open_parent(root, &components, true)?;
        if parent
            .symlink_metadata(&leaf)
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(filesystem_error("destination_symlink_rejected"));
        }
        let part_name = OsString::from(format!(".wii-transfer-{transfer_id}.part"));
        let metadata_name = OsString::from(format!(".wii-transfer-{transfer_id}.json"));
        let expected_metadata = PartMetadata {
            destination: manifest.path.clone(),
            size: manifest.size,
            sha256: manifest.sha256.clone(),
        };
        // A partial transfer remains available for a bounded 24-hour resume
        // window. A subsequent attempt to the same destination is the only
        // time it is cleaned up; there is deliberately no ambient directory
        // sweep that could touch user files.
        let stale = parent
            .symlink_metadata(&metadata_name)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| SystemTime::now().duration_since(modified.into_std()).ok())
            .is_some_and(|age| age > Duration::from_millis(PART_RETENTION_MS));
        if stale {
            let _ = parent.remove_file(&part_name);
            let _ = parent.remove_file(&metadata_name);
        }
        let written = match parent.open_with(&metadata_name, &nofollow_options(true, false, false))
        {
            Ok(mut file) => {
                let mut encoded = String::new();
                file.read_to_string(&mut encoded)
                    .map_err(|error| io_error("resume_metadata", error))?;
                let existing: PartMetadata = serde_json::from_str(&encoded)
                    .map_err(|_| filesystem_error("resume_metadata_invalid"))?;
                if existing != expected_metadata {
                    return Err(filesystem_error("resume_manifest_mismatch"));
                }
                let part = parent
                    .open_with(&part_name, &nofollow_options(true, false, false))
                    .map_err(|error| io_error("resume_part", error))?;
                let metadata = part
                    .metadata()
                    .map_err(|error| io_error("resume_part", error))?;
                if !metadata.is_file() || metadata.len() > manifest.size {
                    return Err(filesystem_error("resume_part_invalid"));
                }
                metadata.len()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut metadata = parent
                    .open_with(&metadata_name, &nofollow_options(false, true, true))
                    .map_err(|error| io_error("resume_metadata", error))?;
                metadata
                    .write_all(
                        serde_json::to_string(&expected_metadata)
                            .map_err(|_| filesystem_error("resume_metadata_invalid"))?
                            .as_bytes(),
                    )
                    .map_err(|error| io_error("resume_metadata", error))?;
                metadata
                    .sync_all()
                    .map_err(|error| io_error("resume_metadata", error))?;
                parent
                    .open_with(&part_name, &nofollow_options(false, true, true))
                    .map_err(|error| io_error("part_create", error))?;
                0
            }
            Err(error) => return Err(io_error("resume_metadata", error)),
        };
        Ok(WriteTransfer {
            destination: leaf.to_string_lossy().into_owned(),
            part_name,
            metadata_name,
            parent,
            expected: manifest,
            written,
        })
    }
}

impl WriteTransfer {
    pub fn offset(&self) -> u64 {
        self.written
    }

    pub fn expected_size(&self) -> u64 {
        self.expected.size
    }

    pub fn path(&self) -> &str {
        &self.expected.path
    }

    pub fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        if offset != self.written
            || bytes.is_empty()
            || bytes.len() > MAX_CHUNK_BYTES
            || self.written.saturating_add(bytes.len() as u64) > self.expected.size
        {
            return Err(filesystem_error("invalid_chunk_order"));
        }
        let mut file = self
            .parent
            .open_with(&self.part_name, &nofollow_options(false, true, false))
            .map_err(|error| io_error("part_write", error))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| io_error("part_write", error))?;
        file.write_all(bytes)
            .map_err(|error| io_error("part_write", error))?;
        file.sync_data()
            .map_err(|error| io_error("part_write", error))?;
        self.written += bytes.len() as u64;
        Ok(())
    }

    pub fn complete(self, collision: &str) -> Result<String> {
        if self.written != self.expected.size {
            return Err(filesystem_error("transfer_incomplete"));
        }
        let mut file = self
            .parent
            .open_with(&self.part_name, &nofollow_options(true, false, false))
            .map_err(|error| io_error("part_verify", error))?;
        let (size, sha256) = sha256_file(&mut file)?;
        if size != self.expected.size || sha256 != self.expected.sha256 {
            return Err(filesystem_error("integrity_mismatch"));
        }
        let destination = OsString::from(&self.destination);
        match self.parent.symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(filesystem_error("destination_symlink_rejected"))
            }
            Ok(_) if collision == "fail" => return Err(filesystem_error("destination_exists")),
            Ok(_) if collision == "replace" => self
                .parent
                .remove_file(&destination)
                .map_err(|error| io_error("replace_destination", error))?,
            Ok(_) => return Err(filesystem_error("invalid_collision_policy")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error("destination", error)),
        }
        self.parent
            .rename(&self.part_name, &self.parent, &destination)
            .map_err(|error| io_error("atomic_complete", error))?;
        let _ = self.parent.remove_file(&self.metadata_name);
        Ok(self.expected.path)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    static TEMPORARY_ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = TEMPORARY_ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("wii-ultra-desk-files-{nonce}-{sequence}"));
        fs::create_dir_all(&root).expect("temporary root");
        root
    }

    fn filesystem(root: &Path) -> RootedFileSystem {
        let root = root.to_string_lossy().into_owned();
        let config = FileRootsConfig::canonicalize(&[root.clone()], &[root]).expect("root config");
        RootedFileSystem::open(&config).expect("root open")
    }

    #[test]
    fn rejects_traversal_and_symlink_escape() {
        let root = temporary_root();
        fs::write(root.join("inside.txt"), b"inside").expect("inside");
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc", root.join("escape")).expect("symlink");
        let filesystem = filesystem(&root);
        assert!(filesystem.manifest("0/../inside.txt").is_err());
        assert!(filesystem.manifest("0//inside.txt").is_err());
        #[cfg(unix)]
        assert!(filesystem.list("0/escape").is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn resumes_and_completes_only_after_integrity_check() {
        let root = temporary_root();
        let filesystem = filesystem(&root);
        let content = b"bounded transfer payload";
        let manifest = FileManifest {
            path: "0/nested/result.bin".into(),
            size: content.len() as u64,
            sha256: format!("{:x}", Sha256::digest(content)),
        };
        let mut transfer = filesystem
            .begin_write("aaaaaaaaaaaaaaaaaaaaaa", manifest.clone())
            .expect("start transfer");
        transfer.write_chunk(0, &content[..8]).expect("first chunk");
        assert_eq!(transfer.offset(), 8);
        drop(transfer);
        let mut resumed = filesystem
            .begin_write("aaaaaaaaaaaaaaaaaaaaaa", manifest.clone())
            .expect("resume transfer");
        assert_eq!(resumed.offset(), 8);
        resumed.write_chunk(8, &content[8..]).expect("second chunk");
        assert_eq!(resumed.complete("fail").expect("complete"), manifest.path);
        assert_eq!(
            fs::read(root.join("nested/result.bin")).expect("result"),
            content
        );

        let bad = FileManifest {
            path: "0/bad.bin".into(),
            size: 3,
            sha256: "0".repeat(64),
        };
        let mut bad_transfer = filesystem
            .begin_write("bbbbbbbbbbbbbbbbbbbbbb", bad)
            .expect("bad transfer starts");
        bad_transfer.write_chunk(0, b"bad").expect("bad chunk");
        assert!(bad_transfer.complete("fail").is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn selects_portable_directory_tree_and_creates_empty_directory() {
        let root = temporary_root();
        fs::create_dir_all(root.join("tree/empty")).expect("empty directory");
        fs::create_dir_all(root.join("tree/nested")).expect("nested directory");
        fs::write(root.join("tree/nested/leaf.txt"), b"leaf").expect("leaf");
        fs::write(root.join("bad:name.txt"), b"not portable").expect("bad name");
        let filesystem = filesystem(&root);
        let selection = filesystem.selection("0/tree").expect("tree selection");
        assert!(selection.is_directory);
        assert_eq!(selection.directories.len(), 3);
        assert_eq!(selection.manifests.len(), 1);
        assert_eq!(selection.manifests[0].path, "0/tree/nested/leaf.txt");
        assert!(filesystem.manifest("0/bad:name.txt").is_err());
        filesystem
            .ensure_directory("0/destination/empty")
            .expect("ensure directory");
        assert!(root.join("destination/empty").is_dir());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
