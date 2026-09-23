use super::{req_str, Tool};
use crate::error::{Error, Result};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;

fn write_file(path: &Path, content: &str) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Do not follow a final symlink between Sandbox::check_write and
        // open(2). The scoped check rejects links up front; this is the
        // atomic filesystem backstop for a link swap in that small window.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    file.write_all(content.as_bytes())
}

pub struct WriteTool;

#[async_trait]
impl Tool for WriteTool {
    fn name(&self) -> &'static str {
        "Write"
    }

    fn audit_summary(&self, input: &Value) -> Option<super::AuditSummary> {
        input
            .get("path")
            .and_then(Value::as_str)
            .map(|p| super::AuditSummary::targets([p.to_string()]))
    }

    fn description(&self) -> &'static str {
        "Write the given content to a file. Creates parent directories as needed. \
         Overwrites any existing file at the path."
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path":    {"type": "string"},
                "content": {"type": "string"}
            },
            "required": ["path", "content"]
        })
    }

    fn requires_approval(&self, _input: &Value) -> bool {
        true
    }

    async fn call(&self, input: Value) -> Result<String> {
        let raw_path = req_str(&input, "path")?;
        let validated = crate::sandbox::Sandbox::check_write(raw_path)?;
        // Lead is a coordinator — never the author. The destructive-command
        // guard in BashTool catches `rm -rf` etc., but a lead could still
        // overwrite source files via Write. Cut that off here so every
        // code change has to go through a teammate via SendMessage.
        // Narrow exception: when a git merge is in progress AND the file
        // currently contains conflict markers, the lead is mid-merge-
        // resolution and that's the one legitimate lead-author activity.
        if crate::team::is_team_lead() && !crate::team::lead_resolving_merge_conflict(&validated) {
            return Err(Error::Tool(format!(
                "team lead may not write source files (path: {raw_path}). Lead is a COORDINATOR — delegate every code change to the responsible teammate via SendMessage. (Exception: when a git merge is in progress and this file has `<<<<<<<` markers, you may write the resolved version. That doesn't apply here — there's no active merge or this file isn't conflicted.)"
            )));
        }
        let path = validated.to_string_lossy();
        let content = req_str(&input, "content")?;

        let p = Path::new(path.as_ref());
        if let Some(parent) = p.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Tool(format!("mkdir {}: {}", parent.display(), e)))?;
            }
        }
        write_file(p, content).map_err(|e| Error::Tool(format!("write {path}: {e}")))?;
        Ok(format!("Wrote {} bytes to {}", content.len(), path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn writes_new_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.txt");
        let msg = WriteTool
            .call(json!({
                "path": path.to_string_lossy(),
                "content": "hello"
            }))
            .await
            .unwrap();
        assert!(msg.contains("Wrote 5 bytes"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
    }

    #[tokio::test]
    async fn overwrites_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ow.txt");
        std::fs::write(&path, "old").unwrap();

        WriteTool
            .call(json!({
                "path": path.to_string_lossy(),
                "content": "new"
            }))
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[tokio::test]
    async fn creates_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a/b/c/nested.txt");
        WriteTool
            .call(json!({
                "path": path.to_string_lossy(),
                "content": "x"
            }))
            .await
            .unwrap();
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn refuses_a_dangling_final_symlink_before_and_during_open() {
        let dir = tempdir().unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let path = dir.path().join("output");
        std::fs::create_dir(&path).unwrap();
        let link = path.join("artifact.txt");
        std::os::unix::fs::symlink(outside.join("artifact.txt"), &link).unwrap();

        // The normal tool path rejects the link before opening it.
        let err = WriteTool
            .call(json!({
                "path": link.to_string_lossy(),
                "content": "must not follow"
            }))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("symbolic link"));

        // The filesystem backstop also rejects a final-link swap in the
        // check/open window, independently of the policy check.
        let err = write_file(&link, "must not follow").unwrap_err();
        let message = format!("{err}");
        assert!(
            message.contains("symbolic link") || message.contains("Too many levels"),
            "unexpected error: {message}"
        );
        assert!(!outside.join("artifact.txt").exists());
    }

    #[tokio::test]
    async fn missing_content_errors() {
        let err = WriteTool
            .call(json!({"path": "/tmp/noop"}))
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("content"));
    }
}
