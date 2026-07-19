use std::{
    io::Write,
    process::{Command, Stdio},
};

use anyhow::{Context, Result, bail};

const DESCRIPTION: &str = "av:oidc-access-token";

pub fn store(token: &str) -> Result<()> {
    if token.is_empty() {
        bail!("refusing to store an empty token");
    }
    let _ = remove();
    let mut child = Command::new("keyctl")
        .args(["padd", "user", DESCRIPTION, "@u"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("start keyctl")?;
    child
        .stdin
        .take()
        .context("open keyctl stdin")?
        .write_all(token.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("keyctl rejected the OIDC session token");
    }
    Ok(())
}

pub fn load() -> Result<Option<String>> {
    let Some(id) = search()? else {
        return Ok(None);
    };
    let output = Command::new("keyctl")
        .args(["pipe", &id])
        .output()
        .context("read token from kernel keyring")?;
    if !output.status.success() {
        bail!("could not read OIDC session token from kernel keyring");
    }
    Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
}

pub fn remove() -> Result<()> {
    if let Some(id) = search()? {
        let status = Command::new("keyctl")
            .args(["unlink", &id, "@u"])
            .status()
            .context("remove token from kernel keyring")?;
        if !status.success() {
            bail!("could not remove OIDC session token from kernel keyring");
        }
    }
    Ok(())
}

fn search() -> Result<Option<String>> {
    let output = Command::new("keyctl")
        .args(["search", "@u", "user", DESCRIPTION])
        .output()
        .context("search kernel keyring; install keyutils or set AV_TOKEN")?;
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
}
