//! What the image says to run: entrypoint, command, environment, working
//! directory and user, from the OCI image config.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunConfig {
    pub argv: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    /// Raw `User` field: `""`, `name`, `uid`, `uid:gid`, `name:group`.
    pub user: String,
}

#[derive(Deserialize)]
struct Doc {
    config: Option<Inner>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct Inner {
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<Vec<String>>,
    working_dir: Option<String>,
    user: Option<String>,
}

impl RunConfig {
    /// `cmd_override` replaces the image's `Cmd` (as trailing `docker run` args do).
    pub fn parse(config_json: &[u8], cmd_override: Option<Vec<String>>) -> Result<Self> {
        let doc: Doc =
            serde_json::from_slice(config_json).context("image config is not valid JSON")?;
        let c = doc.config.unwrap_or_default();
        let mut argv = c.entrypoint.unwrap_or_default();
        argv.extend(cmd_override.or(c.cmd).unwrap_or_default());
        if argv.is_empty() {
            bail!("image has no Entrypoint or Cmd to run");
        }
        let mut env = c.env.unwrap_or_default();
        // What a container runtime would add if the image does not set them.
        if !env.iter().any(|e| e.starts_with("PATH=")) {
            env.push("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
        }
        if !env.iter().any(|e| e.starts_with("HOME=")) {
            env.push("HOME=/root".into());
        }
        let working_dir = match c.working_dir.as_deref() {
            None | Some("") => "/".to_string(),
            Some(w) => w.to_string(),
        };
        Ok(Self { argv, env, working_dir, user: c.user.unwrap_or_default() })
    }

    /// The program to exec: `argv[0]` as is when it contains a `/`, else the
    /// first match on the image's `PATH`, as a container runtime would do.
    pub fn program(&self, rootfs: &Path) -> Result<String> {
        let name = &self.argv[0];
        if name.contains('/') {
            return Ok(name.clone());
        }
        let path = self.env.iter().find_map(|e| e.strip_prefix("PATH=")).unwrap_or_default();
        for dir in path.split(':').filter(|d| !d.is_empty()) {
            let candidate = Path::new("/").join(dir).join(name);
            let found = super::resolve::resolve(rootfs, &candidate, true)
                .filter(|r| r.exists && rootfs.join(&r.real).is_file());
            if found.is_some() {
                return Ok(candidate.display().to_string());
            }
        }
        bail!("executable {name:?} not found in the image's PATH ({path})")
    }

    /// Resolves `User` to numeric (uid, gid), reading `/etc/passwd` and
    /// `/etc/group` from the extracted rootfs for names.
    pub fn ids(&self, rootfs: &Path) -> Result<(u32, u32)> {
        let (user, group) = match self.user.split_once(':') {
            Some((u, g)) => (u, Some(g)),
            None => (self.user.as_str(), None),
        };
        if user.is_empty() {
            return Ok((0, 0));
        }
        let read =
            |f: &str| std::fs::read_to_string(rootfs.join("etc").join(f)).unwrap_or_default();
        let field = |text: &str, name: &str, col: usize| -> Option<u32> {
            text.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.first() == Some(&name)).then(|| f.get(col)?.parse().ok()).flatten()
            })
        };
        let (uid, default_gid) = match user.parse::<u32>() {
            Ok(n) => {
                let gid = read("passwd")
                    .lines()
                    .find_map(|l| {
                        let f: Vec<&str> = l.split(':').collect();
                        (f.get(2) == Some(&user)).then(|| f.get(3)?.parse().ok()).flatten()
                    })
                    .unwrap_or(0);
                (n, gid)
            }
            Err(_) => {
                let passwd = read("passwd");
                let uid = field(&passwd, user, 2)
                    .with_context(|| format!("user {user:?} not in /etc/passwd"))?;
                (uid, field(&passwd, user, 3).unwrap_or(0))
            }
        };
        let gid = match group {
            None => default_gid,
            Some(g) => match g.parse::<u32>() {
                Ok(n) => n,
                Err(_) => field(&read("group"), g, 2)
                    .with_context(|| format!("group {g:?} not in /etc/group"))?,
            },
        };
        Ok((uid, gid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrypoint_plus_cmd_and_defaults() {
        let j = br#"{"config":{"Entrypoint":["/bin/app"],"Cmd":["--serve"],"Env":["A=1"],"WorkingDir":"/srv","User":"app:web"}}"#;
        let c = RunConfig::parse(j, None).unwrap();
        assert_eq!(c.argv, ["/bin/app", "--serve"]);
        assert_eq!(c.working_dir, "/srv");
        assert!(c.env.iter().any(|e| e.starts_with("PATH=")));
        let o = RunConfig::parse(j, Some(vec!["--other".into()])).unwrap();
        assert_eq!(o.argv, ["/bin/app", "--other"]);
        assert!(RunConfig::parse(b"{}", None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn program_is_looked_up_on_the_images_path() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("usr/local/bin")).unwrap();
        std::fs::write(t.path().join("usr/local/bin/python3"), b"x").unwrap();
        let c = |a: &str| RunConfig {
            argv: vec![a.into()],
            env: vec!["PATH=/usr/bin:/usr/local/bin".into()],
            ..Default::default()
        };
        assert_eq!(c("python3").program(t.path()).unwrap(), "/usr/local/bin/python3");
        assert_eq!(c("./run").program(t.path()).unwrap(), "./run");
        assert!(c("nope").program(t.path()).is_err());
    }

    #[test]
    fn user_resolution_uses_the_images_passwd() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("etc")).unwrap();
        std::fs::write(
            t.path().join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\napp:x:1000:1001::/home/app:/bin/sh\n",
        )
        .unwrap();
        std::fs::write(t.path().join("etc/group"), "web:x:2000:\n").unwrap();
        let ids = |u: &str| RunConfig { user: u.into(), ..Default::default() }.ids(t.path());
        assert_eq!(ids("").unwrap(), (0, 0));
        assert_eq!(ids("app").unwrap(), (1000, 1001));
        assert_eq!(ids("1000").unwrap(), (1000, 1001));
        assert_eq!(ids("app:web").unwrap(), (1000, 2000));
        assert_eq!(ids("5:6").unwrap(), (5, 6));
        assert!(ids("ghost").is_err());
    }
}
