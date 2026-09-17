use crate::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct ElfClosure {
    paths: HashSet<PathBuf>,
}

impl Default for ElfClosure {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfClosure {
    pub fn new() -> Self {
        Self { paths: HashSet::new() }
    }

    #[cfg(target_os = "linux")]
    pub fn add_binary(&mut self, path: &Path, rootfs: &Path) -> Result<()> {
        use std::fs;
        let data = fs::read(rootfs.join(path))?;

        if let Ok(elf) = goblin::elf::Elf::parse(&data) {
            for dep in elf.libraries {
                // In reality, this needs to resolve via DT_RUNPATH/DT_RPATH and ld.so.cache
                self.paths.insert(PathBuf::from("lib").join(dep));
            }
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    pub fn add_binary(&mut self, _path: &Path, _rootfs: &Path) -> Result<()> {
        Ok(())
    }

    pub fn get_closure(&self) -> &HashSet<PathBuf> {
        &self.paths
    }
}
