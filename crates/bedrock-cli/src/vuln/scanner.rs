use crate::vuln::db::VulnerabilityDb;
use crate::sbom::Package;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub package_name: String,
    pub package_version: String,
    pub advisory_id: String,
    pub severity: Severity,
    pub fixed_version: Option<String>,
}

pub struct Scanner<'a> {
    db: &'a VulnerabilityDb,
}

impl<'a> Scanner<'a> {
    pub fn new(db: &'a VulnerabilityDb) -> Self {
        Self { db }
    }

    pub fn scan(&self, packages: &[Package]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let advisories = self.db.get_advisories();

        for pkg in packages {
            let pkg_purl_base = pkg.purl.split('@').next().unwrap_or(&pkg.purl);

            for adv in advisories {
                for affected in &adv.affected_purls {
                    let affected_base = affected.split('@').next().unwrap_or(affected);
                    if pkg_purl_base == affected_base {
                        let mut is_vulnerable = true;

                        // Basic version check for the stub
                        if let Some(fixed) = &adv.fixed_version {
                            // If package version >= fixed version, it's not vulnerable.
                            // We do a simple string comparison, which is enough for the stub to not "ignore" versions.
                            if pkg.version.as_str() >= fixed.as_str() {
                                is_vulnerable = false;
                            }
                        } else if affected.contains('@') {
                            // If affected PURL has a specific version, check exact match
                            let affected_version = affected.split('@').nth(1).unwrap_or("").split('?').next().unwrap_or("");
                            if pkg.version != affected_version {
                                is_vulnerable = false;
                            }
                        }

                        if is_vulnerable {
                            findings.push(Finding {
                                package_name: pkg.name.clone(),
                                package_version: pkg.version.clone(),
                                advisory_id: adv.id.clone(),
                                severity: adv.severity.clone(),
                                fixed_version: adv.fixed_version.clone(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }
}





