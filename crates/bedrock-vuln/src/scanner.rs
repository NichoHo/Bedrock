use crate::db::VulnerabilityDb;
use bedrock_sbom::Package;
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
            // Simplified PURL matching for Phase 2 stub
            // A real implementation would parse the PURL and compare version ranges
            let pkg_purl_base = pkg.purl.split('@').next().unwrap_or(&pkg.purl);
            
            for adv in advisories {
                for affected in &adv.affected_purls {
                    let affected_base = affected.split('@').next().unwrap_or(affected);
                    if pkg_purl_base == affected_base {
                        // Dummy version match - assumes vulnerable if base PURL matches
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
        
        findings
    }
}
