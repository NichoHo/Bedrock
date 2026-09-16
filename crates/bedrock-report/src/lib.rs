use bedrock_prune::RemovalEvidence;

#[derive(thiserror::Error, Debug)]
pub enum ReportError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, ReportError>;

pub struct MarkdownRenderer;

impl MarkdownRenderer {
    pub fn render(evidence: &[RemovalEvidence], original_size: u64, new_size: u64) -> String {
        let mut out = String::new();
        out.push_str("# Bedrock Prune Report\n\n");
        out.push_str(format!("**Original Size:** {} bytes\n", original_size).as_str());
        out.push_str(format!("**Pruned Size:** {} bytes\n", new_size).as_str());

        let diff = original_size.saturating_sub(new_size);
        out.push_str(format!("**Saved:** {} bytes\n\n", diff).as_str());

        out.push_str("## Removed Packages\n\n");
        out.push_str("| Package | Removed Files | Kept Files | Reason |\n");
        out.push_str("|---|---|---|---|\n");
        for e in evidence {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                e.package_name, e.removed_files, e.kept_files, e.reason
            ));
        }
        out
    }
}

pub struct HtmlRenderer;

impl HtmlRenderer {
    pub fn render(evidence: &[RemovalEvidence], original_size: u64, new_size: u64) -> String {
        let mut out = String::new();
        out.push_str("<html><head><title>Bedrock Prune Report</title><style>table, th, td { border: 1px solid black; border-collapse: collapse; padding: 5px; }</style></head><body>");
        out.push_str("<h1>Bedrock Prune Report</h1>");
        out.push_str(&format!("<p><strong>Original Size:</strong> {} bytes</p>", original_size));
        out.push_str(&format!("<p><strong>Pruned Size:</strong> {} bytes</p>", new_size));

        let diff = original_size.saturating_sub(new_size);
        out.push_str(&format!("<p><strong>Saved:</strong> {} bytes</p>", diff));

        out.push_str("<h2>Removed Packages</h2>");
        out.push_str("<table><tr><th>Package</th><th>Removed Files</th><th>Kept Files</th><th>Reason</th></tr>");

        for e in evidence {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                e.package_name, e.removed_files, e.kept_files, e.reason
            ));
        }

        out.push_str("</table></body></html>");
        out
    }
}
