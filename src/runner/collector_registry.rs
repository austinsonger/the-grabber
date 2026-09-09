use crate::evidence::{CsvCollector, EvidenceCollector, JsonCollector};
use crate::providers::aws::factory::AwsProviderFactory;
use crate::providers::aws::inspector_sbom::InspectorSbomConfig;
use crate::providers::ProviderFactory;

pub struct CollectorRegistry {
    factories: Vec<Box<dyn ProviderFactory>>,
}

impl CollectorRegistry {
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
        }
    }

    pub fn register(&mut self, factory: impl ProviderFactory + 'static) {
        self.factories.push(Box::new(factory));
    }

    pub fn csv_collectors(&self) -> Vec<Box<dyn CsvCollector>> {
        self.factories
            .iter()
            .flat_map(|f| f.csv_collectors())
            .collect()
    }

    pub fn json_collectors(&self) -> Vec<Box<dyn JsonCollector>> {
        self.factories
            .iter()
            .flat_map(|f| f.json_collectors())
            .collect()
    }

    pub fn evidence_collectors(&self) -> Vec<Box<dyn EvidenceCollector>> {
        self.factories
            .iter()
            .flat_map(|f| f.evidence_collectors())
            .collect()
    }
}

impl Default for CollectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Backward-compat wrappers — used by tui_session.rs and multi-account path
// ---------------------------------------------------------------------------

pub fn build_csv_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn CsvCollector>> {
    build_csv_collectors_with_sbom(names, config, None)
}

/// Same as [`build_csv_collectors`], but lets the caller supply the Inspector
/// SBOM export destination + repository scope. Used by the TUI path, where
/// those values come from the wizard rather than CLI flags.
pub fn build_csv_collectors_with_sbom(
    names: &[&str],
    config: &aws_config::SdkConfig,
    sbom: Option<(InspectorSbomConfig, std::path::PathBuf)>,
) -> Vec<Box<dyn CsvCollector>> {
    let mut factory = AwsProviderFactory::new(
        config.clone(),
        String::new(),
        String::new(),
        names.iter().map(|s| s.to_string()).collect(),
    );
    if let Some((cfg, out)) = sbom {
        factory = factory.with_sbom_config(cfg, Some(out));
    }
    factory.csv_collectors()
}

pub fn build_json_inv_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn JsonCollector>> {
    AwsProviderFactory::new(
        config.clone(),
        String::new(),
        String::new(),
        names.iter().map(|s| s.to_string()).collect(),
    )
    .json_collectors()
}

pub fn build_json_collectors(
    names: &[&str],
    config: &aws_config::SdkConfig,
) -> Vec<Box<dyn EvidenceCollector>> {
    AwsProviderFactory::new(
        config.clone(),
        String::new(),
        String::new(),
        names.iter().map(|s| s.to_string()).collect(),
    )
    .evidence_collectors()
}
