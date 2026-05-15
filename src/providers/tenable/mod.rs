pub mod assets;
pub mod compliance;
pub mod factory;
pub mod pci_asv;
pub mod vulnerabilities;
pub mod was;

// Authentication:
//   Tenable.io  — X-ApiKeys header: "accessKey=<key>; secretKey=<key>"
//   Tenable.sc  — X-SecurityCenter-Token or username/password session
//
// Base URLs:
//   Tenable.io  — https://cloud.tenable.com  (fixed)
//   Tenable.sc  — configurable (on-premises deployment)
