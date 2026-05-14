pub mod factory;
pub mod vulnerabilities;

// Tenable collector submodules go here, e.g.:
//   pub mod vulnerabilities;  // → Inspector2 / SecurityHub findings equivalent
//   pub mod assets;           // → EC2 inventory / resource tagging equivalent
//   pub mod scans;            // → Inspector scan history equivalent
//   pub mod audit_log;        // → CloudTrail equivalent
//   pub mod compliance;       // → AWS Config rules / Security Hub standards equivalent
//   pub mod plugins;          // → Inspector rule packages equivalent
//
// Authentication:
//   Tenable.io  — X-ApiKeys header: "accessKey=<key>; secretKey=<key>"
//   Tenable.sc  — X-SecurityCenter-Token or username/password session
//
// Base URLs:
//   Tenable.io  — https://cloud.tenable.com  (fixed)
//   Tenable.sc  — configurable (on-premises deployment)
