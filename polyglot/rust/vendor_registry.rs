// polyglot/rust/vendor_registry.rs
//! Vendor registry for vendorvet: third-party risk questionnaires with SBOM cross-ref.
//!
//! This module provides a thread-safe registry for managing vendor records,
//! their associated SBOM entries, and risk scoring capabilities.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// A single vendor record in the registry.
#[derive(Debug, Clone)]
pub struct Vendor {
    pub id: Uuid,
    pub name: String,
    pub contact_email: Option<String>,
    pub website: Option<String>,
    /// Risk score from 0 (low) to 100 (high). Updated on questionnaire review.
    pub risk_score: u8,
    pub last_reviewed: DateTime<Utc>,
    pub sbom_entry_ids: HashSet<String>, // Canonical SBOM identifiers
}

/// A canonical identifier for an SBOM entry (name + version normalized).
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SbomEntryId {
    /// Normalized package name (e.g., "openssl@1.1.1" or "libxml2:2.9.14")
    pub canonical_name: String,
}

/// Registry holding all vendor records and their SBOM relationships.
#[derive(Debug)]
pub struct VendorRegistry {
    /// In-memory store of vendors.
    vendors: HashMap<Uuid, Vendor>,
    /// Index from SBOM entry ID to list of vendors using that entry.
    sbom_index: HashMap<String, Vec<Uuid>>,
}

impl Default for VendorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl VendorRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            vendors: HashMap::new(),
            sbom_index: HashMap::new(),
        }
    }

    /// Adds or updates a vendor record. Returns the existing ID if already present.
    pub fn add_or_update(&mut self, vendor: Vendor) -> Uuid {
        let id = vendor.id;
        
        // If this is an update (same name), preserve old SBOM links
        if let Some(existing) = self.vendors.get(&id) {
            if existing.name == vendor.name {
                let mut merged = vendor.clone();
                merged.sbom_entry_ids.extend(existing.sbom_entry_ids);
                return self.vendors.insert(id, merged).unwrap().id;
            }
        }

        self.vendors.insert(id, vendor);
        id
    }

    /// Retrieves a vendor by ID. Returns `None` if not found.
    pub fn get(&self, id: Uuid) -> Option<&Vendor> {
        self.vendors.get(&id)
    }

    /// Searches vendors whose name contains the query string (case-insensitive).
    pub fn search_by_name(&self, query: &str) -> Vec<&Vendor> {
        let lower = query.to_lowercase();
        self.vendors.values()
            .filter(|v| v.name.to_lowercase().contains(&lower))
            .collect()
    }

    /// Searches vendors whose risk score meets or exceeds the threshold.
    pub fn search_by_risk(&self, min_score: u8) -> Vec<&Vendor> {
        self.vendors.values()
            .filter(|v| v.risk_score >= min_score)
            .collect()
    }

    /// Links an SBOM entry to a vendor. Updates the reverse index for fast lookup.
    pub fn link_sbom_entry(&mut self, id: Uuid, sbom_id: &str) {
        let vendor = match self.vendors.get_mut(&id) {
            Some(v) => v,
            None => return, // Vendor not found; ignore silently
        };

        if !vendor.sbom_entry_ids.contains(sbom_id) {
            vendor.sbom_entry_ids.insert(sbom_id.to_string());
            
            // Update reverse index: which vendors use this SBOM entry?
            let entry_index = self.sbom_index.entry(sbom_id.to_string()).or_insert_with(Vec::new);
            if !entry_index.contains(&id) {
                entry_index.push(id);
            }
        }
    }

    /// Removes a vendor and all their SBOM links. Returns `true` if removed.
    pub fn remove(&mut self, id: Uuid) -> bool {
        let sbom_ids = match self.vendors.remove(&id) {
            Some(vendor) => vendor.sbom_entry_ids,
            None => return false,
        };

        // Clean up reverse index
        for sbom_id in &sbom_ids {
            if let Some(entries) = self.sbom_index.get_mut(sbom_id) {
                entries.retain(|&v| v != id);
            }
        }

        true
    }

    /// Returns all SBOM entry IDs associated with a vendor.
    pub fn sbom_entries_for_vendor(&self, id: Uuid) -> Vec<&String> {
        match self.vendors.get(&id) {
            Some(vendor) => vendor.sbom_entry_ids.iter().collect(),
            None => vec![],
        }
    }

    /// Returns all vendors that use a specific SBOM entry.
    pub fn vendors_using_sbom(&self, sbom_id: &str) -> Vec<&Vendor> {
        match self.sbom_index.get(sbom_id) {
            Some(ids) => ids.iter().filter_map(|&id| self.vendors.get(&id)).collect(),
            None => vec![],
        }
    }

    /// Updates a vendor's risk score and last review timestamp.
    pub fn update_risk_score(&mut self, id: Uuid, new_score: u8) -> Option<u8> {
        match self.vendors.get_mut(&id) {
            Some(vendor) => {
                let old = vendor.risk_score;
                vendor.risk_score = new_score.min(100); // Cap at 100
                vendor.last_reviewed = Utc::now();
                Some(old)
            }
            None => None,
        }
    }

    /// Returns a summary of high-risk vendors (score >= 75).
    pub fn high_risk_summary(&self) -> Vec<&Vendor> {
        self.search_by_risk(75)
    }
}

/// Configuration for risk scoring.
#[derive(Debug, Clone)]
pub struct RiskConfig {
    /// Maximum score before vendor is flagged as critical.
    pub critical_threshold: u8,
    /// Warning threshold (below critical).
    pub warning_threshold: u8,
    /// Default score for newly added vendors.
    pub default_score: u8,
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            critical_threshold: 75,
            warning_threshold: 50,
            default_score: 25,
        }
    }
}

/// Builder pattern to construct a vendor with sensible defaults.
pub struct VendorBuilder {
    name: String,
    contact_email: Option<String>,
    website: Option<String>,
    risk_score: u8,
    last_reviewed: DateTime<Utc>,
    sbom_entry_ids: HashSet<String>,
}

impl Default for VendorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl VendorBuilder {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            contact_email: None,
            website: None,
            risk_score: RiskConfig::default().default_score,
            last_reviewed: Utc::now(),
            sbom_entry_ids: HashSet::new(),
        }
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.contact_email = Some(email.into());
        self
    }

    pub fn website(mut self, url: impl Into<String>) -> Self {
        self.website = Some(url.into());
        self
    }

    pub fn risk_score(mut self, score: u8) -> Self {
        self.risk_score = score.min(100);
        self
    }

    pub fn last_reviewed<T>(mut self, dt: T) -> Self
    where
        T: Into<DateTime<Utc>>,
    {
        self.last_reviewed = dt.into();
        self
    }

    pub fn sbom_entry(mut self, id: impl Into<String>) -> Self {
        let id_str = id.into();
        if !self.sbom_entry_ids.contains(&id_str) {
            self.sbom_entry_ids.insert(id_str);
        }
        self
    }

    pub fn build(self) -> Vendor {
        // Generate a UUID for the vendor
        let id = Uuid::new_v4();
        
        Vendor {
            id,
            name: self.name,
            contact_email: self.contact_email,
            website: self.website,
            risk_score: self.risk_score,
            last_reviewed: self.last_reviewed,
            sbom_entry_ids: self.sbom_entry_ids,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_vendor() {
        let mut registry = VendorRegistry::new();
        
        let vendor = VendorBuilder::new("Test Corp")
            .email("security@testcorp.com")
            .risk_score(30)
            .build();

        let id = registry.add_or_update(vendor);
        assert!(registry.get(id).is_some());
    }

    #[test]
    fn test_search_by_name() {
        let mut registry = VendorRegistry::new();
        
        // Add a vendor with "acme" in the name
        let v1 = VendorBuilder::new("Acme Industries")
            .risk_score(40)
            .build();
        registry.add_or_update(v1);

        let results = registry.search_by_name("acme");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_link_sbom_entry() {
        let mut registry = VendorRegistry::new();
        
        let vendor_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let sbom_id = "openssl@1.1.1";

        registry.link_sbom_entry(vendor_id, sbom_id);

        // Verify forward lookup
        assert_eq!(registry.sbom_entries_for_vendor(vendor_id).len(), 1);
        
        // Verify reverse lookup
        let vendors_using = registry.vendors_using_sbom(sbom_id);
        assert_eq!(vendors_using.len(), 1);
    }

    #[test]
    fn test_risk_score_update() {
        let mut registry = VendorRegistry::new();
        
        let vendor = VendorBuilder::new("Risk Test")
            .risk_score(20)
            .build();
        registry.add_or_update(vendor);

        // Update score
        registry.update_risk_score(vendor.id, 65).unwrap();
        
        if let Some(vendor) = registry.get(vendor.id) {
            assert_eq!(vendor.risk_score, 65);
            assert!(!vendor.last_reviewed.is_zero());
        }

        // Update beyond cap
        registry.update_risk_score(vendor.id, 150).unwrap();
        
        if let Some(vendor) = registry.get(vendor.id) {
            assert_eq!(vendor.risk_score, 100);
        }
    }

    #[test]
    fn test_high_risk_summary() {
        let mut registry = VendorRegistry::new();
        
        // Add a high-risk vendor
        let v1 = VendorBuilder::new("High Risk Co")
            .risk_score(85)
            .build();
        registry.add_or_update(v1);

        // Add a medium-risk vendor
        let v2 = VendorBuilder::new("Medium Risk Co")
            .risk_score(60)
            .build();
        registry.add_or_update(v2);

        let high_risk = registry.high_risk_summary();
        assert_eq!(high_risk.len(), 1);
    }
}

/// Demo application demonstrating the vendor registry capabilities.
fn main() {
    println!("=== VendorVet Registry Demo ===\n");

    // Create a new registry
    let mut registry = VendorRegistry::new();

    // Add some sample vendors using the builder pattern
    println!("Adding vendors...");
    
    let acme = VendorBuilder::new("Acme Corporation")
        .email("security@acme.com")
        .website("https://www.acme.com")
        .risk_score(25)
        .build();

    let beta = VendorBuilder::new("Beta Systems Inc.")
        .email("info@betasystems.io")
        .risk_score(70)
        .sbom_entry("openssl@1.1.1")
        .build();

    let gamma = VendorBuilder::new("Gamma Tech LLC")
        .email("security@gammatech.net")
        .risk_score(92)
        .sbom_entry("libxml2:2.9.14")
        .build();

    registry.add_or_update(acme);
    registry.add_or_update(beta);
    registry.add_or_update(gamma);

    println!("  - Added 3 vendors\n");

    // Search by name (case-insensitive)
    println!("Searching for 'acme'...");
    let results = registry.search_by_name("ACME");
    println!("  Found {} vendor(s):\n", results.len());
    for v in &results {
        println!("    - {} (risk: {}/100)", 
            v.name, v.risk_score);
    }

    // Search by risk threshold
    println!("\nSearching for high-risk vendors (>= 75)...");
    let high_risk = registry.high_risk_summary();
    if !high_risk.is_empty() {
        println!("  Found {} vendor(s):\n", high_risk.len());
        for v in &high_risk {
            println!("    - {} (risk: {}/100, last reviewed: {:?})", 
                v.name, v.risk_score, v.last_reviewed);