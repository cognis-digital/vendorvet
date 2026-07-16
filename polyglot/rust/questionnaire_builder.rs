use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Question types for vendor risk questionnaires.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QuestionType {
    /// Single-line text response.
    Text,
    /// Multiple choice with predefined options.
    MultipleChoice(Vec<String>),
    /// Checkboxes (multi-select).
    Checkbox(Vec<String>),
    /// File upload for SBOM or certificate artifacts.
    FileUpload,
}

/// A single questionnaire question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Question {
    pub id: String,
    pub section_id: String,
    pub title: String,
    pub description: Option<String>,
    pub question_type: QuestionType,
    pub required: bool,
    pub risk_weight: u8, // 1-10 scale for scoring
}

/// A questionnaire section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    pub id: String,
    pub title: String,
    pub description: Option<String>,
    pub questions: Vec<Question>,
}

/// Complete questionnaire structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Questionnaire {
    pub version: String,
    pub name: String,
    pub description: Option<String>,
    pub sections: Vec<Section>,
    pub scoring_config: ScoringConfig,
}

/// Configuration for risk score calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    pub max_score_per_question: u8,
    pub pass_threshold: f32, // 0.0 to 1.0
    pub weight_by_sbom_match: bool,
}

/// A vendor's response to a questionnaire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorResponse {
    pub vendor_name: String,
    pub responses: HashMap<String, ResponseValue>,
    pub sbom_file: Option<PathBuf>,
    pub metadata: HashMap<String, String>,
}

/// A parsed response value (text or file hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResponseValue {
    Text(String),
    FileHash(String),
    Multiple(Vec<String>),
}

impl VendorResponse {
    pub fn new(vendor_name: &str) -> Self {
        VendorResponse {
            vendor_name: String::from(vendor_name),
            responses: HashMap::new(),
            sbom_file: None,
            metadata: HashMap::new(),
        }
    }

    pub fn add_text_response(&mut self, question_id: &str, text: &str) {
        self.responses.insert(
            String::from(question_id),
            ResponseValue::Text(String::from(text)),
        );
    }

    pub fn add_multiple_choice_response(
        &mut self,
        question_id: &str,
        selected_options: &[String],
    ) {
        self.responses.insert(
            String::from(question_id),
            ResponseValue::Multiple(
                selected_options.iter().map(|s| s.clone()).collect(),
            ),
        );
    }

    pub fn add_file_response(&mut self, question_id: &str, file_hash: &str) {
        self.responses.insert(
            String::from(question_id),
            ResponseValue::FileHash(String::from(file_hash)),
        );
    }

    pub fn set_sbom_path(&mut self, path: PathBuf) {
        self.sbom_file = Some(path);
    }
}

/// SBOM component representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SboComponent {
    pub name: String,
    pub version: String,
    pub supplier: Option<String>,
    pub licenses: Vec<String>,
    pub cpe: Option<String>,
}

/// SBOM parser and matcher.
#[derive(Debug, Default)]
pub struct SbomMatcher {
    known_vendors: HashMap<String, HashSet<String>>, // vendor -> set of component names
}

impl SbomMatcher {
    /// Initialize with known vendor components from a registry.
    pub fn new(known_components: &[(String, String)]) -> Self {
        let mut matcher = SbomMatcher::default();
        for (vendor, components) in known_components.iter() {
            let set = HashSet::from_iter(components.clone());
            matcher.known_vendors.insert(vendor.clone(), set);
        }
        matcher
    }

    /// Check if a component matches any known vendor.
    pub fn find_vendor_match(&self, name: &str, version: &str) -> Option<&String> {
        for (vendor, components) in self.known_vendors.iter() {
            if components.contains(name) || components.contains(&format!("{}@{}", name, version)) {
                return Some(vendor);
            }
        }
        None
    }

    /// Calculate vendor coverage score from SBOM.
    pub fn calculate_coverage_score(
        &self,
        sbom_components: &[SboComponent],
    ) -> f32 {
        let mut matched = 0;
        let total = sbom_components.len();
        
        for component in sbom_components.iter() {
            if self.find_vendor_match(&component.name, &component.version).is_some() {
                matched += 1;
            }
        }
        
        (matched as f32 / total as f32) * 100.0
    }
}

/// Builder for constructing questionnaires programmatically.
#[derive(Debug)]
pub struct QuestionnaireBuilder {
    questionnaire: Questionnaire,
    sections: Vec<Section>,
    scoring_config: ScoringConfig,
}

impl Default for QuestionnaireBuilder {
    fn default() -> Self {
        let mut builder = QuestionnaireBuilder::new();
        builder.scoring_config = ScoringConfig {
            max_score_per_question: 10,
            pass_threshold: 75.0,
            weight_by_sbom_match: true,
        };
        builder
    }
}

impl QuestionnaireBuilder {
    /// Create a new questionnaire builder with initial config.
    pub fn new() -> Self {
        QuestionnaireBuilder::default()
    }

    /// Set the questionnaire name and version.
    pub fn set_metadata(&mut self, name: &str, version: &str) {
        self.questionnaire.name = String::from(name);
        self.questionnaire.version = String::from(version);
    }

    /// Add a section with questions.
    pub fn add_section(
        &mut self,
        title: &str,
        description: Option<&str>,
        questions: Vec<Question>,
    ) {
        let id = format!("sec_{}", self.sections.len() + 1);
        
        let section = Section {
            id,
            title: String::from(title),
            description: description.map(String::from),
            questions,
        };

        self.sections.push(section.clone());
        self.questionnaire.sections.push(section);
    }

    /// Helper to add a required text question.
    pub fn add_text_question(
        &mut self,
        section_id: &str,
        title: &str,
        description: Option<&str>,
        risk_weight: u8,
    ) {
        let id = format!("q_{}_{}", section_id.len(), self.questionnaire.sections.last().map(|s| s.questions.len()).unwrap_or(0) + 1);

        let question = Question {
            id,
            section_id: String::from(section_id),
            title: String::from(title),
            description: description.map(String::from),
            question_type: QuestionType::Text,
            required: true,
            risk_weight,
        };

        if let Some(last_section) = self.sections.last_mut() {
            last_section.questions.push(question);
        } else {
            // Fallback for edge case
            let section = Section {
                id: String::from(section_id),
                title: String::new(),
                description: None,
                questions: vec![question],
            };
            self.sections.push(section);
            self.questionnaire.sections.last_mut().unwrap().questions.push(question.clone());
        }
    }

    /// Helper to add a multiple choice question.
    pub fn add_multiple_choice_question(
        &mut self,
        section_id: &str,
        title: &str,
        options: Vec<String>,
        description: Option<&str>,
        risk_weight: u8,
    ) {
        let id = format!("q_{}_{}", section_id.len(), self.questionnaire.sections.last().map(|s| s.questions.len()).unwrap_or(0) + 1);

        let question = Question {
            id,
            section_id: String::from(section_id),
            title: String::from(title),
            description: description.map(String::from),
            question_type: QuestionType::MultipleChoice(options.clone()),
            required: true,
            risk_weight,
        };

        if let Some(last_section) = self.sections.last_mut() {
            last_section.questions.push(question);
        } else {
            let section = Section {
                id: String::from(section_id),
                title: String::new(),
                description: None,
                questions: vec![question],
            };
            self.sections.push(section);
            self.questionnaire.sections.last_mut().unwrap().questions.push(question.clone());
        }
    }

    /// Build and return the final questionnaire.
    pub fn build(self) -> Questionnaire {
        self.questionnaire
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.build())
    }
}

/// Validate a vendor response against the questionnaire.
pub struct ResponseValidator<'a> {
    questionnaire: &'a Questionnaire,
    scoring_config: &'a ScoringConfig,
}

impl<'a> ResponseValidator<'a> {
    pub fn new(questionnaire: &'a Questionnaire) -> Self {
        ResponseValidator {
            questionnaire,
            scoring_config: &questionnaire.scoring_config,
        }
    }

    /// Validate all responses and calculate risk score.
    pub fn validate_and_score(
        response: &VendorResponse,
    ) -> (ValidationResult, f32) {
        let mut total_weight = 0u8;
        let mut raw_score = 0u8;
        let mut errors: Vec<ValidationError> = Vec::new();

        for section in &questionnaire.sections {
            for question in &section.questions {
                if !question.required {
                    continue;
                }

                total_weight += question.risk_weight as u8;

                // Check if response exists
                let resp_value = match response.responses.get(&question.id) {
                    Some(v) => v,
                    None => {
                        errors.push(ValidationError::Missing(question.id.clone()));
                        continue;
                    }
                };

                // Extract text content for scoring
                let answer_text = match resp_value {
                    ResponseValue::Text(t) | ResponseValue::Multiple(vec![t]) => t,
                    _ => String::new(),
                };

                // Simple heuristic: check if answer is empty or just whitespace
                if answer_text.trim().is_empty() {
                    errors.push(ValidationError::Empty(question.id.clone()));
                    continue;
                }

                // Add to raw score (simplified - real logic would parse content)
                raw_score += question.risk_weight as u8;
            }
        }

        let risk_score = if total_weight > 0 {
            ((raw_score as f32 / total_weight as f32) * 100.0).min(100.0)
        } else {
            0.0
        };

        (ValidationResult {
            errors,
            warnings: Vec::new(), // Could add more sophisticated checks here
        }, risk_score)
    }
}

/// Result of questionnaire validation.
#[derive(Debug)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }
}

#[derive(Debug, Clone)]
pub enum ValidationError {
    Missing(String),
    Empty(String),
    Format(String),
    Content(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::Missing(id) => write!(f, "Missing response for question: {}", id),
            ValidationError::Empty(id) => write!(f, "Empty response for question: {}", id),
            ValidationError::Format(id) => write!(f, "Format error in question: {}", id),
            ValidationError::Content(id) => write!(f, "Content validation failed for: {}", id),
        }
    }
}

/// Main demo and entry point.
fn main() {
    println!("=== VendorVet Questionnaire Builder Demo ===\n");

    // 1. Build a questionnaire with multiple sections
    let mut builder = QuestionnaireBuilder::new();
    
    builder.set_metadata("Vendor Risk Assessment", "2.0.0");

    // Section 1: General Information
    {
        let section_id = "sec_general";
        
        builder.add_section(
            "General Information",
            Some("Basic vendor identification and contact details"),
            vec![
                QuestionnaireBuilder::default()
                    .add_text_question(section_id, "Vendor Legal Name", None, 8),
                QuestionnaireBuilder::default()
                    .add_text_question(section_id, "Primary Contact Email", None, 7),
                QuestionnaireBuilder::default()
                    .add_multiple_choice_question(
                        section_id,
                        "Years in Business",
                        vec![
                            String::from("Less than 1 year"),
                            String::from("1-3 years"),
                            String::from("4-10 years"),
                            String::from("More than 10 years"),
                        ],
                        Some("Longer operating history may indicate stability"),
                        6,
                    ),
            ],
        );
    }

    // Section 2: Security Practices
    {
        let section_id = "sec_security";
        
        builder.add_section(
            "Security Practices",
            Some("Technical security controls and certifications"),
            vec![
                QuestionnaireBuilder::default()
                    .add_multiple_choice_question(
                        section_id,
                        "Industry Certifications Held",
                        vec![
                            String::from("ISO 27001"),
                            String::from("SOC 2 Type II"),
                            String::from("PCI DSS"),
                            String::from("None"),
                        ],
                        Some("Select all that apply"),
                        9,
                    ),
                QuestionnaireBuilder::default()
                    .add_text_question(
                        section_id,
                        "Primary Data Encryption Standard",
                        Some("e.g., AES-256, RSA-4096"),
                        8,
                    ),
            ],
        );
    }

    // Section 3: SBOM & Supply Chain
    {
        let section_id = "sec_sbom";
        
        builder.add_section(
            "SBOM and Supply Chain",
            Some("Software Bill of Materials and third-party dependencies"),
            vec![
                QuestionnaireBuilder::default()
                    .add_text_question(
                        section_id,
                        "SBOM Format Used",
                        Some("SPDX, CycloneDX, or other"),
                        10,
                    ),
                QuestionnaireBuilder::default()
                    .add_file_upload_question(section_id, "SBOM File Upload", None),
            ],
        );
    }

    // Section 4: Incident Response
    {
        let section_id = "sec_incident";
        
        builder.add_section(
            "Incident Response",
            Some("How the vendor handles security incidents"),
            vec![
                QuestionnaireBuilder::default()
                    .add_multiple_choice_question(
                        section_id,
                        "Typical Incident Response Time (24h)",
                        vec![
                            String::from("< 1 hour"),
                            String::from("1-4 hours"),
                            String::from("4