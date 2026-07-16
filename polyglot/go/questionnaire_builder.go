package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// =============================================================================
// Data Models
// =============================================================================

// Questionnaire represents the root document for vendor risk questionnaires.
type Questionnaire struct {
	Meta         Meta              `json:"meta,omitempty"`
	Version      string            `json:"version,omitempty"`
	Sections     []Section         `json:"sections,omitempty"`
	SBOMRefs     []SBOMReference   `json:"sbom_refs,omitempty"`
	CreatedAt    time.Time         `json:"created_at,omitempty"`
	UpdatedAt    *time.Time        `json:"updated_at,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
}

// Meta contains metadata about the questionnaire.
type Meta struct {
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Author      string   `json:"author,omitempty"`
	OrgID       string   `json:"org_id,omitempty"`
	ProjectID   string   `json:"project_id,omitempty"`
}

// Section groups related questions together.
type Section struct {
	ID          string        `json:"id,omitempty"`
	Title       string        `json:"title,omitempty"`
	Description string        `json:"description,omitempty"`
	Order       int            `json:"order,omitempty"`
	Visible     bool           `json:"visible,omitempty"`
	Questions   []Question    `json:"questions,omitempty"`
	SBOMScope   SBOMScope      `json:"sbom_scope,omitempty"`
}

// SBOMScope defines how to scope the SBOM reference.
type SBOMScope struct {
	ComponentID string `json:"component_id,omitempty"`
	Version     string `json:"version,omitempty"`
	LicenseRef  string `json:"license_ref,omitempty"`
}

// Question represents a single question in the questionnaire.
type Question struct {
	ID          string        `json:"id,omitempty"`
	Type        QType         `json:"type,omitempty"`
	Title       string        `json:"title,omitempty"`
	Description string        `json:"description,omitempty"`
	Order       int            `json:"order,omitempty"`
	Required    bool           `json:"required,omitempty"`
	Options     []AnswerOption `json:"options,omitempty"`
	Default     string         `json:"default,omitempty"`
	Validator   *QuestionValidator `json:"validator,omitempty"`
	SBOMRefs    []SBOMRef      `json:"sbom_refs,omitempty"`
}

// QType defines the type of question.
type QType string

const (
	QTypeText     QType = "text"
	QTypeCheckbox QType = "checkbox"
	QTypeDropdown QType = "dropdown"
	QTypeFile     QType = "file"
)

// AnswerOption represents a selectable option for multiple choice questions.
type AnswerOption struct {
	Value   string `json:"value,omitempty"`
	Label   string `json:"label,omitempty"`
	Subtext string `json:"subtext,omitempty"`
}

// QuestionValidator defines validation rules for answers.
type QuestionValidator struct {
	Pattern    *PatternRule  `json:"pattern,omitempty"`
	MinLength  int           `json:"min_length,omitempty"`
	MaxLength  int           `json:"max_length,omitempty"`
	Required   bool          `json:"required,omitempty"`
	Choices    []string      `json:"choices,omitempty"`
}

// PatternRule defines a regex pattern for validation.
type PatternRule struct {
	Pattern string `json:"pattern,omitempty"`
	Message string `json:"message,omitempty"`
}

// SBOMReference holds a reference to an external SBOM document.
type SBOMReference struct {
	ID         string    `json:"id,omitempty"`
	Source     string    `json:"source,omitempty"`
	Version    string    `json:"version,omitempty"`
	URL        string    `json:"url,omitempty"`
	Components []SBOMCompRef `json:"components,omitempty"`
}

// SBOMCompRef is a reference to a specific component in an SBOM.
type SBOMCompRef struct {
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Category  string `json:"category,omitempty"`
	LicenseID string `json:"license_id,omitempty"`
}

// =============================================================================
// Builder Pattern for Questionnaire Construction
// =============================================================================

type QuestionnaireBuilder struct {
	base    *Questionnaire
	current *Section
	version  string
	tags     []string
}

func NewQuestionnaireBuilder() *QuestionnaireBuilder {
	return &QuestionnaireBuilder{
		base: &Questionnaire{
			Meta: Meta{
				Title:       "Vendor Risk Questionnaire",
				Description: "Third-party vendor risk assessment questionnaire with SBOM cross-references.",
				CreatedAt:   time.Now(),
			},
			Version:    "1.0.0",
			SBOMRefs:   []SBOMReference{},
			Tags:       []string{"vendor-risk", "sbom"},
		},
	}
}

func (b *QuestionnaireBuilder) SetMeta(title, description, author string) *QuestionnaireBuilder {
	b.base.Meta.Title = title
	if description != "" {
		b.base.Meta.Description = description
	}
	if author != "" {
		b.base.Meta.Author = author
	}
	return b
}

func (b *QuestionnaireBuilder) SetVersion(v string) *QuestionnaireBuilder {
	b.version = v
	return b
}

func (b *QuestionnaireBuilder) AddTag(tag string) *QuestionnaireBuilder {
	if !contains(b.base.Tags, tag) {
		b.base.Tags = append(b.base.Tags, tag)
	}
	return b
}

// StartSection begins a new section. Returns the builder for chaining.
func (b *QuestionnaireBuilder) StartSection(title string, order int) *Section {
	if b.current != nil && len(b.current.Questions) > 0 {
		b.base.Sections = append(b.base.Sections, *b.current)
	}

	b.current = &Section{
		ID:          fmt.Sprintf("sec_%d", len(b.base.Sections)+1),
		Title:       title,
		Description: "",
		Order:       order,
		Questions:   []Question{},
		SBOMScope:    SBOMScope{},
	}

	return b.current
}

// FinishSection completes the current section and returns it.
func (b *QuestionnaireBuilder) FinishSection() *Section {
	if b.current != nil && len(b.current.Questions) > 0 {
		b.base.Sections = append(b.base.Sections, *b.current)
	}

	return b.current
}

// AddSBOMScope sets the SBOM scope for the current section.
func (b *QuestionnaireBuilder) AddSBOMScope(componentID, version, licenseRef string) *Section {
	if b.current != nil {
		b.current.SBOMScope = SBOMScope{
			ComponentID: componentID,
			Version:     version,
			LicenseRef:  licenseRef,
		}
	}

	return b.current
}

// AddQuestion adds a question to the current section.
func (b *QuestionnaireBuilder) AddQuestion(qType QType, title string, required bool) *Question {
	if b.current == nil {
		b.StartSection("Default Section", 0)
	}

	id := fmt.Sprintf("q_%d", len(b.base.Sections)*10+len(b.current.Questions))

	q := Question{
		ID:          id,
		Type:        qType,
		Title:       title,
		Description: "",
		Order:       len(b.current.Questions) + 1,
		Required:    required,
	}

	b.current.Questions = append(b.current.Questions, q)
	return &q
}

// SetDescription sets the description for a question.
func (b *QuestionnaireBuilder) SetDescription(qID string, desc string) {
	for i := range b.base.Sections {
		for j := range b.base.Sections[i].Questions {
			if b.base.Sections[i].Questions[j].ID == qID {
				b.base.Sections[i].Questions[j].Description = desc
				return
			}
		}
	}
}

// AddOption adds an answer option to a question.
func (b *QuestionnaireBuilder) AddOption(qID string, value, label, subtext string) {
	for i := range b.base.Sections {
		for j := range b.base.Sections[i].Questions {
			if b.base.Sections[i].Questions[j].ID == qID {
				b.base.Sections[i].Questions[j].Options = append(b.base.Sections[i].Questions[j].Options, AnswerOption{
					Value:  value,
					Label:  label,
					Subtext: subtext,
				})
				return
			}
		}
	}
}

// AddSBOMRef adds an SBOM reference to a question.
func (b *QuestionnaireBuilder) AddSBOMRef(qID string, name, version, category, licenseID string) {
	for i := range b.base.Sections {
		for j := range b.base.Sections[i].Questions {
			if b.base.Sections[i].Questions[j].ID == qID {
				b.base.Sections[i].Questions[j].SBOMRefs = append(b.base.Sections[i].Questions[j].SBOMRefs, SBOMCompRef{
					Name:      name,
					Version:   version,
					Category:  category,
					LicenseID: licenseID,
				})
				return
			}
		}
	}
}

// AddValidator adds a validator to a question.
func (b *QuestionnaireBuilder) AddValidator(qID string, pattern string, minLength, maxLength int, choices []string) {
	for i := range b.base.Sections {
		for j := range b.base.Sections[i].Questions {
			if b.base.Sections[i].Questions[j].ID == qID {
				v := &QuestionValidator{
					Pattern:    &PatternRule{Pattern: pattern},
					MinLength:  minLength,
					MaxLength:  maxLength,
					Choices:    choices,
				}

				if v.Pattern != nil && v.Pattern.Message == "" {
					v.Pattern.Message = "Must match the required pattern."
				}

				b.base.Sections[i].Questions[j].Validator = v
				return
			}
		}
	}
}

// =============================================================================
// SBOM Cross-Reference Logic
// =============================================================================

func (q *Question) ValidateSBOMRefs(sbomData map[string]map[string]string) error {
	var errs []string

	for _, ref := range q.SBOMRefs {
		if sbom, ok := sbomData[ref.Name]; ok {
			if ver, exists := sbom["version"]; exists && ver != ref.Version {
				errs = append(errs, fmt.Sprintf("Version mismatch for %s: expected %q, got %q", ref.Name, ref.Version, ver))
			}

			if lic, exists := sbom["license_id"]; exists && lic != ref.LicenseID {
				errs = append(errs, fmt.Sprintf("License mismatch for %s: expected %q, got %q", ref.Name, ref.LicenseID, lic))
			}
		} else {
			errs = append(errs, fmt.Sprintf("Unknown component in SBOM: %s", ref.Name))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%d SBOM reference errors:\n%s", len(errs), strings.Join(errs, "\n"))
	}
	return nil
}

func (s *Section) ValidateSBOMScope(sbomData map[string]map[string]string) error {
	if s.SBOMScope.ComponentID == "" || s.SBOMScope.Version == "" {
		return nil // No scope defined
	}

	if sbom, ok := sbomData[s.SBOMScope.ComponentID]; ok {
		if ver, exists := sbom["version"]; exists && ver != s.SBOMScope.Version {
			return fmt.Errorf("SBOM scope version mismatch for %s: expected %q, got %q", 
				s.SBOMScope.ComponentID, s.SBOMScope.Version, ver)
		}
	}

	return nil
}

// =============================================================================
// Validation Engine
// =============================================================================

func (q *Question) ValidateAnswer(answer string) error {
	if q.Validator == nil {
		return nil
	}

	v := q.Validator

	// Check required flag
	if v.Required && strings.TrimSpace(answer) == "" {
		return fmt.Errorf("required field is empty")
	}

	// Check minimum length
	if v.MinLength > 0 && len(strings.TrimSpace(answer)) < v.MinLength {
		return fmt.Errorf("answer must be at least %d characters", v.MinLength)
	}

	// Check maximum length
	if v.MaxLength > 0 && len(strings.TrimSpace(answer)) > v.MaxLength {
		return fmt.Errorf("answer must not exceed %d characters", v.MaxLength)
	}

	// Check choices (for dropdown/checkbox)
	if len(v.Choices) > 0 {
		valid := false
		for _, choice := range v.Choices {
			if answer == choice || strings.Contains(answer, choice) {
				valid = true
				break
			}
		}

		if !valid && len(answer) > 0 {
			return fmt.Errorf("answer must be one of: %v", v.Choices)
		}
	}

	// Check pattern (regex)
	if v.Pattern != nil {
		pattern := v.Pattern.Pattern
		if strings.HasPrefix(pattern, "r:") {
			pattern = pattern[1:] // Strip 'r:' prefix if present
		}

		matched, err := regexp.MatchString(pattern, answer)
		if err != nil {
			return fmt.Errorf("pattern compilation error: %w", err)
		}

		if !matched {
			return fmt.Errorf(v.Pattern.Message)
		}
	}

	return nil
}

// =============================================================================
// Serialization / Deserialization
// =============================================================================

func (q *Questionnaire) MarshalJSON() ([]byte, error) {
	type Alias Questionnaire
	aux := &struct {
		CreatedAt time.Time `json:"created_at,omitempty"`
		UpdatedAt *time.Time `json:"updated_at,omitempty"`
		Alias
	}{
		CreatedAt: q.CreatedAt,
		UpdatedAt: q.UpdatedAt,
		Alias:     Alias(*q),
	}

	return json.Marshal(aux)
}

func (q *Questionnaire) UnmarshalJSON(data []byte) error {
	type Alias Questionnaire
	aux := &struct {
		CreatedAt time.Time `json:"created_at,omitempty"`
		UpdatedAt *time.Time `json:"updated_at,omitempty"`
		Alias
	}{
		Alias: Alias(*q),
	}

	if err := json.Unmarshal(data, aux); err != nil {
		return err
	}

	q.CreatedAt = aux.CreatedAt
	q.UpdatedAt = aux.UpdatedAt

	return nil
}

func (q *Questionnaire) MarshalYAML() (interface{}, error) {
	type Alias Questionnaire
	aux := &struct {
		CreatedAt time.Time `yaml:"created_at,omitempty"`
		UpdatedAt *time.Time `yaml:"updated_at,omitempty"`
		Alias
	}{
		CreatedAt: q.CreatedAt,
		UpdatedAt: q.UpdatedAt,
		Alias:     Alias(*q),
	}

	return aux, nil
}

func (q *Questionnaire) UnmarshalYAML(value *yaml.Node) error {
	type Alias Questionnaire
	aux := &struct {
		CreatedAt time.Time `yaml:"created_at,omitempty"`
		UpdatedAt *time.Time `yaml:"updated_at,omitempty"`
		Alias
	}{
		Alias: Alias(*q),
	}

	if err := value.Decode(&aux); err != nil {
		return err
	}

	q.CreatedAt = aux.CreatedAt
	q.UpdatedAt = aux.UpdatedAt

	return nil
}

// =============================================================================
// File I/O Operations
// =============================================================================

func (q *Questionnaire) SaveJSON(path string) error {
	data, err := q.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}