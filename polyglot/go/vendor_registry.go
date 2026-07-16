package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Vendor represents a third-party vendor in the registry
type Vendor struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Categories  []string      `json:"categories,omitempty"`
	RiskScore   float64       `json:"risk_score"`
	LastUpdated time.Time     `json:"last_updated"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// SBOMEntry represents a software component from an SBOM linked to a vendor
type SBOMEntry struct {
	VendorID      string   `json:"vendor_id"`
	ComponentName string   `json:"component_name"`
	Version       string   `json:"version"`
	License       string   `json:"license,omitempty"`
	PackageMgr    string   `json:"package_manager,omitempty"`
}

// Registry holds the vendor registry state and operations
type Registry struct {
	mu         sync.RWMutex
	vendors    map[string]*Vendor
	sbomCache  map[string][]SBOMEntry
	thresholds map[string]float64 // "high", "medium", "low" risk thresholds
}

// NewRegistry creates a new vendor registry with default thresholds
func NewRegistry() *Registry {
	r := &Registry{
		vendors:    make(map[string]*Vendor),
		sbomCache:  make(map[string][]SBOMEntry),
		thresholds: map[string]float64{
			"high":   8.0,
			"medium": 5.0,
			"low":    3.0,
		},
	}
	return r
}

// RiskLevel returns the risk level string for a given score
func (r *Registry) RiskLevel(score float64) string {
	if score >= r.thresholds["high"] {
		return "HIGH"
	} else if score >= r.thresholds["medium"] {
		return "MEDIUM"
	}
	return "LOW"
}

// AddVendor creates a new vendor entry with validation
func (r *Registry) AddVendor(v Vendor) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v.ID == "" {
		v.ID = fmt.Sprintf("vendor-%d", time.Now().UnixNano())
	}

	if v.Name == "" {
		return fmt.Errorf("vendor name required")
	}

	if _, exists := r.vendors[v.ID]; exists {
		return fmt.Errorf("vendor ID %s already exists", v.ID)
	}

	v.LastUpdated = time.Now()
	r.vendors[v.ID] = &v

	return nil
}

// GetVendor retrieves a vendor by ID with thread safety
func (r *Registry) GetVendor(id string, includeSBOM bool) (*Vendor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	v, exists := r.vendors[id]
	if !exists {
		return nil, fmt.Errorf("vendor %s not found", id)
	}

	if includeSBOM && v != nil {
		sbomEntries := make([]SBOMEntry, 0, len(v.SBOMEntries))
		for _, e := range v.SBOMEntries {
			if e.VendorID == id {
				sbomEntries = append(sbomEntries, e)
			}
		}
		v.SBOMEntries = sbomEntries
	}

	return v, nil
}

// SearchVendors performs a case-insensitive search across multiple fields
func (r *Registry) SearchVendors(query string) ([]Vendor, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if query == "" {
		vendors := make([]Vendor, 0, len(r.vendors))
		for _, v := range r.vendors {
			vendors = append(vendors, *v)
		}
		return vendors, nil
	}

	queryLower := strings.ToLower(query)
	results := make([]Vendor, 0)

	for _, v := range r.vendors {
		if strings.Contains(strings.ToLower(v.Name), queryLower) ||
			strings.Contains(strings.Join(v.Categories, " "), queryLower) {
			results = append(results, *v)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].RiskScore > results[j].RiskScore
	})

	return results, nil
}

// CrossRefSBOM parses an SBOM and finds all matching vendors in the registry
func (r *Registry) CrossRefSBOM(sbomData []byte) ([]SBOMEntry, error) {
	var entries []SBOMEntry

	err := json.Unmarshal(sbomData, &entries)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SBOM: %w", err)
	}

	matched := make([]SBOMEntry, 0)
	for _, e := range entries {
		vendor, exists := r.GetVendor(e.VendorID, false)
		if exists && vendor != nil {
			e.RiskLevel = r.RiskLevel(vendor.RiskScore)
			matched = append(matched, e)
		} else if !exists {
			e.Status = "UNKNOWN_VENDOR"
			matched = append(matched, e)
		}
	}

	return matched, nil
}

// UpdateRiskScore modifies a vendor's risk score with validation
func (r *Registry) UpdateRiskScore(id string, newScore float64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	v, exists := r.vendors[id]
	if !exists {
		return fmt.Errorf("vendor %s not found", id)
	}

	oldScore := v.RiskScore
	v.RiskScore = newScore
	v.LastUpdated = time.Now()

	return nil
}

// GetRiskSummary returns a summary of all vendors grouped by risk level
func (r *Registry) GetRiskSummary() map[string][]*Vendor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	summary := make(map[string][]*Vendor, 3)
	for _, v := range r.vendors {
		level := r.RiskLevel(v.RiskScore)
		summary[level] = append(summary[level], v)
	}

	return summary
}

// ExportJSON marshals the entire registry to JSON bytes
func (r *Registry) ExportJSON() ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	type Export struct {
		Vendors    []Vendor      `json:"vendors"`
		SBOMCache  map[string][]SBOMEntry `json:"sbom_cache,omitempty"`
		Thresholds map[string]float64 `json:"thresholds"`
	}

	export := Export{
		Vendors:     make([]Vendor, 0, len(r.vendors)),
		Thresholds:  r.thresholds,
		SBOMCache:   r.sbomCache,
	}

	for _, v := range r.vendors {
		export.Vendors = append(export.Vendors, *v)
	}

	return json.MarshalIndent(&export, "", "  ")
}

// ImportJSON loads vendors from JSON bytes
func (r *Registry) ImportJSON(data []byte) error {
	var export Export
	err := json.Unmarshal(data, &export)
	if err != nil {
		return fmt.Errorf("failed to parse registry JSON: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, v := range export.Vendors {
		v.ID = fmt.Sprintf("%s-%d", v.ID, time.Now().UnixNano())
		r.vendors[v.ID] = &v
	}

	return nil
}

// VendorService provides a service layer for vendor operations
type VendorService struct {
	registry *Registry
}

// NewVendorService creates a new service instance
func NewVendorService(registry *Registry) *VendorService {
	return &VendorService{registry: registry}
}

// CreateVendor wraps AddVendor with error handling and logging
func (s *VendorService) CreateVendor(name string, categories []string, riskScore float64) (*Vendor, error) {
	v := Vendor{
		Name:       name,
		Categories: categories,
		RiskScore:  riskScore,
	}

	if err := s.registry.AddVendor(v); err != nil {
		return nil, fmt.Errorf("failed to create vendor %s: %w", name, err)
	}

	return &v, nil
}

// FindVendorsByCategory returns all vendors in a specific category
func (s *VendorService) FindVendorsByCategory(category string) ([]*Vendor, error) {
	results := make([]*Vendor, 0)
	s.registry.mu.RLock()
	defer s.registry.mu.RUnlock()

	for _, v := range s.registry.vendors {
		for _, c := range v.Categories {
			if strings.EqualFold(c, category) {
				results = append(results, v)
				break
			}
		}
	}

	return results, nil
}

// CalculateAggregateRisk computes the average risk score across all vendors
func (s *VendorService) CalculateAggregateRisk() float64 {
	s.registry.mu.RLock()
	defer s.registry.mu.RUnlock()

	if len(s.registry.vendors) == 0 {
		return 0.0
	}

	var total float64
	for _, v := range s.registry.vendors {
		total += v.RiskScore
	}

	return total / float64(len(s.registry.vendors))
}

// Main demo function showcasing all capabilities
func main() {
	fmt.Println("=== VendorVet Registry Demo ===\n")

	reg := NewRegistry()
	service := NewVendorService(reg)

	// 1. Create vendors
	fmt.Println("--- Creating Vendors ---")
	vendor1, _ := service.CreateVendor(
		"Acme Corp",
		[]string{"cloud", "infrastructure"},
		7.5,
	)
	vendor2, _ := service.CreateVendor(
		"TechSolutions Inc",
		[]string{"software", "saas"},
		3.2,
	)

	fmt.Printf("Created: %+v\n", vendor1)
	fmt.Printf("Risk Level: %s\n\n", reg.RiskLevel(vendor1.RiskScore))

	// 2. Search and retrieve
	fmt.Println("--- Searching Vendors ---")
	results, _ := reg.SearchVendors("cloud")
	for _, v := range results {
		fmt.Printf("Found: %s (Risk: %.1f)\n", v.Name, v.RiskScore)
	}

	vendor, _ := reg.GetVendor(vendor1.ID, true)
	fmt.Printf("\nFull Vendor Record:\n%+v\n\n", vendor)

	// 3. Risk summary
	fmt.Println("--- Risk Summary ---")
	summary := reg.GetRiskSummary()
	for level, vendors := range summary {
		fmt.Printf("%s: %d vendors (avg risk: %.2f)\n", level, len(vendors), calculateAvgRisk(vendors))
	}

	// 4. Export/Import simulation
	fmt.Println("\n--- Export/Import Demo ---")
	exported, _ := reg.ExportJSON()
	fmt.Printf("Exported size: %d bytes\n", len(exported))

	// 5. Aggregate calculation
	fmt.Printf("\nAggregate Risk Score: %.2f\n", service.CalculateAggregateRisk())

	// 6. Update risk score
	fmt.Println("\n--- Updating Risk Scores ---")
	reg.UpdateRiskScore(vendor1.ID, 9.0)
	vendor3, _ := reg.GetVendor(vendor1.ID, false)
	fmt.Printf("Updated risk: %.1f (Level: %s)\n", vendor3.RiskScore, reg.RiskLevel(vendor3.RiskScore))

	// 7. Final state
	fmt.Println("\n--- Final Registry State ---")
	exportedFinal, _ := reg.ExportJSON()
	var finalExport Export
	json.Unmarshal(exportedFinal, &finalExport)
	for _, v := range finalExport.Vendors {
		fmt.Printf("ID: %s | Name: %-20s | Risk: %.1f | Level: %s\n",
			v.ID, v.Name, v.RiskScore, reg.RiskLevel(v.RiskScore))
	}

	// 8. Error handling demo
	fmt.Println("\n--- Error Handling Demo ---")
	_, err := reg.GetVendor("nonexistent-id-12345", false)
	if err != nil {
		fmt.Printf("Expected error: %v\n", err)
	}

	_, err = service.CreateVendor("", []string{}, 0.0)
	if err != nil {
		fmt.Printf("Validation error: %v\n", err)
	}
}

// Helper function for risk calculation
func calculateAvgRisk(vendors []*Vendor) float64 {
	if len(vendors) == 0 {
		return 0.0
	}
	var total float64
	for _, v := range vendors {
		total += v.RiskScore
	}
	return total / float64(len(vendors))
}

// Export type alias for main function
type Export struct {
	Vendors    []Vendor      `json:"vendors"`
	SBOMCache  map[string][]SBOMEntry `json:"sbom_cache,omitempty"`
	Thresholds map[string]float64 `json:"thresholds"`
}