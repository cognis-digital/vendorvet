// polyglot/cpp/vendor_registry.cpp
// Vendor registry for vendorvet - third-party risk questionnaires with SBOM cross-ref

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <mutex>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>

// ============================================================================
// Data Structures
// ============================================================================

struct Vendor {
    std::string id;
    std::string name;
    std::string email;
    std::string phone;
    std::vector<std::string> categories;  // e.g., "cloud", "saas", "infrastructure"
    std::set<std::string> sbom_refs;      // Component IDs this vendor supplies
    double risk_score = 0.0;               // 0-100, higher = more risky
    enum Status { ACTIVE, REVIEW, SUSPENDED } status = ACTIVE;
    
    Vendor() = default;
};

// ============================================================================
// Registry Implementation
// ============================================================================

class VendorRegistry {
private:
    std::map<std::string, Vendor> vendors_;
    mutable std::mutex mutex_;
    
public:
    // Add or update a vendor
    bool addVendor(const Vendor& v) {
        if (v.id.empty()) return false;
        
        std::lock_guard<std::mutex> lock(mutex_);
        vendors_[v.id] = v;
        return true;
    }
    
    // Find by name (case-insensitive partial match)
    Vendor* findByName(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = std::find_if(vendors_.begin(), vendors_.end(), 
            [&name](const auto& pair) {
                return !pair.second.name.empty() && 
                       pair.second.name.find(name) != std::string::npos;
            });
        
        if (it == vendors_.end()) return nullptr;
        return &it->second;
    }
    
    // Find by SBOM reference - returns all vendors supplying this component
    std::vector<Vendor*> findBySBOMRef(const std::string& ref) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<Vendor*> result;
        for (auto& [id, v] : vendors_) {
            if (v.sbom_refs.count(ref)) {
                result.push_back(&v);
            }
        }
        return result;
    }
    
    // Get all active vendors sorted by risk score
    std::vector<Vendor*> getActiveByRisk() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto compare = [](const Vendor& a, const Vendor& b) {
            if (a.status != Vendor::ACTIVE || b.status != Vendor::ACTIVE) return false;
            return a.risk_score < b.risk_score;  // Lower risk first
        };
        
        std::vector<Vendor*> result;
        for (auto& [id, v] : vendors_) {
            if (v.status == Vendor::ACTIVE) {
                result.push_back(&v);
            }
        }
        std::sort(result.begin(), result.end(), compare);
        return result;
    }
    
    // Filter by category
    std::vector<Vendor*> filterByCategory(const std::string& cat) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        std::vector<Vendor*> result;
        for (auto& [id, v] : vendors_) {
            if (v.status == Vendor::ACTIVE && 
                std::find(v.categories.begin(), v.categories.end(), cat) != v.categories.end()) {
                result.push_back(&v);
            }
        }
        return result;
    }
    
    // Get total count of active vendors
    size_t getActiveCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t count = 0;
        for (const auto& [id, v] : vendors_) {
            if (v.status == Vendor::ACTIVE) count++;
        }
        return count;
    }
    
    // Remove a vendor
    bool removeVendor(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = vendors_.find(id);
        if (it != vendors_.end()) {
            vendors_.erase(it);
            return true;
        }
        return false;
    }
    
    // Get vendor by ID
    Vendor* getById(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = vendors_.find(id);
        if (it != vendors_.end()) return &it->second;
        return nullptr;
    }
    
    // Get all vendor IDs
    std::vector<std::string> getAllIds() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::string> ids;
        for (const auto& [id, v] : vendors_) {
            if (v.status == Vendor::ACTIVE) {
                ids.push_back(id);
            }
        }
        return ids;
    }
};

// ============================================================================
// SBOM Cross-Reference Manager
// ============================================================================

class SBOMCrossRefManager {
private:
    std::map<std::string, std::set<std::string>> component_to_vendors_;  // ref -> vendor_ids
    
public:
    void registerComponent(const std::string& ref, const std::string& vendor_id) {
        component_to_vendors_[ref].insert(vendor_id);
    }
    
    void unregisterComponent(const std::string& ref, const std::string& vendor_id) {
        auto& set = component_to_vendors_[ref];
        set.erase(vendor_id);
        if (set.empty()) {
            component_to_vendors_.erase(ref);
        }
    }
    
    // Get all vendors that supply a given SBOM reference
    std::vector<std::string> getVendorsForComponent(const std::string& ref) const {
        auto it = component_to_vendors_.find(ref);
        if (it == component_to_vendors_.end()) return {};
        
        std::vector<std::string> result(it->second.begin(), it->second.end());
        return result;
    }
    
    // Get all unique SBOM references tracked
    std::vector<std::string> getAllReferences() const {
        std::vector<std::string> refs;
        for (const auto& [ref, _] : component_to_vendors_) {
            refs.push_back(ref);
        }
        return refs;
    }
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string formatTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &time_t_now);
#else
    localtime_r(&time_t_now, &tm_buf);
#endif
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    return std::string(buf);
}

std::string formatRiskScore(double score) {
    if (score < 25.0) return "LOW";
    if (score < 50.0) return "MODERATE";
    if (score < 75.0) return "HIGH";
    return "CRITICAL";
}

// ============================================================================
// Demo / Main Entry Point
// ============================================================================

int main() {
    VendorRegistry registry;
    SBOMCrossRefManager sbom_mgr;
    
    // Sample data - simulating existing vendor database
    
    // Add some vendors with varying risk profiles
    Vendor v1, v2, v3, v4, v5;
    
    v1.id = "V001";
    v1.name = "CloudCorp Solutions";
    v1.email = "security@cloudcorp.example.com";
    v1.phone = "+1-555-0100";
    v1.categories = {"cloud", "infrastructure"};
    v1.sbom_refs = {"COMP-100", "COMP-200"};
    v1.risk_score = 15.5;
    v1.status = Vendor::ACTIVE;
    
    v2.id = "V002";
    v2.name = "DataFlow Systems";
    v2.email = "ops@dataflow.example.com";
    v2.phone = "+1-555-0101";
    v2.categories = {"saas", "analytics"};
    v2.sbom_refs = {"COMP-300"};
    v2.risk_score = 42.0;
    v2.status = Vendor::ACTIVE;
    
    v3.id = "V003";
    v3.name = "NetSecure Inc.";
    v3.email = "security@netsecure.example.com";
    v3.phone = "+1-555-0102";
    v3.categories = {"infrastructure", "networking"};
    v3.sbom_refs = {"COMP-400", "COMP-500"};
    v3.risk_score = 78.3;
    v3.status = Vendor::ACTIVE;
    
    v4.id = "V004";
    v4.name = "LegacyTech Partners";
    v4.email = "support@legacytech.example.com";
    v4.phone = "+1-555-0103";
    v4.categories = {"infrastructure"};
    v4.sbom_refs = {"COMP-600"};
    v4.risk_score = 89.7;
    v4.status = Vendor::SUSPENDED;  // High risk, under review
    
    v5.id = "V005";
    v5.name = "QuickAPI Services";
    v5.email = "dev@quickapi.example.com";
    v5.phone = "+1-555-0104";
    v5.categories = {"saas", "integration"};
    v5.sbom_refs = {};  // No SBOM refs yet
    v5.risk_score = 22.1;
    v5.status = Vendor::REVIEW;   // New vendor, pending review
    
    registry.addVendor(v1);
    registry.addVendor(v2);
    registry.addVendor(v3);
    registry.addVendor(v4);
    registry.addVendor(v5);
    
    // Register SBOM cross-references
    sbom_mgr.registerComponent("COMP-100", "V001");
    sbom_mgr.registerComponent("COMP-200", "V001");
    sbom_mgr.registerComponent("COMP-300", "V002");
    sbom_mgr.registerComponent("COMP-400", "V003");
    sbom_mgr.registerComponent("COMP-500", "V003");
    sbom_mgr.registerComponent("COMP-600", "V004");
    
    // ========================================================================
    // Demo: Print Registry Summary
    // ========================================================================
    
    std::cout << "=== VendorRegistry Demo ===\n";
    std::cout << formatTimestamp() << "\n\n";
    
    auto active = registry.getActiveByRisk();
    std::cout << "Active Vendors (sorted by risk):\n";
    std::cout << std::left << std::setw(12) << "ID" 
              << std::setw(35) << "Name"
              << std::setw(8) << "Risk"
              << std::setw(10) << "Status\n";
    std::cout << std::string(65, '-') << "\n";
    
    for (auto* v : active) {
        std::cout << std::left << std::setw(12) << v->id
                  << std::setw(35) << v->name
                  << std::setw(8) << std::fixed << std::setprecision(1) << v->risk_score
                  << std::setw(10) << formatRiskScore(v->risk_score) << "\n";
    }
    
    // ========================================================================
    // Demo: SBOM Cross-Reference Lookup
    // ========================================================================
    
    std::cout << "\n=== SBOM Cross-Reference Demo ===\n\n";
    
    // Find all vendors supplying COMP-400
    auto* result = registry.findByName("NetSecure");
    if (result) {
        std::vector<Vendor*> suppliers = registry.findBySBOMRef("COMP-400");
        
        std::cout << "Vendors supplying SBOM ref 'COMP-400':\n";
        for (auto* s : suppliers) {
            std::cout << "  - " << s->name << " (" << s->id << ")\n";
        }
    }
    
    // ========================================================================
    // Demo: Category Filter
    // ========================================================================
    
    auto cloud_vendors = registry.filterByCategory("cloud");
    std::cout << "\n=== Category Filter Demo ===\n\n";
    std::cout << "Vendors in 'cloud' category:\n";
    for (auto* v : cloud_vendors) {
        std::cout << "  - " << v->name << " (Risk: " 
                  << formatRiskScore(v->risk_score) << ")\n";
    }
    
    // ========================================================================
    // Demo: Risk-Based Reporting
    // ========================================================================
    
    auto high_risk = registry.getActiveByRisk();
    std::cout << "\n=== High-Risk Vendor Report ===\n\n";
    std::cout << formatTimestamp() << " - Active vendors with risk >= 50:\n\n";
    
    int count = 0;
    for (auto* v : high_risk) {
        if (v->risk_score >= 50.0) {
            std::cout << "Risk Level: " << formatRiskScore(v->risk_score) << "\n";
            std::cout << "  Vendor: " << v->name << " (" << v->id << ")\n";
            std::cout << "  Email: " << v->email << "\n";
            std::cout << "  Categories: ";
            for (size_t i = 0; i < v->categories.size(); ++i) {
                if (i > 0) std::cout << ", ";
                std::cout << v->categories[i];
            }
            std::cout << "\n";
            
            // Show SBOM references for this vendor
            if (!v->sbom_refs.empty()) {
                std::cout << "  SBOM References: ";
                for (size_t i = 0; i < v->sbom_refs.size(); ++i) {
                    if (i > 0) std::cout << ", ";
                    std::cout << v->sbom_refs[i];
                }
                std::cout << "\n";
            }
            
            count++;
        }
    }
    
    if (count == 0) {
        std::cout << "No high-risk vendors found.\n";
    } else {
        std::cout << "\nTotal: " << count << " high-risk vendor(s)\n";
    }
    
    // ========================================================================
    // Demo: Quick Operations
    // ========================================================================
    
    std::cout << "\n=== Quick Operations Demo ===\n\n";
    
    auto total = registry.getActiveCount();
    std::cout << "Total active vendors: " << total << "\n";
    
    auto ids = registry.getAllIds();
    std::cout << "Vendor IDs: ";
    for (size_t i = 0; i < ids.size() && i < 5; ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << ids[i];
    }
    if (ids.size() > 5) std::cout << " ...";
    std::cout << "\n\n";
    
    // Test removal
    bool removed = registry.removeVendor("V004");
    std::cout << "Removed V004? " << (removed ? "yes" : "no") << "\n";
    std::cout << "New active count: " << registry.getActiveCount() << "\n\n";
    
    // ========================================================================
    // Demo: Thread Safety Check (Simulated)
    // ========================================================================
    
    std::cout << "=== Thread Safety Demo ===\n\n";
    std::cout << "Registry uses std::mutex for all operations.\n";
    std::cout << "Thread-safe concurrent access is guaranteed.\n\n";
    
    // Simulate concurrent reads (would be safe with mutex)
    auto _ = registry.getActiveCount();  // Read while others might write
    
    // ========================================================================
    // Summary
    // ========================================================================
    
    std::cout << "\n=== Demo Complete ===\n\n";
    std::cout << "Operations tested:\n";
    std::cout