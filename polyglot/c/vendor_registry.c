#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#define MAX_VENDORS 1024
#define MAX_PACKAGES_PER_VENDOR 64
#define DEFAULT_RISK_SCORE 50

typedef enum { VENDOR_ACTIVE, VENDOR_SUSPECTED, VENDOR_FLAGGED } vendor_status_t;

typedef struct {
    char id[64];
    char name[256];
    char website[128];
    char email[128];
    int risk_score;
    vendor_status_t status;
    time_t created_at;
} vendor_t;

typedef struct {
    char package_name[64];
    char version[32];
    char license[64];
    int cpe_id;
    char sbom_ref[128];
} pkg_t;

typedef struct {
    vendor_t *vendor;
    pkg_t packages[MAX_PACKAGES_PER_VENDOR];
    int num_packages;
    time_t last_reviewed;
} registry_entry_t;

static registry_entry_t registry[MAX_VENDORS];
static int registry_count = 0;

void registry_init(void) {
    for (int i = 0; i < MAX_VENDORS; i++) {
        registry[i].vendor = NULL;
        registry[i].num_packages = 0;
        registry[i].last_reviewed = time(NULL);
    }
}

static int find_by_id(const char *id) {
    for (int i = 0; i < MAX_VENDORS; i++) {
        if (registry[i].vendor && strcmp(registry[i].vendor->id, id) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_by_name(const char *name) {
    for (int i = 0; i < MAX_VENDORS; i++) {
        if (registry[i].vendor && 
            strcasecmp(registry[i].vendor->name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int find_by_cpe(int cpe_id) {
    for (int i = 0; i < MAX_VENDORS; i++) {
        if (registry[i].vendor && 
            registry[i].num_packages > 0) {
            for (int j = 0; j < registry[i].num_packages; j++) {
                if (registry[i].packages[j].cpe_id == cpe_id) {
                    return i;
                }
            }
        }
    }
    return -1;
}

vendor_t *registry_add_vendor(const char *id, const char *name, 
                              const char *website, const char *email) {
    if (registry_count >= MAX_VENDORS) {
        fprintf(stderr, "Registry full\n");
        return NULL;
    }

    registry_entry_t *entry = &registry[registry_count];
    vendor_t *v = entry->vendor = &entry->packages[0];  // Reuse first pkg slot as vendor data
    
    strncpy(v->id, id, sizeof(v->id) - 1);
    v->id[sizeof(v->id) - 1] = '\0';
    
    strncpy(v->name, name, sizeof(v->name) - 1);
    v->name[sizeof(v->name) - 1] = '\0';
    
    if (website) {
        strncpy(v->website, website, sizeof(v->website) - 1);
        v->website[sizeof(v->website) - 1] = '\0';
    } else {
        v->website[0] = '\0';
    }
    
    if (email) {
        strncpy(v->email, email, sizeof(v->email) - 1);
        v->email[sizeof(v->email) - 1] = '\0';
    } else {
        v->email[0] = '\0';
    }
    
    v->risk_score = DEFAULT_RISK_SCORE;
    v->status = VENDOR_ACTIVE;
    v->created_at = time(NULL);
    
    entry->num_packages = 1;
    registry_count++;
    
    return v;
}

bool registry_update_risk(int index, int new_score) {
    if (index < 0 || index >= MAX_VENDORS) {
        return false;
    }
    
    vendor_t *v = registry[index].vendor;
    if (!v) {
        return false;
    }
    
    v->risk_score = new_score;
    v->last_reviewed = time(NULL);
    
    // Auto-flag high risk vendors
    if (new_score >= 80) {
        v->status = VENDOR_FLAGGED;
    } else if (new_score >= 50 && v->status != VENDOR_ACTIVE) {
        v->status = VENDOR_SUSPECTED;
    }
    
    return true;
}

bool registry_add_package(int vendor_index, const char *pkg_name, 
                         const char *version, int cpe_id) {
    if (vendor_index < 0 || vendor_index >= MAX_VENDORS) {
        return false;
    }
    
    vendor_t *v = registry[vendor_index].vendor;
    if (!v) {
        return false;
    }
    
    if (registry[vendor_index].num_packages >= MAX_PACKAGES_PER_VENDOR - 1) {
        return false;
    }
    
    pkg_t *p = &registry[vendor_index].packages[registry[vendor_index].num_packages];
    
    strncpy(p->package_name, pkg_name, sizeof(p->package_name) - 1);
    p->package_name[sizeof(p->package_name) - 1] = '\0';
    
    if (version) {
        strncpy(p->version, version, sizeof(p->version) - 1);
        p->version[sizeof(p->version) - 1] = '\0';
    } else {
        p->version[0] = '\0';
    }
    
    p->cpe_id = cpe_id;
    p->sbom_ref[0] = '\0';
    
    registry[vendor_index].num_packages++;
    return true;
}

vendor_t *registry_lookup(const char *id) {
    int idx = find_by_id(id);
    if (idx >= 0) {
        return registry[idx].vendor;
    }
    return NULL;
}

bool registry_export_sbom_refs(FILE *fp, const vendor_t *v) {
    if (!v || !fp) {
        return false;
    }
    
    fprintf(fp, "  <Vendor ID=\"%s\" Name=\"%s\">\n", v->id, v->name);
    fprintf(fp, "    <RiskScore>%d</RiskScore>\n", v->risk_score);
    fprintf(fp, "    <Status>%s</Status>\n", 
            (v->status == VENDOR_ACTIVE) ? "Active" :
            (v->status == VENDOR_SUSPECTED) ? "Suspected" : "Flagged");
    
    if (v->website[0]) {
        fprintf(fp, "    <Website>%s</Website>\n", v->website);
    }
    
    fprintf(fp, "    <Packages>\n");
    for (int i = 0; i < registry[vendor_index].num_packages; i++) {
        pkg_t *p = &registry[vendor_index].packages[i];
        fprintf(fp, "      <Package Name=\"%s\" Version=\"%s\" CPE=\"%d\">\n",
                p->package_name, p->version, p->cpe_id);
        
        if (p->sbom_ref[0]) {
            fprintf(fp, "        <SBOMRef>%s</SBOMRef>\n", p->sbom_ref);
        }
        
        fprintf(fp, "      </Package>\n");
    }
    fprintf(fp, "    </Packages>\n");
    
    fprintf(fp, "  </Vendor>\n");
    return true;
}

int main(void) {
    registry_init();
    
    // Demo: Add some vendors
    vendor_t *v1 = registry_add_vendor("V001", "Acme Corp", 
                                       "https://acme.com", "security@acme.com");
    vendor_t *v2 = registry_add_vendor("V002", "Globex Inc", 
                                       "https://globex.net", NULL);
    
    // Add packages with SBOM refs
    registry_add_package(0, "openssl", "1.1.1k", 12345);
    registry_add_package(0, "libcurl", "7.84.0", 12346);
    registry_add_package(1, "nginx", "1.24.0", 12347);
    
    // Update risk score for one vendor
    registry_update_risk(0, 75);  // Medium-high risk
    
    // Export to XML format (common for SBOM exchange)
    FILE *fp = fopen("/tmp/vendorvet_sbom.xml", "w");
    if (fp) {
        fprintf(fp, "<SBOMExport>\n");
        fprintf(fp, "  <Vendors>\n");
        
        // Export all vendors with their packages
        for (int i = 0; i < MAX_VENDORS && registry[i].vendor; i++) {
            vendor_t *v = registry[i].vendor;
            fprintf(fp, "    <!-- %s -->\n", v->name);
            
            // Check if this vendor has any packages
            int pkg_idx = find_by_id(v->id);
            if (pkg_idx >= 0) {
                registry_export_sbom_refs(fp, v);
            } else {
                fprintf(fp, "    <Vendor ID=\"%s\" Name=\"%s\">\n", 
                        v->id, v->name);
                fprintf(fp, "      <RiskScore>%d</RiskScore>\n", v->risk_score);
                fprintf(fp, "      <Status>Active</Status>\n");
                if (v->website[0]) {
                    fprintf(fp, "      <Website>%s</Website>\n", v->website);
                }
                fprintf(fp, "    </Vendor>\n");
            }
        }
        
        fprintf(fp, "  </Vendors>\n");
        fprintf(fp, "</SBOMExport>\n");
        fclose(fp);
        printf("Exported SBOM refs to /tmp/vendorvet_sbom.xml\n");
    }
    
    // Print summary
    printf("\n=== Vendor Registry Summary ===\n");
    for (int i = 0; i < MAX_VENDORS && registry[i].vendor; i++) {
        vendor_t *v = registry[i].vendor;
        int idx = find_by_id(v->id);
        
        printf("ID: %s | Name: %s | Risk: %d/100 ", 
               v->id, v->name, v->risk_score);
        
        switch (v->status) {
            case VENDOR_ACTIVE: printf("[OK]"); break;
            case VENDOR_SUSPECTED: printf("[WARN]"); break;
            case VENDOR_FLAGGED: printf("[CRIT]"); break;
        }
        
        if (idx >= 0 && registry[idx].num_packages > 0) {
            printf(" | %d packages", registry[idx].num_packages);
        }
        printf("\n");
    }
    
    return 0;
}