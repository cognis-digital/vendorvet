import { Vendor, QuestionnaireResponse, SBOMEntry, RiskProfile } from './types';

export interface VendorRegistry {
  vendors: Map<string, Vendor>;
  responses: Map<string, QuestionnaireResponse[]>;
  sbomLinks: Map<string, SBOMEntry[]>;
}

class VendorRegistryImpl implements VendorRegistry {
  private vendors = new Map<string, Vendor>();
  private responses = new Map<string, QuestionnaireResponse[]>();
  private sbomLinks = new Map<string, SBOMEntry[]>();

  registerVendor(
    id: string,
    name: string,
    industry: string,
    contactEmail?: string,
    website?: string,
    headquarters?: { city: string; country: string }
  ): Vendor {
    const existing = this.vendors.get(id);
    
    if (existing) {
      // Merge update strategy - preserve what exists, override with new data
      existing.name = name;
      existing.industry = industry;
      if (contactEmail) existing.contactEmail = contactEmail;
      if (website) existing.website = website;
      if (headquarters) {
        existing.headquarters = headquarters;
      }
      
      return existing;
    }

    const vendor: Vendor = {
      id,
      name,
      industry,
      contactEmail,
      website,
      headquarters,
      createdAt: new Date(),
      updatedAt: new Date(),
      riskProfile: this.createDefaultRiskProfile()
    };

    this.vendors.set(id, vendor);
    return vendor;
  }

  private createDefaultRiskProfile(): RiskProfile {
    return {
      overallScore: 0,
      categories: {
        financialStability: 50,
        operationalContinuity: 50,
        dataSecurity: 50,
        regulatoryCompliance: 50,
        supplyChainResilience: 50
      },
      lastAssessmentDate: new Date(),
      assessmentMethodology: 'default'
    };
  }

  submitResponse(
    vendorId: string,
    questionnaireId: string,
    responses: Record<string, unknown>,
    metadata?: { submittedBy: string; timestamp: Date }
  ): QuestionnaireResponse {
    const existingResponses = this.responses.get(vendorId) || [];
    
    // Validate required fields
    if (!questionnaireId) throw new Error('Questionnaire ID is required');
    
    const response: QuestionnaireResponse = {
      questionnaireId,
      vendorId,
      responses,
      metadata: metadata || {
        submittedBy: 'system',
        timestamp: new Date()
      },
      status: 'submitted',
      createdAt: new Date(),
      updatedAt: new Date()
    };

    this.responses.set(vendorId, [...existingResponses, response]);
    
    // Update risk profile based on responses
    this.updateRiskProfileFromResponse(response);
    
    return response;
  }

  private updateRiskProfileFromResponse(response: QuestionnaireResponse): void {
    const vendor = this.vendors.get(response.vendorId);
    if (!vendor) return;

    // Simple scoring logic - in production would use ML models
    let totalScore = 0;
    let categoryCount = 0;

    for (const [key, value] of Object.entries(response.responses)) {
      const score = this.calculateQuestionScore(key, value);
      if (score !== null) {
        totalScore += score || 0;
        categoryCount++;
        
        // Update specific category scores
        if (this.mapCategoryToProfileKey(key)) {
          vendor.riskProfile.categories[
            this.mapCategoryToProfileKey(key)!
          ] = (vendor.riskProfile.categories[this.mapCategoryToProfileKey(key)] || 50) + 
             ((score! / 100) * 30); // Add up to 30 points per category
        }
      }
    }

    if (categoryCount > 0) {
      vendor.riskProfile.overallScore = Math.min(100, totalScore / categoryCount);
      vendor.riskProfile.lastAssessmentDate = new Date();
      vendor.riskProfile.assessmentMethodology = 'questionnaire';
    }

    vendor.updatedAt = new Date();
  }

  private calculateQuestionScore(questionKey: string, value: unknown): number | null {
    // Normalize numeric answers to 0-100 scale
    if (typeof value === 'number') {
      return Math.min(100, Math.max(0, value));
    }

    // Boolean questions - true = good, false = bad
    if (value === true) return 100;
    if (value === false) return 50; // Neutral for booleans

    // String answers - simple heuristic
    const strLower = String(value).toLowerCase();
    
    // Positive keywords boost score
    const positiveKeywords = ['yes', 'true', 'secure', 'encrypted', 'compliant'];
    if (positiveKeywords.some(k => strLower.includes(k))) {
      return 80;
    }

    // Negative keywords reduce score
    const negativeKeywords = ['no', 'false', 'unverified', 'manual'];
    if (negativeKeywords.some(k => strLower.includes(k))) {
      return 40;
    }

    return null; // Unknown question type
  }

  private mapCategoryToProfileKey(questionKey: string): keyof RiskProfile['categories'] | null {
    const mapping: Record<string, keyof RiskProfile['categories']> = {
      'financial': 'financialStability',
      'operational': 'operationalContinuity',
      'security': 'dataSecurity',
      'compliance': 'regulatoryCompliance',
      'supply_chain': 'supplyChainResilience'
    };

    return mapping[questionKey.toLowerCase()] || null;
  }

  linkSBOM(
    vendorId: string,
    sbomData: SBOMEntry,
    metadata?: { sourceUrl: string; version: string }
  ): void {
    const existingLinks = this.sbomLinks.get(vendorId) || [];
    
    // Check for duplicates by hash of package list
    const existingHash = this.calculateSBOMHash(existingLinks);
    if (existingHash === sbomData.hash) return;

    const link: SBOMEntry & { vendorId: string } = {
      ...sbomData,
      vendorId,
      metadata: metadata || {}
    };

    this.sbomLinks.set(vendorId, [...existingLinks, link]);
  }

  private calculateSBOMHash(entries: SBOMEntry[]): string {
    // Simple hash for deduplication - production would use proper crypto
    const sorted = JSON.stringify(entries.sort((a, b) => 
      a.name.localeCompare(b.name) || a.version.localeCompare(b.version)
    ));
    
    let hash = 0;
    for (let i = 0; i < sorted.length; i++) {
      hash = ((hash << 5) - hash + sorted.charCodeAt(i)) | 0;
    }
    return hash.toString(16);
  }

  getVendorById(id: string): Vendor | undefined {
    return this.vendors.get(id);
  }

  getAllVendors(): Vendor[] {
    return Array.from(this.vendors.values());
  }

  searchVendors(query: string, options?: { 
    industryOnly?: boolean;
    minRiskScore?: number;
    maxRiskScore?: number;
  }): Vendor[] {
    const results = this.getAllVendors();
    
    if (!query) return results;
    
    const lowerQuery = query.toLowerCase();
    let filtered = results.filter(v => 
      v.name.toLowerCase().includes(lowerQuery) ||
      v.industry.toLowerCase().includes(lowerQuery) ||
      (v.contactEmail && v.contactEmail.toLowerCase().includes(lowerQuery))
    );

    if (options?.industryOnly) {
      filtered = filtered.filter(v => 
        v.industry.toLowerCase().includes(lowerQuery)
      );
    }

    if (typeof options?.minRiskScore === 'number') {
      filtered = filtered.filter(v => v.riskProfile.overallScore >= options.minRiskScore);
    }

    if (typeof options?.maxRiskScore === 'number') {
      filtered = filtered.filter(v => v.riskProfile.overallScore <= options.maxRiskScore);
    }

    return filtered;
  }

  getResponseHistory(
    vendorId: string,
    questionnaireId?: string
  ): QuestionnaireResponse[] | undefined {
    const allResponses = this.responses.get(vendorId) || [];
    
    if (!questionnaireId) return allResponses;

    return allResponses.filter(r => r.questionnaireId === questionnaireId);
  }

  getSBOMHistory(
    vendorId: string,
    sortByDate?: 'asc' | 'desc'
  ): (SBOMEntry & { vendorId: string })[] | undefined {
    const links = this.sbomLinks.get(vendorId) || [];
    
    if (!sortByDate) return links;

    return [...links].sort((a, b) => {
      const dateA = a.metadata?.sourceUrl ? new Date(a.metadata.sourceUrl).getTime() : 0;
      const dateB = b.metadata?.sourceUrl ? new Date(b.metadata.sourceUrl).getTime() : 0;
      return sortByDate === 'desc' ? dateB - dateA : dateA - dateB;
    });
  }

  getRiskDashboard(): { 
    totalVendors: number;
    highRiskCount: number;
    mediumRiskCount: number;
    lowRiskCount: number;
    responseRate: number;
  } {
    const dashboard = {
      totalVendors: this.vendors.size,
      highRiskCount: 0,
      mediumRiskCount: 0,
      lowRiskCount: 0,
      responseRate: 0
    };

    // Count by risk level
    for (const vendor of this.vendors.values()) {
      const score = vendor.riskProfile.overallScore;
      if (score >= 80) dashboard.highRiskCount++;
      else if (score >= 50) dashboard.mediumRiskCount++;
      else dashboard.lowRiskCount++;
    }

    // Calculate response rate
    const totalResponseSlots = this.vendors.size * 10; // Assume 10 questions per questionnaire
    let answeredQuestions = 0;

    for (const [vendorId, responses] of this.responses.entries()) {
      for (const resp of responses) {
        answeredQuestions += Object.keys(resp.responses).length;
      }
    }

    dashboard.responseRate = totalResponseSlots > 0 
      ? Math.round((answeredQuestions / totalResponseSlots) * 100) 
      : 0;

    return dashboard;
  }

  exportReport(format: 'json' | 'csv'): string {
    const vendorsArray = this.getAllVendors();
    
    if (format === 'json') {
      return JSON.stringify(vendorsArray, null, 2);
    }

    // CSV format
    let csv = 'ID,Name,Industry,Overall Score,Last Assessment\n';
    for (const v of vendorsArray) {
      const dateStr = v.riskProfile.lastAssessmentDate.toISOString().split('T')[0];
      csv += `${v.id},"${v.name}","${v.industry}",${Math.round(v.riskProfile.overallScore)},${dateStr}\n`;
    }

    return csv;
  }

  clear() {
    this.vendors.clear();
    this.responses.clear();
    this.sbomLinks.clear();
  }
}

// Export singleton instance for convenience
export const registry = new VendorRegistryImpl();

// Demo / Test code - can be removed in production
if (typeof require !== 'undefined' && typeof module !== 'undefined') {
  // Node.js environment - run demo when imported directly
  (async () => {
    console.log('=== Vendor Registry Demo ===\n');

    // Sample data
    const sampleVendors = [
      { id: 'v1', name: 'CloudCorp Inc.', industry: 'Technology' },
      { id: 'v2', name: 'FinanceFlow LLC', industry: 'Financial Services' },
      { id: 'v3', name: 'SecureData Systems', industry: 'Cybersecurity' }
    ];

    // Register vendors
    for (const v of sampleVendors) {
      registry.registerVendor(v.id, v.name, v.industry);
      console.log(`Registered: ${v.name}`);
    }

    // Submit questionnaire responses
    const questionnaires = [
      { id: 'q1', name: 'Annual Risk Assessment' },
      { id: 'q2', name: 'Security Questionnaire 2024' }
    ];

    for (const q of questionnaires) {
      console.log(`\n--- Processing ${q.name} ---`);
      
      const responses: Record<string, unknown> = {};
      
      // Simulate responses for each vendor
      for (const vId of sampleVendors.map(v => v.id)) {
        // Financial stability question
        responses['financial_stability'] = Math.random() > 0.3 ? true : false;
        
        // Security controls
        responses['security_controls_adequate'] = Math.random() > 0.2;
        
        // Compliance status
        responses['regulatory_compliance'] = 'compliant';
      }

      for (const vId of sampleVendors.map(v => v.id)) {
        registry.submitResponse(vId, q.id, responses);
      }
    }

    // Link SBOMs
    console.log('\n--- Linking SBOMs ---');
    
    const sbomData = [
      { name: 'openssl', version: '3.0.12', hash: 'abc123' },
      { name: 'libcurl', version: '7.89.0', hash: 'def456' }
    ];

    for (const vId of sampleVendors.map(v => v.id)) {
      registry.linkSBOM(vId, sbomData[0]);
    }

    // Print dashboard
    console.log('\n=== Risk Dashboard ===');
    const dashboard = registry.getRiskDashboard();
    console.log(JSON.stringify(dashboard, null, 2));

    // Search demo
    console.log('\n--- Search Demo ---');
    const searchResults = registry.searchVendors('secure', { minRiskScore: 60 });
    console.log(`Found ${searchResults.length} vendors matching "secure" with score >= 60`);

    // Export CSV
    console.log('\n=== CSV Export Preview ===');
    console.log(registry.exportReport('csv').substring(0, 200) + '...');

    console.log('\nDemo complete.');
  })();
}

export default registry;