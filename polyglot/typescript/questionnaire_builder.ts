import { Question, Section, Questionnaire, VendorProfile, SBOMEntry, ValidationResult } from './models';

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const DEFAULT_QUESTIONNAIRE_ID = 'default-vendor-risk-q';
const MAX_QUESTION_LENGTH = 500;
const MIN_RESPONSE_OPTIONS = 2;
const REQUIRED_SECTIONS = ['General', 'Technical'];

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function generateId(prefix: string, length: number = 8): string {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let id = prefix;
    while (id.length < length) {
        id += chars[Math.floor(Math.random() * chars.length)];
    }
    return id.slice(0, length);
}

function validateQuestion(question: Question): ValidationResult<Question> | null {
    const errors: string[] = [];

    if (!question.id || question.id.length > 128) {
        errors.push('Question ID must be between 1 and 128 characters');
    }

    if (!question.text || question.text.length > MAX_QUESTION_LENGTH) {
        errors.push(`Question text must not exceed ${MAX_QUESTION_LENGTH} characters`);
    }

    if (question.type === 'multiple_choice' && !question.options) {
        errors.push('Multiple choice questions require options');
    } else if (question.type === 'multiple_choice' && question.options?.length < MIN_RESPONSE_OPTIONS) {
        errors.push(`Multiple choice questions need at least ${MIN_RESPONSE_OPTIONS} options`);
    }

    if (!errors.length) return null;
    
    return { valid: false, errors };
}

function validateSection(section: Section): ValidationResult<Section> | null {
    const errors: string[] = [];

    if (!section.id || section.id.length > 128) {
        errors.push('Section ID must be between 1 and 128 characters');
    }

    if (!section.name || !/^[a-zA-Z][a-zA-Z0-9 ]+$/.test(section.name)) {
        errors.push('Section name must start with a letter and contain only letters, numbers, and spaces');
    }

    const subQuestions = section.questions?.length ?? 0;
    if (subQuestions > 100) {
        errors.push(`A section can have at most 100 questions (found ${subQuestions})`);
    }

    return { valid: !errors.length, errors };
}

function validateQuestionnaire(questionnaire: Questionnaire): ValidationResult<Questionnaire> | null {
    const errors: string[] = [];

    if (!questionnaire.id || questionnaire.id.length > 128) {
        errors.push('Questionnaire ID must be between 1 and 128 characters');
    }

    if (!questionnaire.name || !/^[a-zA-Z][a-zA-Z0-9 ]+$/.test(questionnaire.name)) {
        errors.push('Questionnaire name must start with a letter and contain only letters, numbers, and spaces');
    }

    const totalQuestions = questionnaire.sections?.reduce((sum, s) => sum + (s.questions?.length ?? 0), 0) || 0;
    if (totalQuestions > 500) {
        errors.push(`Questionnaire can have at most 500 questions (found ${totalQuestions})`);
    }

    const missingSections = REQUIRED_SECTIONS.filter(req => 
        !questionnaire.sections?.some(s => s.id === req)
    );
    if (missingSections.length > 0) {
        errors.push(`Missing required sections: ${JSON.stringify(missingSections)}`);
    }

    return { valid: !errors.length, errors };
}

// ============================================================================
// SBOM CROSS-REFERENCE ENGINE
// ============================================================================

interface SBOMDatabase {
    [vendorId: string]: SBOMEntry[];
}

function createEmptySBOMDatabase(): SBOMDatabase {
    return {};
}

function getVendorSBOMs(database: SBOMDatabase, vendorId: string): SBOMEntry[] {
    const entries = database[vendorId] || [];
    // Sort by severity for risk assessment
    return entries.sort((a, b) => (b.severity || 'low').localeCompare(a.severity || 'low'));
}

function calculateSBOMRiskScore(sbmEntries: SBOMEntry[]): number {
    const weights = {
        critical: 10,
        high: 5,
        medium: 2,
        low: 1,
        none: 0.5
    };

    let score = 0;
    for (const entry of sbmEntries) {
        const weight = weights[entry.severity || 'low'];
        // Critical and high severity entries count twice as they often indicate supply chain issues
        if (['critical', 'high'].includes(entry.severity)) {
            score += weight * 2;
        } else {
            score += weight;
        }
    }

    return Math.round(score);
}

function assessSBOMRisk(vendorId: string, database: SBOMDatabase): ValidationResult<{
    vendorId: string;
    riskScore: number;
    sbomEntries: SBOMEntry[];
    recommendations: string[];
}> | null {
    const entries = getVendorSBOMs(database, vendorId);

    if (!entries.length) {
        return {
            valid: true,
            data: {
                vendorId,
                riskScore: 0,
                sbomEntries: [],
                recommendations: ['No SBOM data found for this vendor'],
            },
        };
    }

    const riskScore = calculateSBOMRiskScore(entries);

    // Generate recommendations based on findings
    const recommendations: string[] = [];
    
    if (riskScore >= 20) {
        recommendations.push('Review critical and high severity dependencies');
    }
    if (riskScore >= 15) {
        recommendations.push('Consider alternative vendors or version upgrades');
    }
    if (entries.some(e => e.severity === 'critical')) {
        recommendations.push('Immediate remediation required for critical vulnerabilities');
    }

    return {
        valid: true,
        data: {
            vendorId,
            riskScore,
            sbomEntries,
            recommendations,
        },
    };
}

// ============================================================================
// QUESTIONNAIRE BUILDER CLASS
// ============================================================================

export class QuestionnaireBuilder {
    private id: string;
    private name: string;
    private description: string;
    private sections: Section[] = [];
    private sbomDatabase: SBOMDatabase = createEmptySBOMDatabase();

    constructor(options?: { id?: string; name?: string; description?: string }) {
        this.id = options?.id || generateId('qna-', 12);
        this.name = options?.name || 'Untitled Questionnaire';
        this.description = options?.description || '';
    }

    // Add a new section to the questionnaire
    addSection(section: Partial<Section>): Section {
        const id = section.id || generateId('sec-', 10);
        
        const baseSection: Section = {
            id,
            name: section.name || `Section ${this.sections.length + 1}`,
            questions: [],
            metadata: {},
            ...section,
        };

        // Validate before adding
        const validation = validateSection(baseSection);
        if (!validation.valid) {
            console.warn(`Warning: Section "${id}" has validation issues:`, validation.errors);
        }

        this.sections.push(baseSection);
        return baseSection;
    }

    // Add a question to the last section (or create new section if none exists)
    addQuestion(question: Partial<Question>): Question {
        const targetSection = this.sections[this.sections.length - 1];
        
        let id = question.id || generateId('qst-', 10);

        // Auto-generate a descriptive name for the question
        const autoName = question.text?.slice(0, 50) || `Question ${targetSection.questions.length + 1}`;

        const baseQuestion: Question = {
            id,
            text: question.text || '',
            type: question.type || 'text',
            required: question.required ?? true,
            options: question.options || [],
            metadata: {},
            ...question,
        };

        // Validate before adding
        const validation = validateQuestion(baseQuestion);
        if (!validation.valid) {
            console.warn(`Warning: Question "${id}" has validation issues:`, validation.errors);
        }

        targetSection.questions.push(baseQuestion);
        return baseQuestion;
    }

    // Register SBOM data for a vendor
    registerSBOM(vendorId: string, entries: SBOMEntry[]): void {
        if (!this.sbomDatabase[vendorId]) {
            this.sbomDatabase[vendorId] = [];
        }
        
        const existingEntries = this.sbomDatabase[vendorId];
        
        // Merge and deduplicate by package name + version
        for (const entry of entries) {
            const key = `${entry.packageName}-${entry.version}`;
            if (!existingEntries.some(e => e.packageName === entry.packageName && e.version === entry.version)) {
                existingEntries.push(entry);
            }
        }

        // Sort by severity after insertion
        this.sbomDatabase[vendorId].sort((a, b) => 
            (b.severity || 'low').localeCompare(a.severity || 'low')
        );
    }

    // Get SBOM risk assessment for a vendor
    getVendorRisk(vendorId: string): ValidationResult<{
        questionnaireId: string;
        vendorId: string;
        riskScore: number;
        sbomEntries: SBOMEntry[];
        recommendations: string[];
    }> | null {
        return assessSBOMRisk(vendorId, this.sbomDatabase);
    }

    // Validate entire questionnaire
    validate(): ValidationResult<Questionnaire> | null {
        const validation = validateQuestionnaire(this.toQuestionnaire());
        
        if (!validation.valid) {
            console.warn('Questionnaire validation failed:', validation.errors.join(', '));
        }

        return validation;
    }

    // Convert builder to Questionnaire object
    toQuestionnaire(): Questionnaire {
        return {
            id: this.id,
            name: this.name,
            description: this.description,
            version: 1,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            sections: [...this.sections],
            sbomDatabase: JSON.parse(JSON.stringify(this.sbomDatabase)),
        };
    }

    // Export questionnaire to JSON string
    export(): string {
        return JSON.stringify(this.toQuestionnaire(), null, 2);
    }

    // Import questionnaire from JSON string
    static import(jsonString: string): QuestionnaireBuilder {
        const data = JSON.parse(jsonString) as Questionnaire;
        
        const builder = new QuestionnaireBuilder({
            id: data.id,
            name: data.name,
            description: data.description || '',
        });

        // Restore sections
        for (const section of data.sections) {
            builder.addSection(section);
        }

        // Restore SBOM database
        if (data.sbomDatabase) {
            builder.sbomDatabase = JSON.parse(JSON.stringify(data.sbomDatabase));
        }

        return builder;
    }

    // Clone the questionnaire builder
    clone(): QuestionnaireBuilder {
        const cloned = new QuestionnaireBuilder({
            id: this.id,
            name: this.name,
            description: this.description,
        });

        // Deep copy sections
        for (const section of this.sections) {
            cloned.addSection({ ...section, questions: [...section.questions] });
        }

        // Deep copy SBOM database
        cloned.sbomDatabase = JSON.parse(JSON.stringify(this.sbomDatabase));

        return cloned;
    }

    // Get total question count
    getQuestionCount(): number {
        return this.sections.reduce((sum, s) => sum + (s.questions?.length ?? 0), 0);
    }

    // Get section by ID
    getSectionById(id: string): Section | undefined {
        return this.sections.find(s => s.id === id);
    }

    // Remove a section by ID
    removeSection(id: string): boolean {
        const index = this.sections.findIndex(s => s.id === id);
        if (index >= 0) {
            this.sections.splice(index, 1);
            return true;
        }
        return false;
    }

    // Clear all sections and start fresh
    clear(): void {
        this.sections = [];
        this.sbomDatabase = createEmptySBOMDatabase();
    }

    // Get summary statistics
    getSummary(): Record<string, any> {
        const totalQuestions = this.getQuestionCount();
        const sectionNames = this.sections.map(s => s.name).join(', ');

        return {
            id: this.id,
            name: this.name,
            description: this.description,
            version: 1,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            totalSections: this.sections.length,
            totalQuestions: totalQuestions,
            sectionNames: sectionNames,
            sbomVendorsRegistered: Object.keys(this.sbomDatabase).length,
        };
    }

    // Append another questionnaire's sections
    append(other: QuestionnaireBuilder): void {
        for (const section of other.sections) {
            this.addSection(section);
        }
    }

    // Merge SBOM databases
    mergeSBOM(other: QuestionnaireBuilder): void {
        for (const [vendorId, entries] of Object.entries(other.sbomDatabase)) {
            if (!this.sbomDatabase[vendorId]) {
                this.sbomDatabase[vendorId] = [];
            }
            
            const existingEntries = this.sbomDatabase[vendorId];
            
            // Merge and deduplicate
            for (const entry of entries) {
                const key = `${entry.packageName}-${entry.version}`;
                if (!existingEntries.some(e => e.packageName === entry.packageName && e.version === entry.version)) {
                    existingEntries.push(entry);
                }
            }

            // Re-sort after merge
            this.sbomDatabase[vendorId].sort((a, b) => 
                (b.severity || 'low').localeCompare(a.severity || 'low')
            );
        }
    }
}

// ============================================================================
// PRE-BUILT TEMPLATES
// ============================================================================

export const STANDARD_RISK_QUESTIONNAIRE: QuestionnaireBuilder = new QuestionnaireBuilder({
    id: 'standard-risk-q',
    name: 'Standard Vendor Risk Assessment',
    description: 'Comprehensive risk questionnaire for third-party vendors with SBOM integration',
});

function configureStandardQuestionnaire(builder: QuestionnaireBuilder): void {
    // Section 1: General Information
    const generalSection = builder.addSection({
        id: 'general-info',
        name: 'General Information',
        metadata: { order: 1 },
    });

    builder.addQuestion({
        text: 'Vendor Legal Name:',
        type: 'text',
        required: true,
        metadata: { field: 'legal_name' },
    });

    builder.addQuestion({
        text: 'Primary Contact Email:',
        type: 'email',
        required: true,
        metadata: { field: 'contact_email' },
    });

    builder.addQuestion({
        text: 'Years in Business:',
        type: 'multiple_choice',
        options: [
            { value: '0-1', label: 'Less than 1 year' },
            { value: '1-3', label: '1-3 years' },
            { value: '3-5', label: '3-5 years' },
            { value: '5-10', label: '5-10 years' },
            { value: '10+', label: 'More than 10 years' },
        ],
        required: true,
        metadata: { field: 'years_in_business' },
    });

    // Section 2: Technical Infrastructure
    const technicalSection = builder.addSection({
        id: 'technical-infra',
        name: 'Technical Infrastructure',
        metadata: { order: 2 },
    });

    builder.addQuestion({
        text: 'Primary Technology Stack:',
        type: 'text',
        required: true,
        metadata: { field: 'tech_stack' },
    });

    builder.addQuestion({
        text: 'Cloud Provider(s) Used:',
        type: 'multiple_choice',
        options: [
            { value: 'aws', label: 'AWS' },
            { value: 'azure', label: 'Microsoft Azure' },
            { value: 'gcp', label: 'Google Cloud Platform' },
            { value: 'onprem', label: 'On-Premises' },
            { value: 'hybrid', label: 'Hybrid' },
        ],
        required: true,
        metadata: { field: 'cloud_providers' },
    });

    builder.addQuestion({
        text: 'API Versioning Strategy:',
        type: 'multiple_choice',
        options: [
            { value: 'url', label: 'URL Path (e.g., /v1/)' },
            { value: 'header', label: 'HTTP Header' },
            { value: 'query', label: 'Query Parameter' },
            { value: '