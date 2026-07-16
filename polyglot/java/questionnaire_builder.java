package vendorvet.polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Questionnaire Builder for VendorVet - Third-party Risk Assessment Tool.
 * 
 * Constructs structured questionnaires with SBOM cross-referencing capabilities.
 */
public class QuestionnaireBuilder {

    // ==================================================================
    // DOMAIN MODELS (Records for immutability)
    // ==================================================================

    /** Type of answer expected from the vendor */
    public record AnswerType(String name, String description, boolean isMultiSelect) {}

    /** A single question in the questionnaire */
    public record Question(
        String id,
        String title,
        String description,
        AnswerType type,
        List<String> options,      // For multiple choice / yes-no
        int requiredScore,         // 0-100, how important this question is
        Map<String, Object> metadata
    ) {}

    /** A section/category of questions */
    public record Section(
        String id,
        String title,
        List<Question> questions,
        int order
    ) {
        static final String DEFAULT_ID = "default";
        
        public QuestionnaireBuilder toBuilder() {
            return new QuestionnaireBuilder(this.id, this.title, 
                this.questions.stream().map(q -> q.toBuilder()).collect(Collectors.toList()),
                this.order);
        }

        public static Section ofDefault(String title) {
            return new Section(DEFAULT_ID, title, Collections.emptyList(), 0);
        }
    }

    /** A complete questionnaire */
    public record Questionnaire(
        String id,
        String title,
        String description,
        List<Section> sections,
        Instant createdAt,
        Instant updatedAt,
        Map<String, Object> metadata
    ) {
        static final String DEFAULT_ID = "vendor-vet-default";

        public QuestionnaireBuilder toBuilder() {
            return new QuestionnaireBuilder(this.id, this.title, 
                this.description, this.sections.stream().map(s -> s.toBuilder()).collect(Collectors.toList()),
                this.createdAt, this.updatedAt, this.metadata);
        }

        /** Add a question to the default section */
        public void addQuestion(Question q) {
            Section defaultSection = sections.stream()
                .filter(s -> s.id().equals(Section.DEFAULT_ID))
                .findFirst()
                .orElseGet(() -> {
                    Section newSection = Section.ofDefault("Default");
                    this.sections.add(newSection);
                    return newSection;
                });
            defaultSection.questions.add(q);
        }

        /** Add a question to a specific section */
        public void addQuestionToSection(String sectionId, Question q) {
            Section section = sections.stream()
                .filter(s -> s.id().equals(sectionId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No section found: " + sectionId));
            section.questions.add(q);
        }

        /** Reorder questions within a section */
        public void reorderQuestions(String sectionId, List<Integer> order) {
            Section section = sections.stream()
                .filter(s -> s.id().equals(sectionId))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("No section found: " + sectionId));
            
            if (order.size() != section.questions.size()) {
                throw new IllegalArgumentException(
                    "Order list size doesn't match question count");
            }

            List<Question> reordered = order.stream()
                .map(i -> section.questions.get(i))
                .collect(Collectors.toList());
            section.questions.clear();
            section.questions.addAll(reordered);
        }

        /** Remove a question by ID */
        public void removeQuestion(String id) {
            boolean removed = false;
            for (Section s : sections) {
                int i = s.questions.indexOf(q -> q.id().equals(id));
                if (i >= 0) {
                    s.questions.remove(i);
                    removed = true;
                    break;
                }
            }
            if (!removed) {
                throw new IllegalArgumentException("Question not found: " + id);
            }
        }

        /** Get total question count */
        public int getTotalQuestionCount() {
            return sections.stream().mapToInt(s -> s.questions.size()).sum();
        }

        /** Calculate weighted score potential (0-100) */
        public double calculatePotentialScore() {
            if (sections.isEmpty()) return 0.0;
            
            int totalRequired = 0;
            int totalPossible = 0;
            
            for (Section s : sections) {
                for (Question q : s.questions) {
                    totalRequired += q.requiredScore();
                    totalPossible += 100;
                }
            }
            
            return totalPossible > 0 ? (double) totalRequired / totalPossible * 100.0 : 0.0;
        }

        /** Find questions by type */
        public List<Question> findQuestionsByType(AnswerType type) {
            return sections.stream()
                .flatMap(s -> s.questions().stream())
                .filter(q -> q.type().equals(type))
                .collect(Collectors.toList());
        }

        /** Find required questions (requiredScore > 0) */
        public List<Question> findRequiredQuestions() {
            return sections.stream()
                .flatMap(s -> s.questions().stream())
                .filter(q -> q.requiredScore() > 0)
                .collect(Collectors.toList());
        }

        /** Get questions in order, flattened */
        public List<Question> getAllQuestionsInOrder() {
            return sections.stream()
                .sorted(Comparator.comparingInt(Section::order))
                .flatMap(s -> s.questions().stream())
                .collect(Collectors.toList());
        }

        /** Check if questionnaire is valid (all required fields present) */
        public boolean isValid() {
            if (id == null || id.isBlank()) return false;
            if (title == null || title.isBlank()) return false;
            
            for (Section s : sections) {
                if (s.questions.isEmpty()) continue;
                
                for (Question q : s.questions) {
                    if (q.id() == null || q.title() == null || q.title().isBlank()) {
                        return false;
                    }
                    if (q.type() == null) {
                        return false;
                    }
                }
            }
            
            return true;
        }

        /** Clone this questionnaire */
        public Questionnaire clone() {
            return new Questionnaire(
                id, title, description, 
                sections.stream().map(s -> s.toBuilder()).collect(Collectors.toList()),
                createdAt, updatedAt, metadata);
        }
    }

    // ==================================================================
    // BUILDER PATTERN IMPLEMENTATION
    // ==================================================================

    /** Builder for Questionnaire */
    public static class QuestionnaireBuilder {
        private String id;
        private String title;
        private String description;
        private List<Section> sections = new ArrayList<>();
        private Instant createdAt;
        private Instant updatedAt;
        private Map<String, Object> metadata;

        public QuestionnaireBuilder() {
            this.id = Questionnaire.DEFAULT_ID;
            this.createdAt = Instant.now();
            this.updatedAt = Instant.now();
            this.metadata = new HashMap<>();
        }

        public QuestionnaireBuilder(String id) {
            this(id, "Untitled Questionnaire", "", 
                Collections.emptyList(), 
                Instant.now(), Instant.now(), new HashMap<>());
        }

        public QuestionnaireBuilder(String id, String title, 
                                   String description, 
                                   List<Section> sections,
                                   Instant createdAt, 
                                   Instant updatedAt,
                                   Map<String, Object> metadata) {
            this.id = id;
            this.title = title;
            this.description = description;
            this.sections = sections != null ? new ArrayList<>(sections) : new ArrayList<>();
            this.createdAt = createdAt;
            this.updatedAt = updatedAt;
            this.metadata = metadata != null ? new HashMap<>(metadata) : new HashMap<>();
        }

        public QuestionnaireBuilder withId(String id) {
            this.id = id;
            return this;
        }

        public QuestionnaireBuilder withTitle(String title) {
            this.title = title;
            return this;
        }

        public QuestionnaireBuilder withDescription(String description) {
            this.description = description;
            return this;
        }

        public QuestionnaireBuilder addSection(Section section) {
            sections.add(section);
            updatedAt = Instant.now();
            return this;
        }

        public QuestionnaireBuilder removeSection(String id) {
            int i = sections.indexOf(s -> s.id().equals(id));
            if (i >= 0) {
                sections.remove(i);
                updatedAt = Instant.now();
            }
            return this;
        }

        public QuestionnaireBuilder clearSections() {
            sections.clear();
            return this;
        }

        public Questionnaire build() {
            if (sections.isEmpty()) {
                Section defaultSection = Section.ofDefault("Default");
                this.sections.add(defaultSection);
            }
            
            // Sort sections by order
            sections.sort(Comparator.comparingInt(Section::order));
            
            return new Questionnaire(id, title, description, 
                                   sections, createdAt, updatedAt, metadata);
        }

        public QuestionnaireBuilder from(Questionnaire q) {
            this.id = q.id();
            this.title = q.title();
            this.description = q.description();
            this.sections = q.sections().stream()
                .map(s -> s.toBuilder()).collect(Collectors.toList());
            this.createdAt = q.createdAt();
            this.updatedAt = q.updatedAt();
            this.metadata = new HashMap<>(q.metadata());
            return this;
        }

        public static QuestionnaireBuilder ofDefault() {
            return new QuestionnaireBuilder(Questionnaire.DEFAULT_ID);
        }
    }

    // ==================================================================
    // SBOM CROSS-REFERENCE CAPABILITY
    // ==================================================================

    /** Represents an SBOM entry/component reference */
    public record SboMReference(
        String componentId,
        String componentName,
        String version,
        String sbomSource,      // e.g., "spdx", "cyclonedx"
        List<String> categories  // e.g., ["security", "compliance"]
    ) {}

    /** Builder for SBOM references */
    public static class SboMReferenceBuilder {
        private SboMReference reference;

        public SboMReferenceBuilder() {
            this.reference = new SboMReference(null, null, null, null, new ArrayList<>());
        }

        public SboMReferenceBuilder withComponentId(String id) {
            if (id != null && !id.isBlank()) {
                reference.componentId = id;
            }
            return this;
        }

        public SboMReferenceBuilder withName(String name) {
            if (name != null && !name.isBlank()) {
                reference.componentName = name;
            }
            return this;
        }

        public SboMReferenceBuilder withVersion(String version) {
            if (version != null) {
                reference.version = version;
            }
            return this;
        }

        public SboMReferenceBuilder withSource(String source) {
            if (source != null && !source.isBlank()) {
                reference.sbomSource = source;
            }
            return this;
        }

        public SboMReferenceBuilder addCategory(String category) {
            if (category != null && !category.isBlank()) {
                reference.categories.add(category);
            }
            return this;
        }

        public SboMReference build() {
            // Auto-generate componentId if not provided
            if (reference.componentId == null || reference.componentId.isBlank()) {
                String safeName = reference.componentName != null ? 
                    reference.componentName.replace(" ", "_").toLowerCase() : "unknown";
                reference.componentId = safeName + "_" + System.currentTimeMillis();
            }

            // Auto-generate source if not provided
            if (reference.sbomSource == null || reference.sbomSource.isBlank()) {
                reference.sbomSource = "vendorvet-default";
            }

            return reference;
        }

        public static SboMReferenceBuilder ofDefault() {
            return new SboMReferenceBuilder();
        }
    }

    /** Extension to add SBOM references to questions */
    public class QuestionnaireWithSBOM extends Questionnaire {
        
        private final Map<String, List<SboMReference>> questionSbomRefs = new HashMap<>();

        public QuestionnaireWithSBOM(Questionnaire q) {
            super(q);
            if (q.sections() != null) {
                for (Section s : q.sections()) {
                    if (s.questions() != null) {
                        for (Question q2 : s.questions()) {
                            questionSbomRefs.putIfAbsent(q2.id(), new ArrayList<>());
                        }
                    }
                }
            }
        }

        public QuestionnaireWithSBOM addSboMReference(Question q, SboMReference ref) {
            if (q != null && !questionSbomRefs.containsKey(q.id())) {
                questionSbomRefs.putIfAbsent(q.id(), new ArrayList<>());
            }
            
            List<SboMReference> refs = questionSbomRefs.getOrDefault(q.id(), new ArrayList<>());
            refs.add(ref);
            return this;
        }

        public QuestionnaireWithSBOM addSboMReferences(Question q, List<SboMReference> refs) {
            if (q != null && !questionSbomRefs.containsKey(q.id())) {
                questionSbomRefs.putIfAbsent(q.id(), new ArrayList<>());
            }
            
            if (refs != null) {
                for (SboMReference r : refs) {
                    addSboMReference(q, r);
                }
            }
            return this;
        }

        public List<SboMReference> getSboMReferencesForQuestion(Question q) {
            return questionSbomRefs.getOrDefault(q.id(), new ArrayList<>());
        }

        public boolean hasSboMReferences() {
            return !questionSbomRefs.isEmpty();
        }

        public int getTotalSboMReferences() {
            return questionSbomRefs.values().stream()
                .mapToInt(List::size)
                .sum();
        }

        /** Find questions that have SBOM references */
        public List<Question> findQuestionsWithSBOM() {
            return questionSbomRefs.entrySet().stream()
                .filter(e -> !e.getValue().isEmpty())
                .map(Map.Entry::getKey)
                .map(id -> sections.stream()
                    .flatMap(s -> s.questions().stream())
                    .filter(q -> q.id().equals(id))
                    .findFirst()
                    .orElse(null))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        }

        /** Get all unique SBOM sources referenced */
        public Set<String> getSboMSources() {
            return questionSbomRefs.values().stream()
                .flatMap(List::stream)
                .map(SboMReference::sbomSource)
                .collect(Collectors.toSet());
        }

        /** Get all unique categories referenced */
        public Set<String> getSboMCategories() {
            return questionSbomRefs.values().stream()
                .flatMap(List::stream)
                .map(SboMReference::categories)
                .flatMap(List::stream)
                .collect(Collectors.toSet());
        }

        /** Check if a specific component is referenced */
        public boolean hasComponentReference(String componentId) {
            return questionSbomRefs.values().stream()
                .anyMatch(refs -> refs.stream()
                    .anyMatch(r -> r.componentId().equals(componentId)));
        }

        /** Find questions referencing a specific component */
        public List<Question> findQuestionsForComponent(String componentId) {
            return questionSbomRefs.entrySet().stream()
                .filter(e -> e.getValue().stream()
                    .anyMatch(r -> r.componentId().equals(componentId)))
                .map(Map.Entry::getKey)
                .map(id -> sections.stream()
                    .flatMap(s -> s.questions().stream())
                    .filter(q -> q.id().equals(id))
                    .findFirst()
                    .orElse(null))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
        }

        /** Remove all SBOM references for a question */
        public QuestionnaireWithSBOM clearSboMReferences(Question q) {
            if (q != null && questionSbomRefs.containsKey(q.id