using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace vendorvet.polyglot.cs.questionnaire_builder
{
    /// <summary>
    /// Question types supported by the questionnaire builder.
    /// </summary>
    public enum QuestionType
    {
        Text,
        TextArea,
        Email,
        Url,
        YesNo,
        MultipleChoice,
        FileUpload,
        CpeMatch // SBOM-specific: vendor-provided CPE list for matching
    }

    /// <summary>
    /// Validation rules for questionnaire answers.
    /// </summary>
    public class AnswerRule
    {
        public string? MinLength { get; set; }
        public string? MaxLength { get; set; }
        public string? Pattern { get; set; } // Regex pattern
        public bool Required { get; set; } = true;
        public string? ErrorMessage { get; set; }

        public static AnswerRule Required(string message) => new() { Required = true, ErrorMessage = message };
        public static AnswerRule MinLength(int length, string? message = null) 
            => new() { MinLength = length.ToString(), ErrorMessage = message ?? $"Must be at least {length} characters." };
        public static AnswerRule MaxLength(int length, string? message = null) 
            => new() { MaxLength = length.ToString(), ErrorMessage = message ?? $"Must not exceed {length} characters." };
        public static AnswerRule Email(string? message = null) 
            => new() { Pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$", ErrorMessage = message ?? "Must be a valid email address." };
        public static AnswerRule Url(string? message = null) 
            => new() { Pattern = @"^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w./?-]*)*?$", ErrorMessage = message ?? "Must be a valid URL." };
    }

    /// <summary>
    /// A single question in the questionnaire.
    /// </summary>
    public class Question : IEquatable<Question>
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Title { get; set; } = "";
        public string? Description { get; set; }
        public QuestionType Type { get; set; }
        public AnswerRule Rule { get; set; }

        /// <summary>
        /// For CpeMatch type: the vendor's declared CPEs. Used for SBOM cross-ref.
        /// </summary>
        public List<string>? VendorCpes { get; set; }

        public bool Equals(Question? other) => 
            other != null && Id == other.Id && Title == other.Title && Type == other.Type;

        public override int GetHashCode() => HashCode.Combine(Id, Title, Type);

        public static Question Create(string id, string title, QuestionType type, AnswerRule rule = null)
            => new() { Id = id, Title = title, Type = type, Rule = rule ?? new AnswerRule(); }

        public static Question CreateText(string id, string title, int maxLength = 1024) 
            => Create(id, title, QuestionType.Text, AnswerRule.MaxLength(maxLength));
        
        public static Question CreateYesNo(string id, string title) 
            => Create(id, title, QuestionType.YesNo);

        public static Question CreateCpeMatch(string id, string title, List<string> vendorCpes = null) 
            => Create(id, title, QuestionType.CpeMatch, AnswerRule.Required("Provide CPE list if applicable"))
                { VendorCpes = vendorCpes };
    }

    /// <summary>
    /// A section of the questionnaire.
    /// </summary>
    public class Section : IEquatable<Section>
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Title { get; set; } = "";
        public string? Description { get; set; }
        public List<Question> Questions { get; set; } = new();

        public bool Equals(Section? other) => 
            other != null && Id == other.Id && Title == other.Title;

        public override int GetHashCode() => HashCode.Combine(Id, Title);
    }

    /// <summary>
    /// A category (group of sections).
    /// </summary>
    public class Category : IEquatable<Category>
    {
        public string Id { get; set; } = Guid.NewGuid().ToString("N");
        public string Title { get; set; } = "";
        public List<Section> Sections { get; set; } = new();

        public bool Equals(Category? other) => 
            other != null && Id == other.Id && Title == other.Title;

        public override int GetHashCode() => HashCode.Combine(Id, Title);
    }

    /// <summary>
    /// The complete questionnaire document.
    /// </summary>
    public class Questionnaire : IEquatable<Questionnaire>
    {
        public string Version { get; set; } = "1.0";
        public string? VendorName { get; set; }
        public List<Category> Categories { get; set; } = new();

        /// <summary>
        /// SBOM metadata for cross-reference purposes.
        /// </summary>
        public SboMetadata? SbomMetadata { get; set; }

        public bool Equals(Questionnaire? other) => 
            other != null && Version == other.Version && VendorName == other.VendorName;

        public override int GetHashCode() => HashCode.Combine(Version, VendorName);

        /// <summary>
        /// Validates all questions and returns a list of errors.
        /// </summary>
        public List<string> Validate()
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(VendorName))
                errors.Add("Vendor name is required.");

            foreach (var cat in Categories)
            {
                foreach (var sec in cat.Sections)
                {
                    foreach (var q in sec.Questions)
                    {
                        var rule = q.Rule;
                        
                        if (rule.Required && string.IsNullOrWhiteSpace(sec.Title))
                            errors.Add($"Question '{q.Id}' is required but section title is missing.");

                        // Validate answer length rules
                        if (!string.IsNullOrEmpty(rule.MinLength) || !string.IsNullOrEmpty(rule.MaxLength))
                        {
                            var text = sec.Questions.Count > 0 ? " (check question content)" : "";
                            errors.Add($"Question '{q.Id}' has length constraints{text}.");
                        }

                        // Validate CPE list for CpeMatch type
                        if (q.Type == QuestionType.CpeMatch && q.VendorCpes != null)
                        {
                            var cpeCount = q.VendorCpes.Count;
                            if (cpeCount > 0)
                                errors.Add($"Question '{q.Id}' has {cpeCount} CPE entries for SBOM cross-ref.");
                        }
                    }
                }
            }

            return errors;
        }

        /// <summary>
        /// Flattens the questionnaire into a linear list of questions.
        /// </summary>
        public List<Question> Flatten()
        {
            var flat = new List<Question>();
            
            foreach (var cat in Categories)
            {
                foreach (var sec in cat.Sections)
                {
                    flat.AddRange(sec.Questions);
                }
            }

            return flat;
        }

        /// <summary>
        /// Adds a question to the last section of the last category.
        /// </summary>
        public void AddQuestion(Question q)
        {
            if (Categories.Count == 0 || Categories.Last().Sections.Count == 0)
            {
                Categories.Add(new Category());
                Categories.Last().Sections.Add(new Section());
            }

            Categories.Last().Sections.Last().Questions.Add(q);
        }
    }

    /// <summary>
    /// Metadata for SBOM cross-reference.
    /// </summary>
    public class SboMetadata
    {
        [JsonPropertyName("sbom_format")]
        public string? SbomFormat { get; set; } // SPDX, CycloneDX, etc.

        [JsonPropertyName("sbom_version")]
        public string? SbomVersion { get; set; }

        [JsonPropertyName("cpe_source_url")]
        public string? CpeSourceUrl { get; set; }

        [JsonPropertyName("nist_nvd_mapping")]
        public bool NistNvdMapping { get; set; } = true;
    }

    /// <summary>
    /// Fluent builder for creating questionnaires.
    /// </summary>
    public static class QuestionnaireBuilder
    {
        private readonly List<Category> _categories = new();
        private string? _vendorName;
        private string _version = "1.0";

        public static QuestionnaireBuilder Create() => new();

        public QuestionnaireBuilder WithVendor(string vendor) 
            => (_vendorName, _categories.Clear(), this).WithState(vendor);

        public QuestionnaireBuilder WithVersion(string ver) 
            => (_version, _categories, this).WithState(ver);

        private (string? Vendor, List<Category> Cats, QuestionnaireBuilder Builder) WithState(
            string vendor, List<Category> cats, QuestionnaireBuilder builder)
        {
            if (!string.IsNullOrEmpty(vendor)) _vendorName = vendor;
            if (!string.IsNullOrWhiteSpace(ver)) _version = ver;

            return (_vendorName, cats, this);
        }

        public QuestionnaireBuilder AddCategory(string title) 
            => (_categories.Add(new Category() { Title = title }), _categories.Count > 1 ? null : this).WithState(null, _categories, this);

        public QuestionnaireBuilder AddSection(string title) 
            => (_categories.Last().Sections.Add(new Section() { Title = title }), _categories.Count == 0 ? null : this).WithState(null, _categories, this);

        public QuestionnaireBuilder AddQuestion(Question q) 
            => (_categories.Last().Sections.Last().Questions.Add(q), _categories.Count == 0 || _categories.Last().Sections.Count == 0 ? null : this).WithState(null, _categories, this);

        public QuestionnaireBuilder WithSbomMetadata(SboMetadata meta)
        {
            if (_categories.Count > 0 && _categories.Last().Sections.Count > 0)
                _categories.Last().Sections.Last().Questions.Add(
                    Question.Create("sbom_meta", "SBOM Metadata", QuestionType.Text, AnswerRule.Required()))
                { VendorCpes = meta != null ? new List<string> 
                    { meta.SbomFormat ?? "", meta.NistNvdMapping.ToString() } : null };

            return this;
        }

        public Questionnaire Build() => new() 
        { 
            Version = _version, 
            VendorName = _vendorName, 
            Categories = _categories 
        };
    }

    /// <summary>
    /// Serializer for questionnaire JSON output.
    /// </summary>
    public static class JsonSerializer
    {
        private const string Indent = "  ";

        public static string ToJson(Questionnaire q, int indentLevel = 0)
        {
            var sb = new StringBuilder();
            var level = indentLevel;
            var prefix = new string(Indent, level);

            sb.AppendLine($"{prefix}{{");
            
            if (!string.IsNullOrEmpty(q.Version))
                sb.AppendLine($"{prefix}{Indent}" + $"\"version\": \"{q.Version}\",");
            
            if (!string.IsNullOrEmpty(q.VendorName))
                sb.AppendLine($"{prefix}{Indent}" + $"\"vendor_name\": \"{q.VendorName}\",");

            if (q.SbomMetadata != null)
            {
                var meta = q.SbomMetadata;
                sb.AppendLine($"{prefix}{Indent}" + $"\"sbom_metadata\": {{");
                sb.AppendLine($"{prefix}{Indent}{Indent}\"sbom_format\": \"{meta?.SbomFormat}\",");
                sb.AppendLine($"{prefix}{Indent}{Indent}\"sbom_version\": \"{meta?.SbomVersion}\",");
                if (!string.IsNullOrEmpty(meta.CpeSourceUrl))
                    sb.AppendLine($"{prefix}{Indent}{Indent}\"cpe_source_url\": \"{meta.CpeSourceUrl}\",");
                sb.AppendLine($"{prefix}{Indent}{Indent}\"nist_nvd_mapping\": {meta.NistNvdMapping},");
                sb.AppendLine($"{prefix}{Indent}}}", ");
            }

            if (q.Categories.Count > 0)
            {
                sb.AppendLine($"{prefix}{Indent}" + "\"categories\":[");
                
                for (int i = 0; i < q.Categories.Count; i++)
                {
                    var cat = q.Categories[i];
                    sb.AppendLine($"{prefix}{Indent}{Indent}{{");
                    
                    if (!string.IsNullOrEmpty(cat.Title))
                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}\"title\": \"{cat.Title}\",");

                    if (cat.Sections.Count > 0)
                    {
                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}" + "\"sections\":[");
                        
                        for (int j = 0; j < cat.Sections.Count; j++)
                        {
                            var sec = cat.Sections[j];
                            sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{{");
                            
                            if (!string.IsNullOrEmpty(sec.Title))
                                sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}\"title\": \"{sec.Title}\",");

                            if (sec.Questions.Count > 0)
                            {
                                sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}" + "\"questions\":[");
                                
                                for (int k = 0; k < sec.Questions.Count; k++)
                                {
                                    var qst = sec.Questions[k];
                                    sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{{");
                                    
                                    if (!string.IsNullOrEmpty(qst.Id))
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}\"id\": \"{qst.Id}\",");
                                    
                                    if (!string.IsNullOrEmpty(qst.Title))
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"title\": \"{qst.Title}\",");

                                    if (!string.IsNullOrEmpty(qst.Description))
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"description\": \"{qst.Description}\",");

                                    if (qst.Type != QuestionType.Text)
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"type\": \"{qst.Type}\",");

                                    if (qst.Rule.Required)
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"required\": true,");

                                    if (!string.IsNullOrEmpty(qst.Rule.MinLength))
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"min_length\": {qst.Rule.MinLength},");

                                    if (!string.IsNullOrEmpty(qst.Rule.MaxLength))
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"max_length\": {qst.Rule.MaxLength},");

                                    if (!string.IsNullOrEmpty(qst.Rule.Pattern))
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"pattern\": \"{qst.Rule.Pattern}\",");

                                    if (qst.VendorCpes != null && qst.VendorCpes.Count > 0)
                                    {
                                        var cpeJson = JsonSerializer.Serialize(qst.VendorCpes, new JsonSerializerOptions 
                                        { 
                                            WriteIndented = true, 
                                            PropertyNamingPolicy = JsonNamingPolicy.CamelCase 
                                        });
                                        sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}" + $"\"vendor_cpes\": {cpeJson},");
                                    }

                                    if (k < sec.Questions.Count - 1)
                                        sb.Remove(sb.Length - 2, 2); // Remove trailing comma
                                    
                                    sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}{Indent}}}", ");
                                }
                                
                                sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}{Indent}{Indent}]", ");
                            }

                            if (j < cat.Sections.Count - 1)
                                sb.Remove(sb.Length - 2, 2); // Remove trailing comma
                            
                            sb.AppendLine($"{prefix}{Indent}{Indent}{Indent}}}", ");
                        }
                        
                        sb.AppendLine($"{prefix}{Indent}{Indent}]", ");
                    }

                    if (i < q.Categories.Count - 1)
                        sb.Remove(sb.Length - 2, 2); // Remove trailing comma
                    
                    sb.AppendLine($"{prefix}{Indent}}}", ");
                }
                
                sb.AppendLine($"{prefix}]", ");
            }

            if (!string.IsNullOrEmpty(q.Version))
                sb.Remove(sb.Length - 2, 2); // Remove trailing comma
            
            sb.AppendLine($"{prefix}}}");

            return sb.ToString();
        }

        public static Questionnaire FromJson(string json) 
            => JsonSerializer.Deserialize<Questionnaire>(json);
    }

    /// <summary>
    /// Demo/entry point for testing the questionnaire builder.
    /// </summary>
    public class Program
    {
        public static void Main()
        {
            Console.WriteLine("=== VendorVet Questionnaire Builder Demo ===\n");

            // Build a sample questionnaire
            var q = QuestionnaireBuilder.Create()
                .WithVendor("Acme Corp")
                .WithVersion("2.1")
                .AddCategory("General Information