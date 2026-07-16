#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <filesystem>
#include <algorithm>
#include <iomanip>
#include <ctime>
#include <chrono>

namespace fs = std::filesystem;

// ============================================================================
// DOMAIN TYPES
// ============================================================================

enum class QuestionType {
    TEXT,
    MULTIPLE_CHOICE,
    TRUE_FALSE,
    RATING_SCALE,
    FILE_UPLOAD,
    SBOM_MATCH
};

struct VendorInfo {
    std::string name;
    std::string domain;
    std::string contact_email;
    std::string ciso_email;
    std::string address;
    std::string phone;
    std::string website;
    
    bool operator==(const VendorInfo& other) const {
        return name == other.name && 
               domain == other.domain &&
               contact_email == other.contact_email;
    }
};

struct SBOMEntry {
    std::string package_name;
    std::string version;
    std::string license;
    std::string maintainer;
    std::optional<std::string> source_url;
    
    bool operator==(const SBOMEntry& other) const {
        return package_name == other.package_name && 
               version == other.version;
    }
};

struct Question {
    int id;
    std::string section_id;
    std::string question_text;
    QuestionType type = QuestionType::TEXT;
    
    // For multiple choice/rating
    std::vector<std::string> options;
    int required_length = 0;
    bool is_required = true;
    std::optional<int> default_value;
    
    // SBOM-specific
    std::optional<SBOMEntry> sbom_reference;
    std::vector<std::string> affected_packages;
};

struct Questionnaire {
    int id;
    std::string title;
    std::string description;
    std::string version = "1.0";
    std::chrono::system_clock::time_point created_at{};
    
    // Sections and questions
    std::vector<std::string> sections;
    std::map<int, Question> questions;
    
    // Vendor metadata
    std::optional<VendorInfo> vendor;
    
    // SBOM context
    std::vector<SBOMEntry> sbom_entries;
};

// ============================================================================
// UTILITIES
// ============================================================================

class JsonHelper {
public:
    static std::string escape(const std::string& s) {
        auto result = s;
        for (auto c : s) {
            switch(c) {
                case '"':  result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
            }
        }
        return result;
    }

    static std::string format_time(std::chrono::system_clock::time_point tp) {
        auto time = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());
        auto tm = *std::gmtime(time.count());
        
        char buffer[64];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return std::string(buffer);
    }

    static std::string to_json(const Questionnaire& q) {
        std::ostringstream oss;
        
        oss << "{\n";
        oss << "  \"id\": " << q.id << ",\n";
        oss << "  \"title\": \"" << escape(q.title) << "\",\n";
        oss << "  \"description\": \"" << escape(q.description) << "\",\n";
        oss << "  \"version\": \"" << escape(q.version) << "\",\n";
        oss << "  \"created_at\": \"" << format_time(q.created_at) << "\",\n";
        
        // Sections
        oss << "  \"sections\": [";
        for (size_t i = 0; i < q.sections.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << "\"" << escape(q.sections[i]) << "\"";
        }
        oss << "],\n";
        
        // Questions
        oss << "  \"questions\": [\n";
        bool first = true;
        for (const auto& [qid, qdata] : q.questions) {
            if (!first) oss << ",\n";
            first = false;
            
            oss << "    {\n";
            oss << "      \"id\": " << qid << ",\n";
            oss << "      \"section_id\": \"" << escape(qdata.section_id) << "\",\n";
            oss << "      \"question_text\": \"" << escape(qdata.question_text) << "\",\n";
            oss << "      \"type\": \"";
            
            switch (qdata.type) {
                case QuestionType::TEXT:  oss << "\"text\""; break;
                case QuestionType::MULTIPLE_CHOICE: oss << "\"multiple_choice\""; break;
                case QuestionType::TRUE_FALSE: oss << "\"true_false\""; break;
                case QuestionType::RATING_SCALE: oss << "\"rating_scale\""; break;
                case QuestionType::FILE_UPLOAD: oss << "\"file_upload\""; break;
                case QuestionType::SBOM_MATCH: oss << "\"sbom_match\""; break;
            }
            
            oss << "\",\n";
            
            if (!qdata.options.empty()) {
                oss << "      \"options\": [";
                for (size_t i = 0; i < qdata.options.size(); ++i) {
                    if (i > 0) oss << ", ";
                    oss << "\"" << escape(qdata.options[i]) << "\"";
                }
                oss << "],\n";
            }
            
            oss << "      \"required_length\": " << qdata.required_length << ",\n";
            oss << "      \"is_required\": " << (qdata.is_required ? "true" : "false") << "\n";
            
            if (qdata.default_value) {
                oss << ",      \"default_value\": " << *qdata.default_value;
            }
            
            oss << "\n    }";
        }
        oss << "\n  ],\n";
        
        // Vendor info
        if (q.vendor) {
            oss << "  \"vendor\": {\n";
            oss << "    \"name\": \"" << escape(q.vendor->name) << "\",\n";
            oss << "    \"domain\": \"" << escape(q.vendor->domain) << "\",\n";
            oss << "    \"contact_email\": \"" << escape(q.vendor->contact_email) << "\",\n";
            oss << "    \"ciso_email\": \"" << escape(q.vendor->ciso_email) << "\",\n";
            oss << "    \"address\": \"" << escape(q.vendor->address) << "\",\n";
            oss << "    \"phone\": \"" << escape(q.vendor->phone) << "\",\n";
            oss << "    \"website\": \"" << escape(q.vendor->website) << "\"\n";
            oss << "  },\n";
        }
        
        // SBOM entries
        if (!q.sbom_entries.empty()) {
            oss << "  \"sbom_entries\": [\n";
            for (size_t i = 0; i < q.sbom_entries.size(); ++i) {
                if (i > 0) oss << ",\n";
                
                const auto& entry = q.sbom_entries[i];
                oss << "    {\n";
                oss << "      \"package_name\": \"" << escape(entry.package_name) << "\",\n";
                oss << "      \"version\": \"" << escape(entry.version) << "\",\n";
                oss << "      \"license\": \"" << escape(entry.license) << "\",\n";
                oss << "      \"maintainer\": \"" << escape(entry.maintainer) << "\"";
                
                if (entry.source_url) {
                    oss << ",\n      \"source_url\": \"" << escape(*entry.source_url) << "\"";
                }
                
                oss << "\n    }";
            }
            oss << "\n  ]";
        } else {
            oss << "  \"sbom_entries\": []";
        }
        
        oss << "\n}\n";
        
        return oss.str();
    }

    static Questionnaire from_json(const std::string& json) {
        // Simple JSON parser for our specific format
        Questionnaire q;
        q.created_at = std::chrono::system_clock::now();
        
        auto pos = 0u, end = json.size();
        
        // Helper to skip whitespace and get next token
        auto skip_ws = [&pos]() { while (pos < end && std::isspace(json[pos])) ++pos; };
        auto peek = [&pos](){ return pos < end ? json[pos] : '\0'; };
        auto get_char = [&pos, &end]()->char{ if(pos >= end) return '\0'; char c = json[pos]; ++pos; return c; };
        
        // Extract top-level fields
        while (skip_ws() && peek() == '{') { get_char(); }  // skip opening brace
        
        auto extract_string = [&]() -> std::string {
            skip_ws();
            if (peek() != '"') return "";
            ++pos;  // skip opening quote
            std::string result;
            while (pos < end) {
                char c = get_char();
                if (c == '"') break;
                if (c == '\\') {
                    if (pos < end) result += get_char();
                } else {
                    result += c;
                }
            }
            return result;
        };

        auto extract_number = [&]() -> int {
            skip_ws();
            std::string num_str;
            while (std::isdigit(peek())) num_str += get_char();
            if (!num_str.empty()) return std::stoi(num_str);
            return 0;
        };

        // Parse id, title, description, version
        auto parse_field = [&](const char* key) -> void {
            skip_ws();
            if (peek() != '"') return;
            ++pos;  // skip quote
            
            std::string value;
            while (pos < end && peek() != '"' && peek() != ',') {
                if (peek() == '\\') {
                    if (pos < end) value += get_char();
                } else {
                    value += get_char();
                }
            }
            
            skip_ws();
            if (peek() == '"') ++pos;  // skip closing quote
            
            if (value == key) {
                std::string next_value = extract_string();
                
                if (key == "id") q.id = std::stoi(next_value);
                else if (key == "title") q.title = next_value;
                else if (key == "description") q.description = next_value;
                else if (key == "version") q.version = next_value;
            }
        };

        parse_field("id");
        parse_field("title");
        parse_field("description");
        parse_field("version");
        
        // Parse created_at
        skip_ws();
        if (peek() == '"') {
            ++pos;  // skip opening quote
            std::string time_str;
            while (pos < end && peek() != '"' && peek() != ',') {
                if (peek() == '\\') {
                    if (pos < end) time_str += get_char();
                } else {
                    time_str += get_char();
                }
            }
            skip_ws();
            if (peek() == '"') ++pos;  // skip closing quote
            
            auto tp = std::chrono::system_clock::now();
            q.created_at = tp;  // Simplified - would need proper parsing
        }

        // Parse sections
        skip_ws();
        if (peek() == '[') {
            ++pos;  // skip opening bracket
            while (pos < end && peek() != ']') {
                std::string section = extract_string();
                q.sections.push_back(section);
                
                skip_ws();
                if (peek() == ',') { get_char(); }
            }
            ++pos;  // skip closing bracket
        }

        // Parse questions
        skip_ws();
        if (peek() == '[') {
            ++pos;  // skip opening bracket
            
            while (pos < end && peek() != ']') {
                Question qn;
                
                // id
                skip_ws();
                if (peek() == '"') {
                    ++pos;
                    std::string val;
                    while (pos < end && peek() != '"' && peek() != ',') {
                        if (peek() == '\\') val += get_char();
                        else val += get_char();
                    }
                    skip_ws();
                    if (peek() == '"') ++pos;
                    qn.id = std::stoi(val);
                }

                // section_id
                skip_ws();
                if (peek() == '"') {
                    ++pos;
                    std::string val;
                    while (pos < end && peek() != '"' && peek() != ',') {
                        if (peek() == '\\') val += get_char();
                        else val += get_char();
                    }
                    skip_ws();
                    if (peek() == '"') ++pos;
                    qn.section_id = val;
                }

                // question_text
                skip_ws();
                if (peek() == '"') {
                    ++pos;
                    std::string val;
                    while (pos < end && peek() != '"' && peek() != ',') {
                        if (peek() == '\\') val += get_char();
                        else val += get_char();
                    }
                    skip_ws();
                    if (peek() == '"') ++pos;
                    qn.question_text = val;
                }

                // type
                skip_ws();
                std::string type_str;
                while (pos < end && peek() != '"' && peek() != ',') {
                    if (peek() == '\\') type_str += get_char();
                    else type_str += get_char();
                }
                skip_ws();
                if (peek() == '"') ++pos;
                
                auto set_type = [&](const std::string& t) {
                    if (t == "text") qn.type = QuestionType::TEXT;
                    else if (t == "multiple_choice") qn.type = QuestionType::MULTIPLE_CHOICE;
                    else if (t == "true_false") qn.type = QuestionType::TRUE_FALSE;
                    else if (t == "rating_scale") qn.type = QuestionType::RATING_SCALE;
                    else if (t == "file_upload") qn.type = QuestionType::FILE_UPLOAD;
                    else if (t == "sbom_match") qn.type = QuestionType::SBOM_MATCH;
                };
                
                set_type(type_str);

                // options
                skip_ws();
                if (peek() == '[') {
                    ++pos;
                    std::vector<std::string> opts;
                    while (pos < end && peek() != ']') {
                        std::string opt = extract_string();
                        opts.push_back(opt);
                        
                        skip_ws();
                        if (peek() == ',') { get_char(); }
                    }
                    ++pos;  // skip closing bracket
                    qn.options = std::move(opts);
                }

                // required_length
                skip_ws();
                if (peek() == '[') {
                    ++pos;
                    int len = extract_number();
                    qn.required_length = len;
                    --pos;  // back up to include closing bracket
                    if (pos < end && peek() == ']') ++pos;
                }

                // is_required
                skip_ws();
                std::string req_str;
                while (pos < end && peek() != ',' && peek() != '}' && peek() != ']') {
                    if (peek() == '\\') req_str += get_char();
                    else req_str += get_char();
                }
                skip_ws();
                
                qn.is_required = (req_str == "true");

                // default_value
                skip_ws();
                if (peek() == '[') {
                    ++pos;
                    int def_val = extract_number();
                    qn.default_value = def_val;
                    --pos;
                    if (pos < end && peek() == ']') ++pos;
                }

                // sbom_reference
                skip_ws();
                if (peek() == '[') {
                    ++pos;
                    SBOMEntry sbom;
                    
                    while (pos < end && peek() != ']') {
                        std::string field = extract_string();
                        
                        auto parse_sbom_field = [&](const char* key, std::string& val) -> void {
                            skip_ws();
                            if (peek() == '"') {
                                ++pos;
                                while (pos < end && peek() != '"' && peek() != ',') {
                                    if (peek() == '\\') val += get_char();
                                    else val += get_char();
                                }
                                skip_ws();
                                if (peek() == '"') ++pos;
                            }
                        };

                        parse_sbom_field("package_name", sbom.package_name);
                        parse_sbom_field("version",