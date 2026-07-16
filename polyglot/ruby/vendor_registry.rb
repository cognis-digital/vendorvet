require 'date'
require 'json'
require 'open-uri'

module VendorVet
  # ============ CONFIGURATION ============
  
  DEFAULT_RISK_THRESHOLD = 75.0
  
  class << self
    attr_accessor :risk_threshold
    
    def risk_threshold=(val)
      @risk_threshold = val.to_f
    end
  end
  
  # ============ DATA MODELS ============

  class Vendor < Struct.new(:id, :name, :domain, :industry, :size, :country, :created_at, :updated_at)
    include Comparable
    
    def <=>(other)
      name <=> other.name
    end
    
    def active?
      !closed_at
    end
    
    def closed!
      self.closed_at = Time.now.utc
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        name:,
        domain:,
        industry:,
        size:,
        country:,
        created_at: created_at.iso8601,
        updated_at: updated_at.iso8601,
        closed_at: closed_at&.iso8601
      }
    end
    
    def to_s
      "#{name} (#{domain})"
    end
  end

  class Questionnaire < Struct.new(:id, :title, :description, :version, :created_by, :created_at)
    include Comparable
    
    def <=>(other)
      title <=> other.title
    end
    
    def active?
      !archived_at
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        title:,
        description:,
        version:,
        created_by:,
        created_at: created_at.iso8601,
        archived_at: archived_at&.iso8601
      }
    end
    
    def to_s
      "#{title} v#{version}"
    end
  end

  class QuestionnaireItem < Struct.new(:id, :questionnaire_id, :text, :type, :weight)
    include Comparable
    
    TYPES = %i[text multiple_choice yes_no risk_scale].freeze
    
    def <=>(other)
      id <=> other.id
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        questionnaire_id:,
        text:,
        type:,
        weight:
      }
    end
    
    def to_s
      "#{text} (#{type})"
    end
  end

  class Response < Struct.new(:id, :vendor_id, :questionnaire_id, :submitted_at)
    include Comparable
    
    def <=>(other)
      id <=> other.id
    end
    
    def active?
      !closed_at
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        vendor_id:,
        questionnaire_id:,
        submitted_at: submitted_at.iso8601,
        closed_at: closed_at&.iso8601,
        overall_risk_score: overall_risk_score,
        risk_level: risk_level
      }
    end
    
    def to_s
      "#{vendor_id} -> #{questionnaire_id}"
    end
  end

  class ResponseItem < Struct.new(:id, :response_id, :item_id, :answer, :submitted_at)
    include Comparable
    
    TYPES = %i[text multiple_choice yes_no risk_scale].freeze
    
    def <=>(other)
      id <=> other.id
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        response_id:,
        item_id:,
        answer:,
        submitted_at: submitted_at.iso8601
      }
    end
    
    def to_s
      "#{item_id}: #{answer}"
    end
  end

  class SBOMEntry < Struct.new(:id, :name, :version, :supplier, :license, :cpe)
    include Comparable
    
    TYPES = %i[text multiple_choice yes_no risk_scale].freeze
    
    def <=>(other)
      id <=> other.id
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        name:,
        version:,
        supplier:,
        license:,
        cpe:
      }
    end
    
    def to_s
      "#{name} v#{version}"
    end
  end

  class SBOMCrossRef < Struct.new(:id, :sbom_entry_id, :vendor_id, :questionnaire_item_id)
    include Comparable
    
    def <=>(other)
      id <=> other.id
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        sbom_entry_id:,
        vendor_id:,
        questionnaire_item_id:
      }
    end
    
    def to_s
      "#{sbom_entry_id} -> #{vendor_id}"
    end
  end

  class RiskProfile < Struct.new(:id, :name, :description)
    include Comparable
    
    TYPES = %i[text multiple_choice yes_no risk_scale].freeze
    
    def <=>(other)
      id <=> other.id
    end
    
    def to_h
      as_json
    end
    
    def as_json(options = {})
      {
        id: id,
        name:,
        description:
      }
    end
    
    def to_s
      "#{name}"
    end
  end

  # ============ BUSINESS LOGIC ============

  class VendorRegistry
    include Enumerable
    
    attr_reader :vendors, :questionnaires, :responses, :sbom_entries, :cross_refs
    
    def initialize
      @vendors = []
      @questionnaires = []
      @responses = []
      @sbom_entries = []
      @cross_refs = []
    end
    
    # Vendor operations
    def add_vendor(name:, domain: nil, industry: nil, size: nil, country: nil)
      vendor = Vendor.new(
        id: generate_id(:vendor),
        name:,
        domain:,
        industry:,
        size:,
        country:,
        created_at: Time.now.utc,
        updated_at: Time.now.utc
      )
      @vendors << vendor
      vendor
    end
    
    def find_vendor(id)
      vendors.find { |v| v.id == id }
    end
    
    def find_vendor_by_name(name)
      vendors.find { |v| v.name.casecmp(name).zero? }
    end
    
    def find_vendors(industry: nil, country: nil)
      result = vendors.dup
      result.select! { |v| industry.nil? || v.industry == industry } if industry
      result.select! { |v| country.nil? || v.country == country } if country
      result
    end
    
    # Questionnaire operations
    def add_questionnaire(title:, description: nil, version: "1.0", created_by: nil)
      questionnaire = Questionnaire.new(
        id: generate_id(:questionnaire),
        title:,
        description:,
        version:,
        created_by:,
        created_at: Time.now.utc
      )
      @questionnaires << questionnaire
      questionnaire
    end
    
    def add_questionnaire_item(questionnaire, text:, type: :text, weight: 10)
      item = QuestionnaireItem.new(
        id: generate_id(:item),
        questionnaire_id: questionnaire.id,
        text:,
        type:,
        weight:
      )
      questionnaire << item
      item
    end
    
    def find_questionnaire(id)
      questionnaires.find { |q| q.id == id }
    end
    
    # Response operations
    def submit_response(response_id:, questionnaire:, answers:)
      response = responses.find { |r| r.id == response_id }
      
      if response.nil?
        response = Response.new(
          id: generate_id(:response),
          vendor_id: nil,
          questionnaire_id: questionnaire.id,
          submitted_at: Time.now.utc
        )
        @responses << response
      end
      
      # Process answers and calculate risk score
      process_answers(response, questionnaire, answers)
      
      response
    end
    
    def find_response(id)
      responses.find { |r| r.id == id }
    end
    
    def find_responses_for_vendor(vendor_id)
      responses.select { |r| r.vendor_id == vendor_id }
    end
    
    # SBOM operations
    def add_sbom_entry(name:, version: nil, supplier: nil, license: nil, cpe: nil)
      entry = SBOMEntry.new(
        id: generate_id(:sbom),
        name:,
        version:,
        supplier:,
        license:,
        cpe:
      )
      @sbom_entries << entry
      entry
    end
    
    def add_sbom_cross_ref(sbom_entry, vendor, questionnaire_item)
      ref = SBOMCrossRef.new(
        id: generate_id(:crossref),
        sbom_entry_id: sbom_entry.id,
        vendor_id: vendor.id,
        questionnaire_item_id: questionnaire_item.id
      )
      @cross_refs << ref
      ref
    end
    
    def find_sbom_entry(id)
      sbom_entries.find { |e| e.id == id }
    end
    
    # Risk calculation
    def calculate_overall_risk_score(response, questionnaire)
      return 0.0 unless response.answers.any?
      
      total_weight = 0
      weighted_sum = 0
      
      questionnaire.items.each do |item|
        answer_item = response.answers.find { |a| a.item_id == item.id }
        
        next if answer_item.nil?
        
        # Parse risk score from answer (for text/risk_scale types)
        score = parse_risk_score(answer_item.answer, item.type)
        
        weighted_sum += score * item.weight
        total_weight += item.weight
      end
      
      (weighted_sum / total_weight.to_f * 100).round(2)
    end
    
    def calculate_risk_level(score)
      return "CRITICAL" if score >= DEFAULT_RISK_THRESHOLD
      return "HIGH" if score >= 50.0
      return "MEDIUM" if score >= 25.0
      "LOW"
    end
    
    # ============ HELPER METHODS ============

    def process_answers(response, questionnaire, answers)
      response.answers = []
      
      questionnaire.items.each do |item|
        answer_item = ResponseItem.new(
          id: generate_id(:answer),
          response_id: response.id,
          item_id: item.id,
          answer:,
          submitted_at: Time.now.utc
        )
        
        # Normalize answer for comparison
        normalized_answer = normalize_answer(answer, item.type)
        
        # Calculate item-specific risk score
        item_score = calculate_item_risk(normalized_answer, item.type, item.weight)
        
        answer_item.answer = {
          raw: answer,
          normalized: normalized_answer,
          risk_score: item_score
        }
        
        response.answers << answer_item
      end
      
      # Calculate overall score after all answers processed
      response.overall_risk_score = calculate_overall_risk_score(response, questionnaire)
      response.risk_level = calculate_risk_level(response.overall_risk_score)
    end
    
    def parse_risk_score(answer_text, type)
      return 0.0 unless answer_text.is_a?(String)
      
      # Look for numeric score in text (e.g., "85", "high: 90")
      if match = answer_text.match(/(\d{1,3})/)
        return [match[1].to_f, 100.0].min
      end
      
      # Type-based defaults for non-numeric answers
      case type.to_s
      when "risk_scale"
        75.0
      when "yes_no"
        answer_text.downcase.include?("yes") ? 80.0 : 20.0
      else
        50.0
      end
    end
    
    def calculate_item_risk(answer, type, weight)
      base_score = parse_risk_score(answer, type)
      
      # Apply type-specific modifiers
      case type.to_s
      when "yes_no"
        base_score *= 1.2 if answer.downcase.include?("yes")
      when "multiple_choice"
        high_risk_choices = %w[high critical severe major].freeze
        base_score *= 1.5 if high_risk_choices.any? { |c| answer.downcase.include?(c) }
      end
      
      [base_score, 100.0].min
    end
    
    def normalize_answer(answer, type)
      return answer unless answer.is_a?(String)
      
      case type.to_s
      when "yes_no"
        answer.downcase.strip
      when "multiple_choice"
        answer.downcase.strip.split(",").map(&:strip).join(",")
      else
        answer
      end
    end
    
    def generate_id(prefix)
      "#{prefix}-#{SecureRandom.uuid.gsub("-", "").first(8)}".to_sym
    end
    
    # ============ QUERY METHODS ============

    def find_high_risk_vendors(threshold: DEFAULT_RISK_THRESHOLD)
      high_risk_responses = responses.select do |r|
        r.overall_risk_score && r.overall_risk_score >= threshold
      end
      
      high_risk_responses.map { |r| r.vendor_id }.uniq.sort_by(&method(:find_vendor)).map(&:name).join(", ")
    end
    
    def find_vendors_with_open_questionnaires
      open_q = questionnaires.select { |q| q.active? }
      vendors_with_open = []
      
      open_q.each do |q|
        responses_for_q = responses.select { |r| r.questionnaire_id == q.id && r.active? }
        vendor_ids = responses_for_q.map(&:vendor_id).uniq
        
        vendor_ids.each do |vid|
          v = find_vendor(vid)
          vendors_with_open << v unless v.nil?
        end
      end
      
    def find_vendors_by_sbom_component(name, version: nil)
      matching_entries = sbom_entries.select do |e|
        e.name.casecmp(name).zero? && (version.nil? || e.version == version)
      end
      
      vendor_ids = cross_refs.select { |r| r.sbom_entry_id.in?(matching_entries.map(&:id)) }
                               .map { |r| r.vendor_id }.uniq
      
    def find_questionnaires_for_vendor(vendor_id)
      responses_for_v = find_responses_for_vendor(vendor_id)
      questionnaire_ids = responses_for_v.map(&:questionnaire_id).uniq
      
    # ============ EXPORT/IMPORT ============

    def to_h
      {
        vendors: vendors.map(&:to_h),
        questionnaires: questionnaires.map(&:to_h),
        responses: responses.map(&:to_h),
        sbom_entries: sbom_entries.map(&:to_h),
        cross_refs: cross_refs.map(&:to_h)
      }
    end
    
    def from_hash(hash)
      hash[:vendors]&.each { |h| add_vendor(**h) } if hash[:vendors]
      hash[:questionnaires]&.each { |h| add_questionnaire(**h) } if hash[:questionnaires]
      hash[:responses]&.each { |h| submit_response(**h) } if hash[:responses]
      hash[:sbom_entries]&.each { |h| add_sbom_entry(**h) } if hash[:sbom_entries]
      hash[:cross_refs]&.each { |h| add_sbom_cross_ref(**h) } if hash[:cross_refs]
      
    def export_json(path = nil, indent: 2)
      data = to_h
      json_str = JSON.pretty_generate(data, indent:)
      
      path ? File.write(path, json_str) : puts(json_str)
      
    # ============ DEMO/ENTRY POINT ============

    if __FILE__ == $0
      demo
    
    def demo
      puts "\n=== VendorVet Demo: Third-Party Risk Questionnaire System ===\n"
      
      registry = VendorRegistry.new
      
      # Setup vendors
      puts "1. Registering vendors..."
      vendor_a = registry.add_vendor(name: "Acme Corp", domain: "acme.com", industry: "tech", size: "enterprise")
      vendor_b = registry.add_vendor(name: "Beta Inc", domain: "beta.io", industry: "finance", size: "mid-market")
      vendor_c = registry.add_vendor(name: "Gamma LLC", domain: "gamma.net", industry: "healthcare", size: "startup")
      
      puts "   Registered: #{registry.vendors.map(&:name).join(", ")}"
      
      # Setup questionnaires
      puts