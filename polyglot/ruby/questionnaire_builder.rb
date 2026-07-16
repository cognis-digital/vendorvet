# frozen_string_literal: true

require 'json'
require 'csv'
require 'date'

module VendorVet
  # Questionnaire builder for vendor risk assessments with SBOM cross-referencing.
  module QuestionnaireBuilder
    # Types of questions supported.
    QUESTION_TYPES = {
      boolean:   ->(v) { v.is_a?(TrueClass) || v.is_a?(FalseClass) },
      text:      ->(v) { v.is_a?(String) && !v.nil? },
      email:     ->(v) { v.is_a?(String) && v.match?(/\A[\w\.-]+@[\w\.-]+\.\w+\z/) },
      multiple:  ->(v) { v.is_a?(Array) && v.all? { |x| x.is_a?(String) } },
      sbom_ref:  ->(v) { v.is_a?(Hash) && v.key?('name') && v.key?('version') }
    }.freeze

    # A single question in the questionnaire.
    Question = Struct.new(:id, :type, :title, :description, :options, :sbom_ref: nil) do
      def valid_response?
        QUESTION_TYPES[type].call(response) if response
      end

      def to_json(*args)
        JSON.generate({ id:, type:, title:, description:, options:, sbom_ref: })
      end
    end

    # A section of the questionnaire (grouping related questions).
    Section = Struct.new(:id, :title, :description, :questions) do
      def valid?
        questions.all? { |q| q.valid_response? } if response
      end

      def to_json(*args)
        JSON.generate({ id:, title:, description:, questions: })
      end
    end

    # The main questionnaire container.
    Questionnaire = Struct.new(:id, :title, :description, :sections, :metadata: {}) do
      def valid?
        sections.all? { |s| s.valid? } if response
      end

      def to_json(*args)
        JSON.generate({ id:, title:, description:, sections:, metadata: })
      end

      def with_response(response_hash)
        self.response = response_hash
        self
      end
    end

    # Builder class for constructing questionnaires via method chaining.
    class Builder
      attr_reader :questionnaire, :current_section

      def initialize(id: SecureRandom.uuid[0..15], title:, description:)
        @questionnaire = Questionnaire.new(
          id:,
          title:,
          description:,
          sections: [],
          metadata: { created_at: Time.now.iso8601, builder_version: '1.0' }
        )
      end

      def section(title:, description:)
        @current_section = Section.new(
          id: SecureRandom.uuid[0..15],
          title:,
          description:,
          questions: []
        )
        @questionnaire.sections << @current_section
        self
      end

      def question(type:, title:, description:, options: nil, sbom_ref: nil)
        q = Question.new(
          id: SecureRandom.uuid[0..15],
          type:,
          title:,
          description:,
          options:,
          sbom_ref:
        )

        @current_section&.questions << q if @current_section
        self
      end

      def with_sbom_ref(name:, version:)
        question(type: :sbom_ref, title: "SBOM Reference", description: "", options: [name], sbom_ref: { name:, version: })
      end

      def build
        @questionnaire
      end

      def to_json(*args)
        JSON.generate(build.to_json(*args))
      end
    end
  end

  # Convenience factory methods.
  module QuestionnaireFactory
    extend self

    def create_security_questionnaire(title:, description:)
      b = VendorVet::QuestionnaireBuilder::Builder.new(
        title: "Security Controls",
        description: description || "Standard security questionnaire for vendor risk assessment."
      )

      b.section(title: "Authentication & Access Control", description: "How the vendor manages user authentication.") do
        b.question(type: :boolean, title: "MFA enforced for all admin accounts?", description: "")
        b.question(type: :text,  title: "Password policy minimum length (days)", description: "")
      end

      b.section(title: "Incident Response", description: "How the vendor handles security incidents.") do
        b.question(type: :boolean, title: "24/7 SOC available?", description: "")
        b.question(type: :text,  title: "Mean time to acknowledge (hours)", description: "")
      end

      b.section(title: "SBOM & Dependencies", description: "Software Bill of Materials management.") do
        b.with_sbom_ref(name: 'openssl', version: '1.1.0')
        b.question(type: :boolean, title: "CVE-2021-3711 patched?", description: "")
      end

      b.build
    end

    def create_compliance_questionnaire(title:, description:)
      b = VendorVet::QuestionnaireBuilder::Builder.new(
        title: "Compliance & Certifications",
        description: description || "Regulatory compliance questionnaire."
      )

      b.section(title: "Certifications", description: "Current certifications held.") do
        b.question(type: :multiple, title: "Active ISO certifications?", description: "")
        b.question(type: :text,  title: "SOC 2 Type (1/2)", description: "")
      end

      b.section(title: "Data Residency", description: "Where data is stored and processed.") do
        b.question(type: :boolean, title: "EU GDPR compliant?", description: "")
        b.question(type: :text,  title: "Primary data center regions", description: "")
      end

      b.build
    end
  end
end

# =============================================================================
# DEMO / RUNNABLE EXAMPLE
# =============================================================================

if __FILE__ == $0 || ARGV.first == '--demo'
  puts "=== VendorVet Questionnaire Builder Demo ==="
  puts ""

  # Create a security questionnaire
  sec_q = VendorVet::QuestionnaireFactory.create_security_questionnaire(
    title: "Acme Corp Security Assessment",
    description: "Q3 2024 vendor review."
  )

  puts "Created questionnaire ID: #{sec_q.id}"
  puts "Title: #{sec_q.title}"
  puts ""

  # Add a response for demo purposes
  sec_q.with_response({
    'sections' => {
      'auth' => {
        'questions' => {
          'q1' => true,
          'q2' => '90'
        }
      },
      'incident' => {
        'questions' => {
          'q3' => false,
          'q4' => '48'
        }
      },
      'sbom' => {
        'questions' => {
          'q5' => true
        }
      }
    }
  })

  # Validate and output
  if sec_q.valid?
    puts "✓ Questionnaire is valid."
  else
    puts "✗ Questionnaire has validation errors:"
    sec_q.sections.each do |s|
      s.questions.each_with_index do |q, i|
        next unless q.response && !q.valid_response?
        puts "   - #{i+1}. #{q.title}: invalid response '#{q.response}'"
      end
    end
  end

  # Export to JSON
  json_output = sec_q.to_json
  File.write('output/questionnaire.json', json_output)
  puts "\nJSON output written to output/questionnaire.json"

  # Show preview of first section
  puts "\n--- Preview (first 200 chars) ---"
  puts json_output[0..197] + "..." if json_output.length > 200

  puts ""
  puts "=== Demo Complete ==="
end