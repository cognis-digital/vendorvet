"""
polyglot/python/questionnaire_builder.py

Third-party / vendor risk questionnaire builder with SBOM cross-reference support.

Features:
- Define questions with multiple types (text, checkbox, dropdown, file upload)
- Group questions into sections with metadata
- Validate responses against constraints and required fields
- Export to JSON/YAML/HTML formats
- Cross-reference packages from SBOM data
- CLI for interactive building
"""

import json
import os
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union


class QuestionType(Enum):
    """Supported question types."""
    TEXT = auto()
    EMAIL = auto()
    URL = auto()
    CHECKBOX = auto()
    DROPDOWN = auto()
    RATING = auto()
    FILE_UPLOAD = auto()
    SBOM_QUERY = auto()


class Severity(Enum):
    """Risk severity levels."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "High"
    LOW = "Low"
    INFO = "Info"


@dataclass
class Constraint:
    """Validation constraint for a field."""
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    required: bool = False
    in_values: Optional[List[str]] = None
    
    def validate(self, value: Any) -> Tuple[bool, str]:
        """Return (is_valid, error_message)."""
        if self.required and not value:
            return False, f"Field is required."
        
        if isinstance(value, str):
            if self.min_length and len(value) < self.min_length:
                return False, f"Minimum length {self.min_length} not met."
            if self.max_length and len(value) > self.max_length:
                return False, f"Maximum length {self.max_length} exceeded."
            if self.pattern and not self.pattern.match(value):
                return False, "Pattern validation failed."
            if self.in_values and value not in self.in_values:
                return False, f"Must be one of: {', '.join(self.in_values)}"
        
        return True, ""


@dataclass
class Question:
    """A single questionnaire question."""
    id: str
    type: QuestionType
    title: str
    description: str = ""
    constraint: Constraint = field(default_factory=Constraint)
    default_value: Any = None
    
    def validate(self, response: Any) -> Tuple[bool, str]:
        """Validate a response against constraints."""
        return self.constraint.validate(response)


@dataclass
class Section:
    """A grouped section of questions."""
    id: str
    title: str
    description: str = ""
    order: int = 0
    
    def add_question(self, question: Question):
        """Add a question to this section."""
        if not hasattr(self, 'questions'):
            self.questions = []
        self.questions.append(question)


@dataclass
class SBOMReference:
    """Cross-reference data from an SBOM."""
    package_name: str
    version: str
    license: Optional[str] = None
    cpe_id: Optional[str] = None
    
    def __str__(self):
        return f"{self.package_name} {self.version}"


@dataclass
class SBOMQuestion:
    """A question that queries SBOM data."""
    id: str
    title: str
    description: str = ""
    package_filter: Optional[str] = None  # Filter by package name/pattern
    
    def resolve(self, sbom_data: Dict) -> List[SBOMReference]:
        """Resolve against SBOM data and return matching references."""
        refs = []
        
        if not sbom_data or 'packages' not in sbom_data:
            return refs
        
        for pkg in sbom_data['packages']:
            name_match = self.package_filter is None or \
                        self.package_filter.lower() in pkg.get('name', '').lower()
            
            if name_match:
                refs.append(SBOMReference(
                    package_name=pkg.get('name', ''),
                    version=pkg.get('version', ''),
                    license=pkg.get('license'),
                    cpe_id=pkg.get('cpe')
                ))
        
        return refs


class QuestionnaireBuilder:
    """Main builder for constructing questionnaires."""
    
    def __init__(self, name: str = "Vendor Risk Assessment"):
        self.name = name
        self.description = ""
        self.version = "1.0"
        self.created_at = datetime.now()
        self.sections: List[Section] = []
        self.metadata: Dict[str, Any] = {}
    
    def add_section(self, title: str, description: str = "", order: int = 0) -> Section:
        """Add a new section and return it for chaining."""
        section = Section(id=f"sec_{len(self.sections)}", 
                         title=title, 
                         description=description,
                         order=order)
        self.sections.append(section)
        return section
    
    def add_question(
        self,
        question_type: QuestionType,
        title: str,
        description: str = "",
        constraint: Optional[Constraint] = None,
        default_value: Any = None,
        parent_section: Optional[Section] = None
    ) -> Question:
        """Add a new question and return it for chaining."""
        
        if not parent_section:
            # Auto-assign to first section or create temp container
            parent_section = self.sections[-1] if self.sections else Section(
                id="temp", title="Temporary", order=999
            )
        
        constraint = constraint or Constraint()
        question = Question(
            id=f"q_{len(parent_section.questions)}",
            type=question_type,
            title=title,
            description=description,
            constraint=constraint,
            default_value=default_value
        )
        
        parent_section.add_question(question)
        return question
    
    def add_sbom_query(
        self,
        title: str,
        description: str = "",
        package_filter: Optional[str] = None,
        parent_section: Optional[Section] = None
    ) -> SBOMQuestion:
        """Add a question that queries SBOM data."""
        
        if not parent_section:
            parent_section = self.sections[-1] if self.sections else Section(
                id="temp", title="Temporary", order=999
            )
        
        sbom_q = SBOMQuestion(
            id=f"sbom_{len(parent_section.questions)}",
            title=title,
            description=description,
            package_filter=package_filter
        )
        
        parent_section.add_question(sbom_q)
        return sbom_q
    
    def set_metadata(self, key: str, value: Any):
        """Set metadata field."""
        self.metadata[key] = value
    
    def get_full_schema(self) -> Dict[str, Any]:
        """Get complete questionnaire schema for export."""
        sections_data = []
        
        for section in self.sections:
            q_list = []
            for q in getattr(section, 'questions', []):
                if isinstance(q, SBOMQuestion):
                    q_dict = {
                        "type": "sbom_query",
                        "id": q.id,
                        "title": q.title,
                        "description": q.description,
                        "package_filter": q.package_filter
                    }
                else:
                    q_dict = {
                        "type": q.type.name.lower(),
                        "id": q.id,
                        "title": q.title,
                        "description": q.description,
                        "constraint": {
                            "min_length": q.constraint.min_length,
                            "max_length": q.constraint.max_length,
                            "pattern": q.constraint.pattern,
                            "required": q.constraint.required,
                            "in_values": q.constraint.in_values
                        },
                        "default_value": q.default_value
                    }
                q_list.append(q_dict)
            
            sections_data.append({
                "id": section.id,
                "title": section.title,
                "description": section.description,
                "order": section.order,
                "questions": q_list
            })
        
        return {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "description": self.description,
            "metadata": self.metadata,
            "sections": sections_data
        }


class QuestionnaireValidator:
    """Validates questionnaire responses."""
    
    def __init__(self, schema: Dict[str, Any]):
        self.schema = schema
    
    def validate_response(self, response: Dict) -> Tuple[bool, List[str]]:
        """Validate a complete response. Returns (is_valid, errors)."""
        errors = []
        
        if not response.get('sections'):
            return False, ["Response missing sections."]
        
        for section_data in response['sections']:
            if 'questions' not in section_data:
                continue
            
            for q_data in section_data['questions']:
                q_type = q_data.get('type')
                constraint = q_data.get('constraint', {})
                
                value = response.get(section_data.get('id', ''), {}).get(
                    q_data.get('id', '')
                )
                
                # Type-specific validation
                if q_type == 'sbom_query':
                    continue  # SBOM queries don't have direct user input
                
                min_len = constraint.get('min_length')
                max_len = constraint.get('max_length')
                required = constraint.get('required', False)
                in_values = constraint.get('in_values')
                
                if value is None:
                    if required:
                        errors.append(f"Required question {q_data['id']} not answered.")
                    continue
                
                if isinstance(value, str):
                    if min_len and len(value) < min_len:
                        errors.append(
                            f"Question {q_data['id']}: minimum length {min_len} not met."
                        )
                    if max_len and len(value) > max_len:
                        errors.append(
                            f"Question {q_data['id']}: maximum length {max_len} exceeded."
                        )
                    if in_values and value not in in_values:
                        errors.append(
                            f"Question {q_data['id']}: must be one of {in_values}"
                        )
        
        return len(errors) == 0, errors


class ResponseRenderer:
    """Renders questionnaire responses to various formats."""
    
    @staticmethod
    def render_html(schema: Dict[str, Any], response: Dict) -> str:
        """Render a completed questionnaire as HTML."""
        if not response.get('sections'):
            return "<p>No sections found.</p>"
        
        html_parts = [f"<h1>{schema.get('name', 'Questionnaire')}</h1>"]
        
        for section in response['sections']:
            q_list = section.get('questions', [])
            
            if not q_list:
                continue
            
            html_parts.append(f"<section><h2>{section.get('title', '')}</h2>")
            
            for q_data in q_list:
                q_type = q_data.get('type')
                title = q_data.get('title', '')
                
                if not title:
                    continue
                
                # Get response value
                section_id = section.get('id', '')
                q_id = q_data.get('id', '')
                value = response.get(section_id, {}).get(q_id)
                
                html_parts.append(f"<p><strong>{title}</strong>")
                
                if value is not None:
                    html_parts.append(f"<code>{value}</code></p>")
                else:
                    html_parts.append("<i>(not answered)</i></p>")
            
            html_parts.append("</section>\n")
        
        return "\n".join(html_parts)


def load_sbom_from_file(filepath: str, format_type: str = "spdx") -> Dict[str, Any]:
    """Load SBOM data from a file."""
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"SBOM file not found: {filepath}")
    
    with open(filepath) as f:
        content = f.read()
    
    # Simple parser for common formats
    if format_type == "spdx":
        # Extract package information from SPDX JSON
        try:
            data = json.loads(content)
            
            packages = []
            if 'packages' in data:
                for pkg in data['packages']:
                    packages.append({
                        'name': pkg.get('name', ''),
                        'version': pkg.get('version'),
                        'license': pkg.get('licenses', [{}])[0].get('identifier') if 
                                  pkg.get('licenses') and len(pkg['licenses']) > 0 else None,
                        'cpe': pkg.get('externalRefs', [])[-1].get('reference') if
                               pkg.get('externalRefs') else None
                    })
            
            return {'packages': packages}
        except json.JSONDecodeError:
            # Fallback for non-JSON SPDX
            return {'packages': []}
    
    elif format_type == "cyclonedx":
        try:
            data = json.loads(content)
            
            packages = []
            if 'components' in data:
                for comp in data['components']:
                    packages.append({
                        'name': comp.get('name', ''),
                        'version': comp.get('version'),
                        'license': comp.get('licenses', [{}])[0].get('id') if
                                  comp.get('licenses') and len(comp['licenses']) > 0 else None,
                        'cpe': comp.get('externalRefs', [])[-1].get('reference') if
                               comp.get('externalRefs') else None
                    })
            
            return {'packages': packages}
        except json.JSONDecodeError:
            return {'packages': []}
    
    elif format_type == "json":
        try:
            data = json.loads(content)
            # Generic JSON with package list
            if isinstance(data, list):
                packages = [{'name': item.get('name', ''), 
                            'version': item.get('version')} for item in data]
            else:
                packages = []
            
            return {'packages': packages}
        except json.JSONDecodeError:
            return {'packages': []}
    
    else:
        raise ValueError(f"Unsupported SBOM format: {format_type}")


def create_demo_questionnaire() -> QuestionnaireBuilder:
    """Create a sample questionnaire for demonstration."""
    builder = QuestionnaireBuilder(name="Vendor Risk Assessment Q1")
    builder.description = "Standard third-party risk assessment questionnaire."
    
    # Section 1: General Information
    sec_general = builder.add_section(
        title="General Information",
        description="Basic vendor details and contact information.",
        order=0
    )
    
    builder.add_question(
        QuestionType.TEXT,
        "Vendor Legal Name",
        "Full legal name of the vendor organization.",
        Constraint(required=True),
        parent_section=sec_general
    )
    
    builder.add_question(
        QuestionType.EMAIL,
        "Primary Contact Email",
        "Email address for primary technical contact.",
        Constraint(pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
        parent_section=sec_general
    )
    
    builder.add_question(
        QuestionType.URL,
        "Vendor Website",
        "Official website URL.",
        Constraint(pattern=r"^(https?://)?[^\s/$.?#].[^\s]*$"),
        parent_section=sec_general
    )
    
    # Section 2: Security Practices
    sec_security = builder.add_section(
        title="Security Practices",
        description="Current security practices and certifications.",
        order=1
    )
    
    builder.add_question(
        QuestionType.CHECKBOX,
        "ISO 27001 Certified",
        "Is the vendor ISO 27001 certified?",
        Constraint(in_values=["Yes", "No"]),
        parent_section=sec_security
    )
    
    builder.add_question(
        QuestionType.RATING,
        "Data Encryption at Rest",
        "Rate encryption implementation (1-5 scale).",
        Constraint(min_length=1, max_length=1),
        default_value="3",
        parent_section=sec_security
    )
    
    builder.add_question(
        QuestionType.TEXT,
        "Last Security Audit Date",
        "Date of most recent security audit.",
        Constraint(pattern=r"^\d{4}-\d{2}-\d{2}$"),
        parent_section=sec_security
    )
    
    # Section 3: SBOM & Dependencies
    sec_sbom = builder.add_section(
        title="SBOM and Dependencies",
        description="Software Bill of Materials and third-party dependencies.",
        order=2
    )
    
    builder.add_question(
        QuestionType.SBOM_QUERY,
        "Critical Vulnerabilities in SBOM",
        "Check for packages with known critical vulnerabilities (CVE).",
        package_filter="critical",
        parent_section=sec_sbom
    )
    
    builder.add_question(
        QuestionType.TEXT,
        "SBOM Format Supported",
        "Which SBOM formats can be provided? (SPDX, CycloneDX, etc.)",
        Constraint(in_values=["SPDX", "CycloneDX", "JSON"]),
        parent_section=sec_sbom
    )
    
    builder.add_question(
        QuestionType.FILE_UPLOAD,
        "SBOM File Upload",
        "Upload your SBOM file for analysis.",
        parent_section=sec_sbom
    )
    
    # Section 4: Incident Response
    sec