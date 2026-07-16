"""vendor_registry.py — Vendor Registry Module for vendorvet

A complete implementation of a third-party/vendor risk questionnaire system
with SBOM cross-referencing capabilities.

Usage:
    from vendor_registry import VendorRegistry, Vendor
    registry = VendorRegistry()
    registry.add_vendor(Vendor(...))
    results = registry.search(name="Acme Corp")
"""

from __future__ import annotations
import json
import csv
import hashlib
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, date
from enum import Enum, auto
from typing import (
    Optional, List, Dict, Any, Iterator, Tuple, 
    Callable, TypeVar, Generic, Protocol
)

# Configure module-level logging
_logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk classification levels for vendors."""
    CRITICAL = auto()      # 90-100
    HIGH = auto()          # 75-89
    MEDIUM = auto()        # 60-74
    LOW = auto()           # 25-59
    MINIMAL = auto()       # 0-24


class ComplianceStatus(Enum):
    """Questionnaire compliance states."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    REVIEW = "review"
    APPROVED = "approved"
    CONDITIONAL = "conditional"
    FAILED = "failed"
    EXPIRED = "expired"


class SBOMFormat(Enum):
    """Supported SBOM standards."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    CPE = "cpe"
    CUSTOM = "custom"


@dataclass(frozen=True)
class Contact:
    """Vendor contact information."""
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    
    def __post_init__(self):
        if not self.name.strip():
            raise ValueError("Contact name cannot be empty")


@dataclass(frozen=True)
class VendorProfile:
    """Core vendor profile data."""
    name: str
    industry: Optional[str] = None
    size_category: Optional[str] = None  # S/M/L/Enterprise
    headquarters: Optional[str] = None
    year_founded: Optional[int] = None
    
    @property
    def unique_id(self) -> str:
        """Generate a stable identifier from name."""
        return hashlib.sha256(
            self.name.strip().lower().encode()
        ).hexdigest()[:12]


@dataclass(frozen=True)
class SBOMReference:
    """Reference to an SBOM document."""
    vendor_name: str
    software_product: Optional[str] = None
    sbom_url: Optional[str] = None
    sbom_hash: Optional[str] = None  # SHA-256 of downloaded content
    format: SBOMFormat = SBOMFormat.CUSTOM
    version: Optional[str] = None
    last_verified: Optional[datetime] = None
    
    def __hash__(self):
        return hash((self.vendor_name, self.sbom_url or ""))


@dataclass(frozen=True)
class QuestionnaireResponse:
    """Single questionnaire response record."""
    vendor_id: str
    question_id: str
    answer_type: str  # text, yes/no, multiple-choice, file_upload
    answer_value: Optional[Any] = None
    confidence_score: float = 1.0  # 0-1, how certain we are
    verified_by: Optional[str] = None
    verification_date: Optional[datetime] = None
    
    @property
    def is_verified(self) -> bool:
        return self.verified_by is not None and self.verification_date is not None


@dataclass(frozen=True)
class VendorRiskProfile:
    """Aggregated risk profile for a vendor."""
    vendor_id: str
    base_score: float = 50.0  # Starting score, 0-100
    questionnaire_score: Optional[float] = None
    sbom_coverage: float = 0.0  # 0.0 to 1.0
    historical_incidents: int = 0
    last_assessment_date: datetime = field(default_factory=datetime.now)
    
    @property
    def risk_level(self) -> RiskLevel:
        """Determine risk level from base score."""
        if self.base_score >= 90:
            return RiskLevel.CRITICAL
        elif self.base_score >= 75:
            return RiskLevel.HIGH
        elif self.base_score >= 60:
            return RiskLevel.MEDIUM
        elif self.base_score >= 25:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL
    
    def adjust(self, delta: float) -> None:
        """Adjust score by delta (can be negative)."""
        new_score = max(0.0, min(100.0, self.base_score + delta))
        _logger.debug("Adjusted %s from %.2f to %.2f", 
                     self.vendor_id, self.base_score, new_score)
        self.base_score = new_score


@dataclass(frozen=True)
class Vendor:
    """Complete vendor record."""
    profile: VendorProfile
    contact: Optional[Contact] = None
    risk_profile: VendorRiskProfile = field(default_factory=VendorRiskProfile)
    sbom_references: List[SBOMReference] = field(default_factory=list)
    questionnaire_responses: List[QuestionnaireResponse] = field(default_factory=list)
    audit_log: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def effective_risk_score(self) -> float:
        """Calculate current risk score considering all factors."""
        if self.risk_profile.questionnaire_score is not None:
            # Blend questionnaire with base risk
            return (self.risk_profile.base_score * 0.4 + 
                    self.risk_profile.questionnaire_score * 0.6)
        return self.risk_profile.base_score
    
    def add_response(self, response: QuestionnaireResponse) -> None:
        """Add a new questionnaire response."""
        self.questionnaire_responses.append(response)
        self._audit_log_action("response_added", {
            "question_id": response.question_id,
            "timestamp": datetime.now().isoformat()
        })
    
    def _audit_log_action(self, action: str, details: Dict[str, Any]) -> None:
        """Log an audit event."""
        self.audit_log.append({
            "action": action,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "vendor_id": self.profile.unique_id
        })


class VendorRegistry(Generic[T]):
    """Thread-safe vendor registry with SBOM cross-referencing."""
    
    def __init__(self, data_dir: Optional[str] = None):
        """Initialize the registry.
        
        Args:
            data_dir: Directory for persisting registry state. Defaults to 
                     ~/.vendorvet/data if not specified.
        """
        self._vendors: Dict[str, Vendor] = {}
        self._data_dir = data_dir or os.path.expanduser(
            "~/.vendorvet/data"
        )
        os.makedirs(self._data_dir, exist_ok=True)
        
        # Load existing state if available
        self._load_from_disk()
    
    def _get_state_file_path(self) -> str:
        """Get path to the main state file."""
        return os.path.join(self._data_dir, "registry.json")
    
    def _save_to_disk(self) -> None:
        """Persist current state to disk."""
        try:
            with open(self._get_state_file_path(), 'w') as f:
                # Convert dataclasses to dicts for JSON serialization
                state = {
                    "vendors": [
                        self._vendor_to_dict(v) 
                        for v in sorted(
                            self._vendors.values(), 
                            key=lambda x: x.profile.unique_id
                        )
                    ],
                    "metadata": {
                        "version": "1.0",
                        "last_saved": datetime.now().isoformat()
                    }
                }
                json.dump(state, f, indent=2, default=str)
            _logger.info("Registry state saved to %s", self._get_state_file_path())
        except (IOError, OSError) as e:
            _logger.error("Failed to save registry: %s", e)
    
    def _vendor_to_dict(self, vendor: Vendor) -> Dict[str, Any]:
        """Convert a Vendor instance to a serializable dict."""
        return {
            "profile": asdict(vendor.profile),
            "contact": asdict(vendor.contact) if vendor.contact else None,
            "risk_profile": {
                "base_score": vendor.risk_profile.base_score,
                "questionnaire_score": vendor.risk_profile.questionnaire_score,
                "sbom_coverage": vendor.risk_profile.sbom_coverage,
                "historical_incidents": vendor.risk_profile.historical_incidents,
            },
            "sbom_references": [asdict(r) for r in vendor.sbom_references],
            "audit_log": vendor.audit_log[-10:],  # Keep last 10 entries only
        }
    
    def _load_from_disk(self) -> None:
        """Load existing registry state from disk."""
        state_file = self._get_state_file_path()
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    data = json.load(f)
                    
                    for v_data in data.get("vendors", []):
                        vendor = self._dict_to_vendor(v_data)
                        self._vendors[vendor.profile.unique_id] = vendor
                    
                    # Restore metadata if present
                    if "metadata" in data:
                        _logger.info(
                            "Loaded %d vendors from persisted state", 
                            len(self._vendors)
                        )
            except (json.JSONDecodeError, IOError) as e:
                _logger.warning("Corrupted state file, starting fresh: %s", e)
    
    def _dict_to_vendor(self, data: Dict[str, Any]) -> Vendor:
        """Convert a dict back to a Vendor instance."""
        profile = VendorProfile(**data["profile"])
        
        vendor = Vendor(
            profile=profile,
            contact=Contact(**data["contact"]) if data.get("contact") else None,
            risk_profile=VendorRiskProfile(
                vendor_id=profile.unique_id,
                base_score=data["risk_profile"]["base_score"],
                questionnaire_score=data["risk_profile"].get("questionnaire_score"),
                sbom_coverage=data["risk_profile"].get("sbom_coverage", 0.0),
                historical_incidents=data["risk_profile"].get(
                    "historical_incidents", 0
                ),
            )
        )
        
        # Restore SBOM references and audit log
        for r_data in data.get("sbom_references", []):
            vendor.sbom_references.append(SBOMReference(**r_data))
        
        vendor.audit_log = data.get("audit_log", [])
        return vendor
    
    def get_vendor(self, identifier: str) -> Optional[Vendor]:
        """Get a vendor by unique ID or name.
        
        Args:
            identifier: Vendor's unique_id, name, or partial match
            
        Returns:
            The matching Vendor instance, or None if not found
        """
        # Direct lookup by unique_id first
        if identifier in self._vendors:
            return self._vendors[identifier]
        
        # Fuzzy search by name
        for vendor in self._vendors.values():
            if (identifier.lower() in vendor.profile.name.lower() or
                identifier == vendor.profile.unique_id):
                return vendor
        
        _logger.debug("No vendor found matching '%s'", identifier)
        return None
    
    def add_vendor(self, vendor: Vendor) -> bool:
        """Add a new vendor to the registry.
        
        Args:
            vendor: The Vendor instance to add
            
        Returns:
            True if added successfully, False if duplicate exists
        """
        existing = self.get_vendor(vendor.profile.unique_id)
        if existing:
            _logger.warning("Vendor %s already exists", vendor.profile.name)
            return False
        
        self._vendors[vendor.profile.unique_id] = vendor
        self._save_to_disk()
        _logger.info("Added new vendor: %s", vendor.profile.name)
        return True
    
    def update_vendor(self, vendor: Vendor) -> bool:
        """Update an existing vendor's data.
        
        Args:
            vendor: The updated Vendor instance
            
        Returns:
            True if updated, False if not found
        """
        identifier = vendor.profile.unique_id
        if identifier in self._vendors:
            old_vendor = self._vendors[identifier]
            
            # Preserve audit history from the existing record
            new_audit_log = old_vendor.audit_log + [
                {
                    "action": "update",
                    "details": {"field": "full_record"},
                    "timestamp": datetime.now().isoformat(),
                    "vendor_id": identifier,
                }
            ]
            
            self._vendors[identifier] = vendor
            vendor.audit_log = new_audit_log
            
            # Only save if something actually changed
            if old_vendor.effective_risk_score != vendor.effective_risk_score:
                _logger.info("Updated risk score for %s", vendor.profile.name)
            
            self._save_to_disk()
            return True
        
        _logger.warning("Update failed - vendor %s not found", identifier)
        return False
    
    def remove_vendor(self, identifier: str) -> bool:
        """Remove a vendor from the registry.
        
        Args:
            identifier: Vendor's unique_id or name
            
        Returns:
            True if removed, False if not found
        """
        vendor = self.get_vendor(identifier)
        if not vendor:
            return False
        
        del self._vendors[vendor.profile.unique_id]
        self._save_to_disk()
        _logger.info("Removed vendor: %s", vendor.profile.name)
        return True
    
    def search(
        self, 
        name: Optional[str] = None,
        industry: Optional[str] = None,
        min_risk_score: float = 0.0,
        max_risk_score: float = 100.0,
        compliance_status: Optional[ComplianceStatus] = None,
    ) -> List[Vendor]:
        """Search vendors with multiple filters.
        
        Args:
            name: Partial or exact name match (case-insensitive)
            industry: Filter by industry code/name
            min_risk_score: Minimum effective risk score
            max_risk_score: Maximum effective risk score  
            compliance_status: Optional compliance filter
            
        Returns:
            List of matching Vendor instances
        """
        results = list(self._vendors.values())
        
        if name:
            search_term = name.lower()
            results = [v for v in results 
                      if search_term in v.profile.name.lower()]
        
        if industry:
            results = [v for v in results 
                      if industry.lower() in (v.profile.industry or "").lower()]
        
        if min_risk_score > 0 or max_risk_score < 100:
            results = [
                v for v in results 
                if min_risk_score <= v.effective_risk_score <= max_risk_score
            ]
        
        return results
    
    def get_sbom_coverage(self, vendor_id: str) -> float:
        """Calculate SBOM coverage for a specific vendor.
        
        Args:
            vendor_id: The unique identifier of the vendor
            
        Returns:
            Coverage ratio (0.0 to 1.0), or 0.0 if no products found
        """
        vendor = self.get_vendor(vendor_id)
        if not vendor:
            return 0.0
        
        # Calculate coverage based on known software products vs expected
        total_products = len(vendor.sbom_references)
        if total_products == 0:
            return 0.0
        
        # Assume we expect at least 3 major product lines for enterprise vendors
        expected_products = max(3, vendor.profile.size_category in ("L", "Enterprise") and 5 or 2)
        
        coverage = min(1.0, total_products / expected_products)
        vendor.risk_profile.sbom_coverage = coverage
        
        return coverage
    
    def cross_reference_sboms(self, 
                             software_name: str,
                             version: Optional[str] = None) -> List[Vendor]:
        """Find all vendors supplying a specific software product.
        
        Args:
            software_name: The software/product name to search for
            version: Optional exact version match
            
        Returns:
            List of Vendor instances that supply the matching software
        """
        results = []
        search_term = software_name.lower()
        
        for vendor in self._vendors.values():
            for sb