"""
SBOM parsing and diffing service.

Accepts CycloneDX JSON and SPDX JSON (the two dominant formats).
Normalises all components to a flat list, then diffs against the previous
snapshot to produce a change set.

Typical CI/CD integration:
    syft <image-or-dir> -o cyclonedx-json > sbom.json
    curl -X POST .../api/v1/sbom/repositories/<id>/submit \
         -H "Content-Type: application/json" -d @sbom.json

    trivy image --format cyclonedx -o sbom.json <image>
    curl -X POST .../api/v1/sbom/repositories/<id>/submit \
         -H "Content-Type: application/json" -d @sbom.json
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SbomComponent:
    name: str
    version: str
    purl: Optional[str] = None
    license: Optional[str] = None
    component_type: str = "library"


def detect_format(raw: Dict[str, Any]) -> str:
    """Return 'cyclonedx', 'spdx', or raise ValueError."""
    if raw.get("bomFormat") == "CycloneDX" or "components" in raw:
        return "cyclonedx"
    if raw.get("spdxVersion") or "packages" in raw:
        return "spdx"
    raise ValueError("Unrecognised SBOM format — expected CycloneDX or SPDX JSON")


def detect_tool(raw: Dict[str, Any]) -> Optional[str]:
    """Best-effort extraction of the tool that generated the SBOM."""
    # CycloneDX metadata.tools — array (CycloneDX ≤1.4) or {components:[]} (CycloneDX 1.5+)
    tools_field = raw.get("metadata", {}).get("tools")
    if isinstance(tools_field, dict):
        tools_list = tools_field.get("components", [])
    elif isinstance(tools_field, list):
        tools_list = tools_field
    else:
        tools_list = []
    for tool in tools_list:
        name = tool.get("name") or tool.get("vendor", "")
        if name:
            version = tool.get("version", "")
            return f"{name} {version}".strip()
    # SPDX creationInfo.creators
    for creator in raw.get("creationInfo", {}).get("creators", []):
        if creator.startswith("Tool:"):
            return creator[5:].strip()
    return None


def parse_cyclonedx(raw: Dict[str, Any]) -> List[SbomComponent]:
    components: List[SbomComponent] = []
    for c in raw.get("components", []):
        name = c.get("name", "")
        version = c.get("version", "")
        if not name:
            continue
        # Licenses — CycloneDX stores as a list of objects
        license_id = None
        licenses = c.get("licenses") or []
        if licenses:
            lic = licenses[0]
            license_id = (
                lic.get("license", {}).get("id")
                or lic.get("license", {}).get("name")
                or lic.get("expression")
            )
        components.append(SbomComponent(
            name=name,
            version=version or "unknown",
            purl=c.get("purl"),
            license=license_id,
            component_type=c.get("type", "library"),
        ))
    return components


def parse_spdx(raw: Dict[str, Any]) -> List[SbomComponent]:
    components: List[SbomComponent] = []
    for pkg in raw.get("packages", []):
        name = pkg.get("name", "")
        version = pkg.get("versionInfo", "")
        if not name or name == "NOASSERTION":
            continue
        # purl from externalRefs
        purl = None
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break
        # License
        license_id = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        if license_id in ("NOASSERTION", "NONE"):
            license_id = None
        components.append(SbomComponent(
            name=name,
            version=version or "unknown",
            purl=purl,
            license=license_id,
            component_type="library",
        ))
    return components


def parse(raw: Dict[str, Any]) -> Tuple[str, Optional[str], List[SbomComponent]]:
    """
    Parse a raw SBOM dict.
    Returns (format, tool, components).
    """
    fmt = detect_format(raw)
    tool = detect_tool(raw)
    if fmt == "cyclonedx":
        components = parse_cyclonedx(raw)
    else:
        components = parse_spdx(raw)
    return fmt, tool, components


def diff(
    old: List[SbomComponent],
    new: List[SbomComponent],
) -> List[Dict[str, Any]]:
    """
    Diff two component lists.  Keys on component name (case-insensitive).

    Returns list of change dicts:
      {type: "added"|"removed"|"updated", name, new_version?, old_version?, purl?}
    """
    old_map = {c.name.lower(): c for c in old}
    new_map = {c.name.lower(): c for c in new}

    changes: List[Dict[str, Any]] = []

    for key, nc in new_map.items():
        if key not in old_map:
            changes.append({"type": "added", "name": nc.name, "new_version": nc.version, "purl": nc.purl})
        elif old_map[key].version != nc.version:
            changes.append({
                "type": "updated",
                "name": nc.name,
                "old_version": old_map[key].version,
                "new_version": nc.version,
                "purl": nc.purl,
            })

    for key, oc in old_map.items():
        if key not in new_map:
            changes.append({"type": "removed", "name": oc.name, "old_version": oc.version, "purl": oc.purl})

    return sorted(changes, key=lambda c: (c["type"], c["name"]))


def components_to_json(components: List[SbomComponent]) -> str:
    return json.dumps([asdict(c) for c in components])


def components_from_json(s: str) -> List[SbomComponent]:
    return [SbomComponent(**d) for d in json.loads(s or "[]")]
