"""Schema estricto para el payload del modelo; metadatos se añaden localmente."""

from .errors import BackendRequestSchemaViolation, BackendResponseSchemaViolation


_ALLOWED_KEYWORDS = {"type", "properties", "required", "additionalProperties", "items", "enum", "description"}
# Esta allowlist es independiente de la validación genérica: documenta exactamente
# el pequeño subconjunto que emite nuestro generador para Structured Outputs strict.
_OPENAI_STRUCTURED_OUTPUT_ALLOWED_KEYWORDS = frozenset(_ALLOWED_KEYWORDS)


def validate_strict_schema(schema, path="$"):
    """Valida localmente el subconjunto strict utilizado antes de llamar al proveedor."""
    if not isinstance(schema, dict):
        raise BackendRequestSchemaViolation(f"schema node is not an object at {path}")
    unsupported = set(schema) - _ALLOWED_KEYWORDS
    if unsupported:
        raise BackendRequestSchemaViolation(f"unsupported schema keywords at {path}: {sorted(unsupported)}")
    node_type = schema.get("type")
    types = (node_type,) if isinstance(node_type, str) else tuple(node_type) if isinstance(node_type, list) else ()
    if not types or any(item not in {"object", "array", "string", "integer", "number", "boolean", "null"} for item in types):
        raise BackendRequestSchemaViolation(f"invalid type at {path}: {node_type!r}")
    if "object" in types:
        properties = schema.get("properties")
        if not isinstance(properties, dict) or schema.get("additionalProperties") is not False:
            raise BackendRequestSchemaViolation(f"object must close properties at {path}")
        required = schema.get("required")
        if not isinstance(required, list) or set(required) != set(properties) or len(required) != len(properties):
            raise BackendRequestSchemaViolation(f"all object properties must be required at {path}")
        for name, child in properties.items(): validate_strict_schema(child, f"{path}.properties.{name}")
    if "array" in types:
        if not isinstance(schema.get("items"), dict):
            raise BackendRequestSchemaViolation(f"array items must be a schema object at {path}")
        validate_strict_schema(schema["items"], f"{path}.items")
    if "enum" in schema:
        if not isinstance(schema["enum"], list) or not schema["enum"]:
            raise BackendRequestSchemaViolation(f"enum must be non-empty at {path}")
        primitive = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool, "null": type(None)}
        allowed_types = tuple(primitive[item] for item in types)
        if any(not isinstance(value, allowed_types) for value in schema["enum"]):
            raise BackendRequestSchemaViolation(f"enum conflicts with type at {path}")


def validate_openai_structured_output_subset(schema, path="$"):
    """Allowlist del subconjunto utilizado con Structured Outputs strict.

    Es deliberadamente más restrictivo que el validador JSON Schema interno: por ejemplo,
    impide enums compuestos como enum:[[]], que el proveedor ya rechazó.
    """
    if not isinstance(schema, dict):
        raise BackendRequestSchemaViolation(f"schema node is not an object at {path}")
    unsupported = set(schema) - _OPENAI_STRUCTURED_OUTPUT_ALLOWED_KEYWORDS
    if unsupported:
        raise BackendRequestSchemaViolation(
            f"unsupported OpenAI Structured Outputs keywords at {path}: {sorted(unsupported)}")
    validate_strict_schema(schema, path)
    if "enum" in schema and any(isinstance(value, (list, dict)) for value in schema["enum"]):
        raise BackendRequestSchemaViolation(f"compound enum values are not allowed for OpenAI strict at {path}")
    for name, child in schema.get("properties", {}).items():
        validate_openai_structured_output_subset(child, f"{path}.properties.{name}")
    if "items" in schema:
        validate_openai_structured_output_subset(schema["items"], f"{path}.items")


def _json_type(value):
    if value is None: return "null"
    if isinstance(value, bool): return "boolean"
    if isinstance(value, str): return "string"
    if isinstance(value, int): return "integer"
    if isinstance(value, float): return "number"
    if isinstance(value, list): return "array"
    if isinstance(value, dict): return "object"
    return type(value).__name__


def _response_violation(message, path, rule, expected, received):
    error = BackendResponseSchemaViolation(message)
    error.failure_stage = "response_schema"
    error.validation_path = path
    error.schema_rule = rule
    error.expected_type = expected
    error.received_type = received
    return error


def validate_response_payload(payload, schema, path="$"):
    """Valida offline la instancia para distinguir contrato de respuesta y parser."""
    if not isinstance(schema, dict):
        raise _response_violation("invalid local schema node", path, "schema_node", "object", _json_type(schema))
    types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
    primitive = {"object": dict, "array": list, "string": str, "integer": int, "number": (int, float), "boolean": bool, "null": type(None)}
    if not any(isinstance(payload, primitive[item]) and not (item in {"integer", "number"} and isinstance(payload, bool)) for item in types):
        raise _response_violation("response type mismatch", path, "type", "|".join(types), _json_type(payload))
    if "enum" in schema and payload not in schema["enum"]:
        raise _response_violation("response enum mismatch", path, "enum", "enum", _json_type(payload))
    if "object" in types:
        if set(payload) != set(schema["properties"]):
            raise _response_violation("response object keys mismatch", path, "properties", "exact required properties", "object")
        for key, child in schema["properties"].items(): validate_response_payload(payload[key], child, f"{path}.{key}")
    if "array" in types:
        for index, value in enumerate(payload): validate_response_payload(value, schema["items"], f"{path}[{index}]")

def reasoning_response_schema(reference_map=None, capabilities=None):
    """Schema strict con aliases compactos, limitado al EvidenceContext seleccionado."""
    event_refs = list(reference_map.aliases("event")) if reference_map else []
    correlation_refs = list(reference_map.aliases("correlation")) if reference_map else []
    finding_refs = list(reference_map.aliases("finding")) if reference_map else []
    paths = list(reference_map.allowed_paths) if reference_map else []
    def nullable_enum(values): return {"type": ["string", "null"], "enum": [*values, None] if values else [None]}
    def ref_array(values): return {"type": "array", "items": {"type": "string", "enum": values or [""]}}
    compact_path = {"type": "object", "additionalProperties": False,
        "properties": {"event_ref": nullable_enum(event_refs), "correlation_ref": nullable_enum(correlation_refs),
            "finding_ref": nullable_enum(finding_refs), "path": nullable_enum(paths)},
        "required": ["event_ref", "correlation_ref", "finding_ref", "path"]}
    statement = {"type": "object", "additionalProperties": False,
        "properties": {"statement": {"type": "string"}, "supporting_event_refs": ref_array(event_refs),
        "supporting_correlation_refs": ref_array(correlation_refs), "supporting_finding_refs": ref_array(finding_refs),
        "evidence_paths": {"type": "array", "items": compact_path},
        "confidence": {"type": "string", "enum": ["low", "moderate", "high"]}, "limitations": {"type": "array", "items": {"type": "string"}}},
        "required": ["statement", "supporting_event_refs", "supporting_correlation_refs", "supporting_finding_refs", "evidence_paths", "confidence", "limitations"]}
    assessment_support = {"supporting_event_refs": ref_array(event_refs),
        "supporting_correlation_refs": ref_array(correlation_refs), "supporting_finding_refs": ref_array(finding_refs),
        "limitations": {"type": "array", "items": {"type": "string"}}}
    mitre = {"type": "object", "additionalProperties": False, "properties": {"technique_id": {"type": ["string", "null"]},
        "technique_name": {"type": ["string", "null"]}, "confidence": {"type": "string", "enum": ["low", "moderate", "high"]}, **assessment_support},
        "required": ["technique_id", "technique_name", "confidence", "supporting_event_refs", "supporting_correlation_refs", "supporting_finding_refs", "limitations"]}
    ioc = {"type": "object", "additionalProperties": False, "properties": {"value": {"type": "string"}, "artifact_type": {"type": "string"},
        "classification": {"type": "string", "enum": ["Observed", "Unknown", "Benign/Expected", "Suspicious", "Confirmed Malicious"]},
        "confidence": {"type": "string", "enum": ["low", "moderate", "high"]}, **assessment_support},
        "required": ["value", "artifact_type", "classification", "confidence", "supporting_event_refs", "supporting_correlation_refs", "supporting_finding_refs", "limitations"]}
    properties = {
        "facts": {"type": "array", "items": statement}, "inferences": {"type": "array", "items": statement},
        "hypotheses": {"type": "array", "items": statement}, "conclusions": {"type": "array", "items": statement},
        "proposed_classification": {"type": "string", "enum": ["Benign / Expected", "Suspicious / Requires Investigation", "Confirmed Security Incident", "Insufficient Evidence"]},
        "proposed_priority": {"type": "string", "enum": ["low", "medium", "high"]}, "confidence": {"type": "string", "enum": ["low", "moderate", "high"]},
        "false_positive_considerations": {"type": "array", "items": statement}, "missing_evidence": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}}}
    if capabilities and capabilities.mitre_mapping: properties["mitre_mappings"] = {"type": "array", "items": mitre}
    if capabilities and capabilities.ioc_assessment: properties["ioc_assessments"] = {"type": "array", "items": ioc}
    schema = {"type": "object", "additionalProperties": False, "properties": properties, "required": list(properties)}
    validate_openai_structured_output_subset(schema)
    return schema
