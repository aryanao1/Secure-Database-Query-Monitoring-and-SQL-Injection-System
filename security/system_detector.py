import re


def detect_sql_injection(query):
    """
    Check a SQL query for common SQL injection patterns.

    Returns:
        (is_suspicious, reason)
    """

    normalized_query = query.lower().strip()

    patterns = {
        "OR condition": r"\bor\s+[\w'\"()]+\s*=\s*[\w'\"()]+",
        "SQL comment": r"(--|#|/\*)",
        "UNION SELECT": r"\bunion\s+(all\s+)?select\b",
        "DROP TABLE": r"\bdrop\s+table\b",
        "DELETE without WHERE": r"^\s*delete\s+from\s+\w+\s*;?\s*$",
        "Always true condition": r"\b1\s*=\s*1\b",
    }

    for reason, pattern in patterns.items():
        if re.search(pattern, normalized_query):
            return True, reason

    return False, "No suspicious pattern detected"