from flask import Flask
from database.database import (
    get_connection,
    log_query,
    log_security_alert
)
from security.system_detector import detect_sql_injection

app = Flask(__name__)


@app.route("/")
def home():
    return """
    <h1>Secure Database Query Monitoring System</h1>
    <p>System is running successfully.</p>
    <p>Database connection is active.</p>
    """


@app.route("/test-query")
def test_query():
    query = "SELECT * FROM users"

    is_suspicious, reason = detect_sql_injection(query)

    if is_suspicious:
        return f"""
        <h1>Query Blocked</h1>
        <p>Suspicious SQL detected: {reason}</p>
        """ 

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(query)
    results = cursor.fetchall()

    cursor.close()
    connection.close()

    log_query(
        user_id=2,
        query_text=query,
        query_type="SELECT",
        status="SAFE"
    )

    return f"""
    <h1>Query Executed Successfully</h1>
    <p>Query: {query}</p>
    <p>Rows returned: {len(results)}</p>
    <p>Query has been logged.</p>
    """


@app.route("/test-injection")
def test_injection():
    query = "SELECT * FROM users WHERE username = 'admin' OR 1=1"

    is_suspicious, reason = detect_sql_injection(query)

    if is_suspicious:

        # Record the suspicious query
        log_query(
            user_id=2,
            query_text=query,
            query_type="SELECT",
            status="BLOCKED"
        )

        # Get the ID of the query we just logged
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM queries "
            "WHERE user_id = %s "
            "AND query_text = %s "
            "ORDER BY id DESC LIMIT 1",
            (2, query)
        )

        result = cursor.fetchone()

        cursor.close()
        connection.close()

        if result:
            query_id = result[0]

            log_security_alert(
                query_id=query_id,
                alert_type="SQL Injection",
                severity="HIGH",
                description=reason,
                action_taken="BLOCKED"
            )

        return f"""
        <h1>🚨 Query Blocked</h1>
        <p>Potential SQL injection detected.</p>
        <p>Reason: {reason}</p>
        <p>The query was NOT executed.</p>
        <p>Security alert has been recorded.</p>
        """

    return "<h1>Query considered safe.</h1>"


if __name__ == "__main__":
    app.run(debug=True)