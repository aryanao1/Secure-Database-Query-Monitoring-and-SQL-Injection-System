import mysql.connector


def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="projectabc",
        database="secure_db"
    )


def log_query(user_id, query_text, query_type, status):
    connection = get_connection()
    cursor = connection.cursor()

    sql = """
        INSERT INTO queries
        (user_id, query_text, query_type, status)
        VALUES (%s, %s, %s, %s)
    """

    cursor.execute(
        sql,
        (user_id, query_text, query_type, status)
    )

    connection.commit()

    cursor.close()
    connection.close()


def log_security_alert(
    query_id,
    alert_type,
    severity,
    description,
    action_taken
):
    connection = get_connection()
    cursor = connection.cursor()

    sql = """
        INSERT INTO security_alerts
        (query_id, alert_type, severity, description, action_taken)
        VALUES (%s, %s, %s, %s, %s)
    """

    cursor.execute(
        sql,
        (
            query_id,
            alert_type,
            severity,
            description,
            action_taken
        )
    )

    connection.commit()

    cursor.close()
    connection.close()