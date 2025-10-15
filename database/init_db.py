from database.models import Database

def initialize_database():
    db = Database()
    print("Database initialized successfully!")
    print("Tables created: devices, events, alerts, rules, licenses, system_logs")
    return db

if __name__ == "__main__":
    initialize_database()
