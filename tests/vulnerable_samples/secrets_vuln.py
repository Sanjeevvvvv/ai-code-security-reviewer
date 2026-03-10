import os


AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyzABCD1234"

DB_PASSWORD = "SuperSecretP@ssw0rd"


def get_db_url():
    # Intentional hardcoded credential usage
    host = os.getenv("DB_HOST", "localhost")
    return f"postgresql://admin:{DB_PASSWORD}@{host}:5432/app"


def use_tokens():
    print("Using GH token:", GITHUB_TOKEN[:8] + "...")
    print("Using AWS key:", AWS_ACCESS_KEY_ID[:8] + "...")

