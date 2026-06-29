from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings.

    The app runs with SQLite by default so the project is free and easy to run.
    Set DATABASE_URL=postgresql+psycopg2://vuln:vuln@db:5432/vulnprio when using Docker Compose.
    """

    database_url: str = "sqlite:///./vulnprio.db"
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    cisa_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cisa_kev_github_fallback_url: str = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
