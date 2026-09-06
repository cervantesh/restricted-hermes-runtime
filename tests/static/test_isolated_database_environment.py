from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UNSAFE_FALLBACK = 'os.environ.get("RESTRICTED_RUNTIME_TEST_DATABASE_URL") or os.environ.get("DATABASE_URL")'


def test_database_backed_tests_never_adopt_an_ambient_application_database():
    offenders = [
        str(path.relative_to(ROOT))
        for path in (ROOT / "tests").rglob("test_*.py")
        if path != Path(__file__).resolve()
        and UNSAFE_FALLBACK in path.read_text(encoding="utf-8")
    ]
    assert offenders == [], (
        "database-backed tests must require the explicit isolated-test variable; "
        f"ambient DATABASE_URL fallback found in {offenders}"
    )
