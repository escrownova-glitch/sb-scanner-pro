"""
SB Scanner — AWS Elastic Beanstalk domain generator.
Tiered combinatorial generation for {prefix}.{region}.elasticbeanstalk.com domains.
Authorized use only.

Generation tiers (highest-likelihood first):
  T1: {prefix}                    → plain environment name
  T2: {prefix}-env                → AWS console default suffix
  T3: {prefix}-{env_tag}          → labelled environments
  T4: {prefix}-{n}                → numbered instances (1-20)
  T5: {p1}-{p2}                   → two-word compound names
  T6: {prefix}-{env_tag}-{n}      → three-part compounds (n 1-5)

Capacity (all tiers, deduplicated):
  fast=True  (4 regions)   ≈ 290k unique domains
  fast=False (21 regions)  ≈ 1.5M unique domains
"""

import itertools
from typing import Iterator

_EB_PREFIXES = [
    # Generic names
    "app", "api", "web", "www", "main", "server", "platform",
    # Environment labels
    "prod", "production", "staging", "stage", "dev", "development",
    "test", "demo", "beta", "alpha", "uat", "qa", "sandbox",
    # Combined prefixes (api-env pattern)
    "api-prod", "api-dev", "api-staging", "api-test",
    "app-prod", "app-dev", "app-staging",
    "web-prod", "web-dev", "web-staging",
    # Service tiers
    "backend", "backend-prod", "backend-dev", "backend-staging",
    "frontend", "frontend-prod",
    "admin", "admin-prod", "portal", "dashboard",
    "service", "services", "microservice",
    "mobile", "mobile-api", "mobile-backend",
    "rest", "graphql", "gateway", "proxy", "edge",
    "worker", "jobs", "scheduler", "queue",
    # Common product names
    "myapp", "myapi", "mysite", "my-app", "my-api",
    "core", "internal", "private", "secure",
    "auth", "login", "oauth", "identity",
    "shop", "store", "ecommerce", "cart",
    "data", "analytics", "reporting", "metrics",
    "chat", "messaging", "notifications",
    "media", "files", "uploads", "cdn",
    # Numbered variants
    "app1", "app2", "app3", "api1", "api2", "api3",
    "web1", "web2", "web3", "server1", "server2",
    # Version-tagged
    "v1", "v2", "v3", "v1-api", "v2-api", "v1-app", "v2-app",
    # User / account services
    "account", "accounts", "user", "users", "profile", "profiles",
    "customer", "customers",
    # Payment / billing
    "payment", "payments", "checkout", "billing", "invoice", "subscription",
    # Notification / event services
    "notification", "webhook", "webhooks", "event", "events", "callback",
    # Search / recommendation
    "search", "recommend", "recommendation",
    # Data / streaming
    "ingest", "pipeline", "stream", "etl",
    # ML / AI services
    "ml", "ai", "model", "inference", "predict",
    # Business ops
    "crm", "erp", "hr", "helpdesk", "support", "ticket", "ticketing",
    "report",
    # SSO / security endpoints
    "sso", "saml", "jwt", "token",
    # Health / ops
    "health", "status", "monitor", "monitoring", "config", "deploy",
    # Storage / assets
    "storage", "asset", "assets", "static", "image", "images",
    # Numbered env combos
    "dev1", "dev2", "staging1", "staging2", "prod1", "prod2",
    # Geo-prefixed API endpoints
    "us-api", "eu-api", "asia-api", "global-api",
    # Service-specific API combos
    "data-api", "auth-api", "user-api", "admin-api",
    "payment-api", "search-api", "core-api", "public-api",
    # Framework / tech stack hints
    "django", "flask", "node", "rails", "express", "spring",
    # More general names
    "hub", "central", "cloud", "integration",
    # Backend combos
    "backend-api", "service-api", "platform-api",
    # Additional env combos
    "api-uat", "app-uat", "api-sandbox", "app-sandbox",
    "api-qa", "app-qa", "api-demo", "app-demo",
    # Common internal tool names
    "console", "management", "ops", "devops", "infra",
    "ci", "cd", "build", "deploy-api",
    # Customer-facing
    "client", "clients", "partner", "partners",
    "vendor", "vendors",
]

# Common EB environment name suffixes (appended to prefixes in T3)
_EB_ENV_TAGS = [
    "prod", "production", "staging", "stage",
    "dev", "development", "test", "demo",
    "beta", "alpha", "uat", "qa", "sandbox",
    "release", "rc", "live", "preview",
    "latest", "main",
]

# Numbered suffix pool for T4 and T6
_EB_NUMBERS = list(range(1, 21))   # 1-20

# All AWS regions with Elastic Beanstalk support
_EB_REGIONS_ALL = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3",
    "eu-central-1", "eu-north-1", "eu-south-1",
    "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-east-1",
    "sa-east-1", "ca-central-1", "me-south-1", "af-south-1",
]

# Top 4 cover 80%+ of public EB deployments
_EB_REGIONS_FAST = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]


def _eb_stream(fast: bool = True) -> Iterator[str]:
    """
    Lazy generator — yields EB URLs in decreasing likelihood order.
    Caller breaks at any point; subsequent tiers are never computed.
    """
    regions = _EB_REGIONS_FAST if fast else _EB_REGIONS_ALL
    seen: set[str] = set()

    def _emit(subdomain: str, region: str) -> str | None:
        key = f"{subdomain}.{region}"
        if key in seen:
            return None
        seen.add(key)
        return f"http://{key}.elasticbeanstalk.com"

    # T1 — plain prefix
    for prefix, region in itertools.product(_EB_PREFIXES, regions):
        url = _emit(prefix, region)
        if url:
            yield url

    # T2 — AWS console default suffix "-env"
    for prefix, region in itertools.product(_EB_PREFIXES, regions):
        url = _emit(f"{prefix}-env", region)
        if url:
            yield url

    # T3 — prefix + env label
    for prefix, tag, region in itertools.product(_EB_PREFIXES, _EB_ENV_TAGS, regions):
        url = _emit(f"{prefix}-{tag}", region)
        if url:
            yield url

    # T4 — prefix + number 1-20
    for prefix, n, region in itertools.product(_EB_PREFIXES, _EB_NUMBERS, regions):
        url = _emit(f"{prefix}-{n}", region)
        if url:
            yield url

    # T5 — two-word compound names (p1-p2, p1 ≠ p2)
    for p1, p2, region in itertools.product(_EB_PREFIXES, _EB_PREFIXES, regions):
        if p1 == p2:
            continue
        url = _emit(f"{p1}-{p2}", region)
        if url:
            yield url

    # T6 — three-part: prefix-tag-number (first 5 numbers only)
    for prefix, tag, n, region in itertools.product(
        _EB_PREFIXES, _EB_ENV_TAGS, _EB_NUMBERS[:5], regions
    ):
        url = _emit(f"{prefix}-{tag}-{n}", region)
        if url:
            yield url


def generate_eb_domains(fast: bool = True, count: int = 0) -> list[str]:
    """
    Return Elastic Beanstalk candidate URLs, shuffled for run-to-run variation.

    fast=True  → 4 top regions  (≈ 290k unique domains across all tiers)
    fast=False → all 21 regions (≈ 1.5M unique domains across all tiers)
    count      → max domains to return; 0 = return everything available.

    Generation is lazy (stops at count), then shuffled — so every run hits
    different targets first while still guaranteeing tier coverage in the pool.
    """
    import random
    results: list[str] = []
    for url in _eb_stream(fast=fast):
        results.append(url)
        if count > 0 and len(results) >= count:
            break
    random.shuffle(results)
    return results


if __name__ == "__main__":
    fast = generate_eb_domains(fast=True, count=0)
    full = generate_eb_domains(fast=False, count=0)
    print(f"Fast (4 regions, all tiers): {len(fast):,} domains")
    print(f"Full (21 regions, all tiers): {len(full):,} domains")
    for d in fast[:8]:
        print(f"  {d}")
    print("  ...")
