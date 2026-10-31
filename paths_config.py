"""
SB - Professional Security Scanner
Path definitions for all scan modules.
Sources: exploit-db.com, vulnhub.com writeups, manual research.
"""

LARAVEL_PATHS = [
    # ── .env variants — root (highest hit rate) ───────────────────────────────
    "/.env",
    "/.env.backup",
    "/.env.bak",
    "/.env.old",
    "/.env.dev",
    "/.env.prod",
    "/.env.local",
    "/.env.staging",
    "/.env.example",
    "/.env.production",
    "/.env.development",
    # ── .env in top sub-paths (app, API, backend layouts) ────────────────────
    "/api/.env",
    "/public/.env",
    "/backend/.env",
    # ── Laravel internals ─────────────────────────────────────────────────────
    "/storage/logs/laravel.log",
    "/_ignition/health-check",
    "/_ignition/execute-solution",
    "/telescope",
    "/telescope/api/requests",
    "/horizon",
    "/horizon/api/stats",
    "/log-viewer",
    "/pulse",
    "/_debugbar/clockwork",
    "/clockwork",
    "/nova",
    "/artisan",
    # ── CVE-2017-9841 phpunit RCE — top 3 install paths ──────────────────────
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
    "/vendor/phpunit/src/Util/PHP/eval-stdin.php",
]

JOOMLA_PATHS = [
    "/administrator/",
    "/administrator/index.php",
    "/administrator/manifests/files/joomla.xml",
    "/includes/version.php",
    "/language/en-GB/en-GB.xml",
    "/joomla.xml",
    "/configuration.php",
    "/libraries/joomla/version.php",
    # CVE-2023-23752 — public API users / config disclosure
    "/api/index.php/v1/users",
    "/api/index.php/v1/users?public=true",
    "/api/index.php/v1/config/application",
    "/api/index.php/v1/config/application?public=true",
]

WORDPRESS_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/wp-admin/admin-ajax.php",
    "/wp-json/wp/v2/users",
    "/wp-json/wp/v2/users?per_page=100",
    "/wp-json/",
    "/xmlrpc.php",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.txt",
    "/wp-config.php.old",
    "/wp-content/debug.log",
    "/wp-content/uploads/",
    "/?author=1",
    "/?author=2",
    "/?feed=rss2",
    "/wp-admin/install.php",
    # CVE-2024-25600 Bricks Builder — unauth RCE
    "/wp-content/themes/bricks/",
    # CVE-2024-1071 Ultimate Member SQLi
    "/wp-content/plugins/ultimate-member/readme.txt",
    # CVE-2024-10924 Really Simple Security auth bypass
    "/wp-content/plugins/really-simple-ssl/readme.txt",
    # High-prevalence plugins
    "/wp-content/plugins/elementor/readme.txt",
    "/wp-content/plugins/woocommerce/readme.txt",
]

MAGENTO_PATHS = [
    "/downloader/",
    "/app/etc/local.xml",
    "/app/etc/env.php",
    "/app/etc/config.php",
    "/var/log/exception.log",
    "/var/log/system.log",
    "/index.php/admin/",
    "/index.php/downloader/",
    "/admin/",
    "/backend/",
]

SHELL_PATHS = [
    # Known shell names at root
    "/shell.php",
    "/cmd.php",
    "/c99.php",
    "/r57.php",
    "/b374k.php",
    "/wso.php",
    "/alfa.php",
    "/indoxploit.php",
    "/webshell.php",
    "/backdoor.php",
    # Upload directory shells
    "/uploads/shell.php",
    "/uploads/cmd.php",
    "/images/shell.php",
    # WordPress upload shells
    "/wp-content/uploads/shell.php",
    "/wp-content/uploads/wso.php",
    "/wp-content/plugins/shell.php",
]

EXPOSURE_PATHS = [
    # JS bundles — hardcoded API keys in compiled frontend code
    "/static/js/main.js",
    "/static/js/app.js",
    "/assets/js/app.js",
    "/build/static/js/main.js",
    # Spring Boot Actuator
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
    "/actuator/mappings",
    "/actuator/beans",
    "/actuator/configprops",
    "/actuator/httptrace",
    # Swagger / API docs
    "/swagger.json",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    # SSH private keys
    "/.ssh/id_rsa",
    "/.ssh/id_ecdsa",
    "/.ssh/id_ed25519",
    "/.ssh/authorized_keys",
    # Grafana CVE-2021-43798
    "/grafana/",
    "/grafana/api/datasources",
    # Jupyter Notebook
    "/jupyter/",
    "/api/kernels",
    # Jenkins
    "/jenkins/",
    "/jenkins/script",
    "/jenkins/api/json",
    # Tomcat
    "/manager/html",
    "/host-manager/html",
    # Elasticsearch
    "/_cat/indices",
    "/_cluster/health",
    "/_nodes",
    # Logs
    "/logs/",
    "/error_log",
    "/debug.log",
    "/application.log",
    # Kubernetes
    "/api/v1/namespaces",
    "/api/v1/pods",
    "/api/v1/secrets",
    # Misc infra
    "/server-status",
    "/server-info",
    "/docker-compose.yml",
    "/.dockerenv",
    # Atlassian Confluence
    "/server-info.action",
    "/setup/setupadministrator!default.action",
    "/rest/api/space",
    "/rest/api/user/current",
    # GitLab
    "/-/admin",
    "/-/metrics",
    "/api/v4/users",
    "/api/v4/projects",
    "/api/v4/version",
    # TeamCity — CVE-2024-27198 / CVE-2024-27199
    "/app/rest/users",
    "/app/rest/users/id:1/tokens/RPC2",
    "/app/rest/server",
    # ConnectWise ScreenConnect — CVE-2024-1709
    "/SetupWizard.aspx",
    "/SetupWizard.aspx/anything",
    # Adobe ColdFusion — CVE-2023-26360 / CVE-2024-20767
    "/CFIDE/administrator/",
    "/CFIDE/administrator/enter.cfm",
    "/cf_scripts/scripts/ajax/",
    # Apache Solr
    "/solr/admin/cores",
    "/solr/admin/info/system",
    "/solr/admin/zookeeper",
    # Drupal
    "/core/install.php",
    "/CHANGELOG.txt",
    "/sites/default/settings.php.bak",
    # CrushFTP — CVE-2024-4040
    "/WebInterface/function/",
    # Ivanti Connect Secure — CVE-2024-21887 / CVE-2023-46805
    "/dana-na/auth/url_default/welcome.cgi",
    "/api/v1/totp/user-backup-code",
    # Citrix — CVE-2023-4966
    "/oauth/idp/.well-known/openid-configuration",
    "/vpn/index.html",
    "/citrix/StoreWeb/",
    # VMware vCenter — CVE-2024-37079 / CVE-2024-38812
    "/sdk",
    "/ui/",
    "/websso/SAML2/SSO/",
    # Veeam Backup — CVE-2024-40711
    "/api/oauth2/token",
    "/api/v1/backupServers",
    # PHP-CGI — CVE-2024-4577
    "/cgi-bin/php-cgi.exe",
    "/cgi-bin/php.cgi",
    "/cgi-bin/php",
    # Ollama — CVE-2024-37032
    "/api/tags",
    "/api/show",
    # Fortinet FortiOS / FortiManager — CVE-2024-47575
    "/remote/login",
    "/api/v1/cmdb/system/admin/",
    # Cleo MFT — CVE-2024-55956
    "/Synchronization",
    "/api/configurations",
    # SharePoint — CVE-2024-38094
    "/_layouts/15/start.aspx",
    "/_api/web/lists",
    # VCS leaks
    "/.git/HEAD",
    "/.git/config",
    "/.git/COMMIT_EDITMSG",
    # phpMyAdmin / Adminer
    "/phpmyadmin/",
    "/phpMyAdmin/",
    "/pma/",
    "/adminer.php",
    "/adminer/",
    "/db/adminer.php",
    # Backup archives and SQL dumps
    "/backup.zip",
    "/backup.sql",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/database.sql",
    "/site.zip",
    # Credential files
    "/.htpasswd",
    "/.htaccess",
    "/.aws/credentials",
    "/.aws/config",
    "/.git-credentials",
    "/.netrc",
    "/credentials.json",
    "/service_account.json",
    # ASP.NET / IIS
    "/elmah.axd",
    "/trace.axd",
    "/web.config",
    "/appsettings.json",
    "/appsettings.Production.json",
    # Framework config files
    "/config/database.php",
    "/config/database.yml",
    "/config/secrets.yml",
    "/app/config/parameters.yml",
    # CI/CD config
    "/.travis.yml",
    "/.circleci/config.yml",
    "/Jenkinsfile",
    # GraphQL endpoints
    "/graphql",
    "/graphiql",
    "/api/graphql",
    # Monitoring / status panels
    "/nginx_status",
    "/metrics",
    "/portainer/",
    # Firebase
    "/firebase-debug.log",
    "/__/firebase/init.json",
    # HashiCorp Vault
    "/v1/sys/health",
    "/v1/sys/seal-status",
    "/v1/auth/token/lookup-self",
    # Additional .env — cloud platform specific
    "/.env.database",
    "/.env.secret",
    "/.env.heroku",
    "/.env.render",
    "/.env.railway",
    "/.env.shopify",
    # PHP info / test pages (exposure, not shells)
    "/phpinfo.php",
    "/info.php",
    # Next.js — CVE-2025-29927 (middleware auth bypass)
    "/_next/static/chunks/main.js",
    # Vite dev server leak — CVE-2025-30208 / CVE-2025-32395
    "/@fs/etc/passwd",
    # Craft CMS CVE-2024-56145 / CVE-2025-32432
    "/actions/users/login",
    "/index.php?p=admin/login",
    # PAN-OS GlobalProtect — CVE-2024-3400
    "/global-protect/login.esp",
    # GeoServer CVE-2024-36401
    "/geoserver/ows",
    "/geoserver/web/",
    # Telerik CVE-2024-6327 / CVE-2024-4358
    "/Telerik.Web.UI.SpellCheckHandler.axd",
    "/Telerik.Web.UI.WebResource.axd",
    # Zimbra CVE-2024-45519
    "/zimbraAdmin/",
    "/service/soap",
    # Exposed WSDL / SOAP
    "/?wsdl",
    # Docker socket via HTTP proxy (version-agnostic ping)
    "/_ping",
    # Shell history files
    "/.bash_history",
    "/.zsh_history",
    # Keycloak CVE-2024-4540
    "/realms/master/.well-known/openid-configuration",
    # Ivanti Connect Secure additional paths
    "/dana-ws/namedusers",
    # ── Package manager auth tokens (high hit rate 2024-2025) ─────────────────
    "/.npmrc",
    "/.pypirc",
    "/.gem/credentials",
    "/composer.auth.json",
    # ── Infrastructure-as-Code secrets ────────────────────────────────────────
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
    "/serverless.yml",
    "/serverless.yaml",
    "/.serverless/serverless-state.json",
    # ── Cloud platform config files ───────────────────────────────────────────
    "/vercel.json",
    "/netlify.toml",
    "/app.yaml",
    "/app.yml",
    "/.platform/env",
    # ── Docker auth ───────────────────────────────────────────────────────────
    "/.docker/config.json",
    "/docker-compose.override.yml",
    # ── Rails secrets ─────────────────────────────────────────────────────────
    "/config/secrets.yml",
    "/config/master.key",
    "/config/credentials.yml.enc",
    # ── Well-known discovery endpoints ───────────────────────────────────────
    "/.well-known/security.txt",
    # ── Node.js / frontend project files ─────────────────────────────────────
    "/package.json",
    "/.env.local",
    "/.env.test",
    # ── Cloud metadata SSRF probes (hit if server-side proxy present) ─────────
    "/latest/meta-data/iam/security-credentials/",
    "/metadata/v1/",
    "/computeMetadata/v1/",
    # ── Exposed API health/debug with internal config ─────────────────────────
    "/api/v1/config",
    "/api/v2/config",
    "/api/health",
    "/api/debug",
    "/api/version",
    "/api/env",
    # ── GitHub Actions / CI secrets exposure ─────────────────────────────────
    "/.github/workflows/deploy.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/release.yml",
    # ── mongo-express unauthorized MongoDB web UI ─────────────────────────────
    "/mongo-express",
    "/mongo-express/",
    # ── Cloud metadata IMDS (direct access — misconfigured reverse proxies) ───
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    "/latest/dynamic/instance-identity/document",
    "/latest/user-data",
    "/computeMetadata/v1/",
    "/computeMetadata/v1/instance/service-accounts/default/token",
    "/computeMetadata/v1/project/",
    "/metadata/v1/",
    "/metadata/v1/id",
    "/metadata/instance?api-version=2021-02-01",
    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    # ── Kubernetes API — cluster-level exposure ────────────────────────────────
    "/api/v1/secrets",
    "/api/v1/configmaps",
    "/api/v1/serviceaccounts",
    "/api/v1/nodes",
    "/apis/apps/v1/deployments",
    "/apis/rbac.authorization.k8s.io/v1/clusterroles",
    "/api",
    # ── .kube config exposure ─────────────────────────────────────────────────
    "/.kube/config",
    "/.kube/cache/discovery/",
    # ── Shell history — credentials in command history ────────────────────────
    "/.bash_history",
    "/.zsh_history",
    "/.ash_history",
    "/.sh_history",
    "/.mysql_history",
    "/.psql_history",
    "/.python_history",
    # ── SSH exposure ──────────────────────────────────────────────────────────
    "/.ssh/id_rsa",
    "/.ssh/id_ecdsa",
    "/.ssh/id_ed25519",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/.ssh/config",
    "/id_rsa",
    "/server.key",
    "/private.key",
    "/ssl.key",
    "/domain.key",
    # ── Package manager auth ──────────────────────────────────────────────────
    "/.npmrc",
    "/.pypirc",
    "/.gem/credentials",
    "/composer.auth.json",
    "/yarn.lock",
    "/Pipfile",
    "/Pipfile.lock",
    # ── Additional IaC / cloud config ─────────────────────────────────────────
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/terraform.tfstate",
    "/serverless.yml",
    "/serverless.yaml",
    "/.serverless/serverless-state.json",
    "/.ansible/credentials",
    "/ansible.cfg",
    "/inventory",
    "/hosts",
    "/Puppetfile",
    # ── Prometheus / metrics exposure ─────────────────────────────────────────
    "/metrics",
    "/prometheus/api/v1/targets",
    "/prometheus/api/v1/rules",
    "/api/v1/targets",
    "/api/v1/rules",
    "/api/v1/alerts",
    # ── Grafana datasources (CVE-2021-43798 path traversal pattern) ───────────
    "/grafana/api/datasources",
    "/grafana/api/org/users",
    "/grafana/api/admin/users",
    "/api/datasources",
    "/api/org/users",
    # ── Airflow DAG / config exposure ─────────────────────────────────────────
    "/api/v1/dags",
    "/api/v1/pools",
    "/api/v1/connections",
    "/api/v1/variables",
    # ── Jupyter / JupyterLab ──────────────────────────────────────────────────
    "/api/sessions",
    "/api/terminals",
    "/tree",
    # ── Portainer ─────────────────────────────────────────────────────────────
    "/api/endpoints",
    "/api/status",
    "/api/users",
    # ── RabbitMQ management API ───────────────────────────────────────────────
    "/api/overview",
    "/api/nodes",
    "/api/connections",
    "/api/queues",
    # ── Firebase ──────────────────────────────────────────────────────────────
    "/__/firebase/init.json",
    "/__/firebase/init.js",
    "/firebase-debug.log",
    # ── SQL / database dumps ──────────────────────────────────────────────────
    "/backup.sql",
    "/dump.sql",
    "/database.sql",
    "/db.sql",
    "/db_backup.sql",
    "/site.sql",
    "/export.sql",
    "/data.sql",
    "/mysql.sql",
    "/wordpress.sql",
    # ── Archive / backup files ────────────────────────────────────────────────
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.tar",
    "/site.zip",
    "/www.zip",
    "/web.zip",
    "/html.tar.gz",
    "/public_html.zip",
    "/old.zip",
    "/archive.zip",
    # ── GCP service account key files ─────────────────────────────────────────
    "/service_account.json",
    "/credentials.json",
    "/gcp_credentials.json",
    "/google_credentials.json",
    "/serviceaccount.json",
    # ── Azure / cloud-specific ────────────────────────────────────────────────
    "/.azure/credentials",
    "/.azure/config",
    "/cloud-config.yml",
    # ── More env variants ─────────────────────────────────────────────────────
    "/.env.test",
    "/.env.database",
    "/.env.secret",
    "/.env.heroku",
    "/.env.render",
    "/.env.railway",
    "/.env.fly",
    "/.env.prod",
    "/.env.production.local",
    "/.env.development.local",
    "/config/.env",
    "/src/.env",
    # ── Node / frontend project files ─────────────────────────────────────────
    "/package.json",
    "/package-lock.json",
    "/.env.local",
    # ── Web server config exposure ────────────────────────────────────────────
    "/nginx.conf",
    "/nginx/nginx.conf",
    "/etc/nginx/nginx.conf",
    "/apache2.conf",
    "/httpd.conf",
    # ── PHP debug / test pages ────────────────────────────────────────────────
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/debug.php",
    "/status.php",
    # ── Exposed configuration endpoints ───────────────────────────────────────
    "/config.json",
    "/config.yaml",
    "/config.yml",
    "/settings.json",
    "/settings.yml",
    "/application.yml",
    "/application.properties",
    "/bootstrap.yml",
    "/bootstrap.properties",
    # ── Additional shell variants ─────────────────────────────────────────────
    "/shell.php",
    "/cmd.php",
    "/c99.php",
    "/webshell.php",
    "/backdoor.php",
    "/uploads/shell.php",
    "/wp-content/uploads/shell.php",
    # ── Well-known / standard paths ───────────────────────────────────────────
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    # ── Additional CVE-specific paths ─────────────────────────────────────────
    # Apache Struts (CVE-2017-5638, CVE-2023-50164)
    "/struts/webconsole.html",
    "/index.action",
    "/upload.action",
    # Apache HTTP Server mod_status
    "/server-status",
    "/server-info",
    # Jenkins additional paths
    "/jenkins/credentials/store/system/domain/_/",
    "/jenkins/computer/api/json",
    "/jenkins/asynchPeople/api/json",
    # Spring Boot additional actuator
    "/actuator/logfile",
    "/actuator/threaddump",
    "/actuator/shutdown",
    "/actuator/gateway/routes",
    # CVE-2024-22024 Ivanti XXE
    "/dana-na/auth/saml-sso",
    # Minio S3 API
    "/minio/health/live",
    "/_minio/health/live",
    # Redis Commander
    "/redis-commander/",
    # pgAdmin
    "/pgadmin/",
    "/pgadmin4/",
    # InfluxDB
    "/influxdb/",
    "/query?q=SHOW+DATABASES",
    # Exposed CI/CD configs
    "/.gitlab-ci.yml",
    "/.drone.yml",
    "/bitbucket-pipelines.yml",
    "/Jenkinsfile",
    "/.circleci/config.yml",
    "/.travis.yml",
    "/.github/workflows/deploy.yml",
    "/.github/workflows/ci.yml",
    "/.github/workflows/release.yml",
    "/.github/workflows/main.yml",
    # Exposed Makefile / Dockerfile
    "/Makefile",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.override.yml",
    # ── 2025 actively exploited CVEs ──────────────────────────────────────────
    # SAP NetWeaver Visual Composer — CVE-2025-31324 (unauth file upload, in-wild)
    "/developmentserver/metadatauploader",
    "/developmentserver/",
    "/irj/portal",
    # Langflow — CVE-2025-3248 (unauth RCE via /api/v1/run)
    "/api/v1/run",
    "/api/v1/flows",
    "/api/v1/users",
    # Gladinet CentreStack — CVE-2025-30406 (deserialization RCE)
    "/api/json/user/GetUserById",
    "/portal/",
    # Commvault Command Center — CVE-2025-34028 (pre-auth RCE)
    "/commandcenter/",
    "/commandcenter/api/Instance",
    # Apache Tomcat — CVE-2025-24813 (partial PUT file upload / session deserialization)
    "/upload",
    "/DefaultServlet/",
    # ingress-nginx — CVE-2025-1974 (admission controller RCE)
    "/nginx-status",
    # Yelp elastalert2 / open Kibana
    "/api/alerts",
    "/api/alert_rules",
    # Exposed Swagger hub variants missed earlier
    "/api/swagger.json",
    "/rest/swagger.json",
    "/api/swagger-ui",
    # OpenAPI 3.1 / Scalar
    "/scalar",
    "/reference",
    "/.well-known/ai-plugin.json",
    # Exposed model serving APIs (LLM infra)
    "/v1/models",
    "/v1/completions",
    "/v1/chat/completions",
    "/ollama/api/tags",
    # n8n workflow automation (often left open)
    "/api/v1/workflows",
    "/n8n/api/v1/workflows",
    "/rest/workflows",
    # Exposed secrets scanning targets (2025 high-hit)
    "/.env.vault",
    "/secrets.yml",
    "/secrets.yaml",
    "/.secrets.baseline",
    "/vault.hcl",
    "/.vault-token",
]

PATH_MODULES = {
    "laravel":   LARAVEL_PATHS,
    "joomla":    JOOMLA_PATHS,
    "wordpress": WORDPRESS_PATHS,
    "magento":   MAGENTO_PATHS,
    "shell":     SHELL_PATHS,
    "exposure":  EXPOSURE_PATHS,
}
