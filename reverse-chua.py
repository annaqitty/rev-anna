import socket
import os
import sys
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# ANSI escape codes for colors
CYAN = '\033[96m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# Global variables
total_found_hosts_count = 0
output_file = 'OUTPUT_HOST.txt' 
results_set = set() 

def reverse_lookup(ip_address):
    """Performs reverse DNS lookup using socket."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        cleaned_hostname = hostname.replace("www.", "").replace('error:Invalid IPv4 address', '')\
                                   .replace('api.', '').replace('cpanel.', '').replace('webmail.', '')\
                                   .replace('webdisk.', '').replace('ftp.', '').replace('cpcalendars.', '')\
                                   .replace('cpcontacts.', '').replace('mail.', '').replace('ns1.', '')\
                                   .replace('ns2.', '').replace('ns3.', '').replace('ns4.', '')\
                                   .replace('autodiscover.', '')
        return cleaned_hostname
    except Exception as e:
        print(f"{RED}Error reversing {ip_address}{RESET}")
        return None

def get_additional_sources(domain):
    """
    Universal extractor using 5 API sources + internal brute-force.
    Returns a list of discovered subdomains/domains.
    """
    found = []
    
    # 1. Crt.sh (SSL Certificates)
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        for item in data:
            if 'name_value' in item:
                found.append(item['name_value'])
    except: pass

    # 2. Waybackurls (Archived Content)
    try:
        url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        for item in data.get('results', []):
            if 'url' in item:
                found.append(item['url'])
    except: pass

    # 3. GitHub Search (Repositories mentioning the domain)
    try:
        url = f"https://api.github.com/search/repositories?q={domain}&sort=updated&order=desc"
        resp = requests.get(url, timeout=5)
        data = resp.json()
        for item in data.get('items', []):
            if 'full_name' in item:
                found.append(item['full_name'])
    except: pass

    # 4. Pastebin Search (Simple Google Query)
    try:
        query = f"site:pastebin.com {domain}"
        url = f"https://www.google.com/search?q={query}"
        resp = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=5)
        # Extract links from HTML
        links = re.findall(r'href="(/url\?q=.*?)"', resp.text)
        for link in links:
             from urllib.parse import unquote
             final_url = unquote(link.split('=')[1])
             if 'pastebin.com' in final_url and domain.lower() in final_url.lower():
                 found.append(final_url)
    except: pass

    # 5. Internal Brute Force (Common Subdomains)
    # This is the "Best Method" addition. It tries common prefixes on the target.
    COMMON_SUBDOMAINS = ["www", "www1", "www2", "www3", "web", "web1", "web2", "web3", "webapp", "webapps", "webmail", "webmail1", "webmail2", "mail", "mail1", "mail2", "mail3", "email", "email1", "email2", "smtp", "smtp1", "smtp2", "smtps", "imap", "imap1", "imap2", "imap4", "imap4s", "pop", "pop3", "pop3s", "autodiscover", "autoconfig", "exchange", "owa", "outlook", "mx", "mx1", "mx2", "mx3", "mx4", "ns", "ns1", "ns2", "ns3", "ns4", "ns5", "ns6", "ns7", "ns8", "dns", "dns1", "dns2", "dns3", "dns4", "ftp", "ftp1", "ftp2", "ftp3", "sftp", "ftps", "files", "file", "file1", "file2", "file3", "storage", "storage1", "storage2", "download", "downloads", "upload", "uploads", "share", "shares", "backup", "backups", "archive", "archives", "mirror", "mirrors", "temp", "tmp", "hosting", "host", "host1", "host2", "host3", "server", "server1", "server2", "server3", "node", "node1", "node2", "node3", "cluster", "cluster1", "cluster2", "cpanel", "whm", "plesk", "panel", "control", "controlpanel", "cp", "cpcalendars", "cpcontacts", "webdisk", "api", "api1", "api2", "api3", "api-dev", "api-test", "api-stage", "api-staging", "api-prod", "graphql", "gql", "rest", "rest1", "service", "services", "backend", "frontend", "mobile", "m", "mobi", "app", "app1", "app2", "app3", "apps", "application", "applications", "gateway", "webhook", "webhooks", "callback", "callbacks", "event", "events", "stream", "streams", "realtime", "real-time", "ws", "wss", "socket", "sockets", "push", "notify", "notification", "notifications", "auth", "authentication", "login", "signin", "sign-in", "signup", "sign-up", "register", "registration", "sso", "oauth", "oauth2", "identity", "id", "idp", "saml", "scim", "token", "tokens", "session", "sessions", "account", "accounts", "user", "users", "member", "members", "profile", "profiles", "password", "password-reset", "reset", "verify", "verification", "2fa", "mfa", "multi-factor", "admin", "administrator", "administration", "admins", "manage", "management", "manager", "console", "dashboard", "dash", "config", "configs", "configuration", "settings", "setting", "setup", "install", "installer", "deploy", "deployment", "release", "upgrade", "migrate", "migration", "dev", "dev1", "dev2", "dev3", "develop", "development", "test", "test1", "test2", "test3", "testing", "qa", "qa1", "qa2", "uat", "uat1", "uat2", "stage", "stage1", "stage2", "staging", "staging1", "staging2", "sandbox", "sandbox1", "sandbox2", "demo", "demo1", "demo2", "preview", "preview1", "alpha", "beta", "canary", "experimental", "lab", "labs", "prod", "prod1", "prod2", "production", "production1", "live", "nightly", "snapshot", "trunk", "main", "master", "feature", "hotfix", "patch", "stable", "rc", "rc1", "rc2", "sprint", "milestone", "integration", "validation", "verification", "certification", "audit", "compliance", "security", "assessment", "review", "code-review", "peer-review", "self-review", "external-review", "internal-review", "third-party-review", "mainline", "release-track", "blog", "blogs", "news", "press", "media", "content", "cms", "cms1", "docs", "doc", "documentation", "wiki", "kb", "knowledgebase", "knowledge-base", "faq", "faqs", "guide", "guides", "handbook", "handbooks", "manual", "manuals", "reference", "references", "tutorial", "tutorials", "howto", "how-to", "getting-started", "get-started", "quickstart", "quick-start", "onboarding", "offboarding", "training", "course", "courses", "class", "classes", "academy", "education", "edu", "forum", "forums", "community", "communities", "group", "groups", "team", "teams", "club", "clubs", "society", "societies", "association", "associations", "organization", "organizations", "org", "orgs", "nonprofit", "non-profit", "ngo", "charity", "charities", "foundation", "foundations", "trust", "trusts", "endowment", "endowments", "grant", "grants", "funding", "sponsor", "sponsors", "patron", "patrons", "benefactor", "benefactors", "donor", "donors", "contributor", "contributors", "supporter", "supporters", "advocate", "advocates", "champion", "champions", "ambassador", "ambassadors", "evangelist", "evangelists", "social", "social1", "social2", "help", "helpdesk", "support", "ticket", "tickets", "feedback", "contact", "contact-us", "contactus", "about", "about-us", "aboutus", "shop", "shop1", "shop2", "store", "store1", "store2", "market", "marketplace", "cart", "checkout", "payment", "payments", "pay", "billing", "invoice", "invoices", "order", "orders", "customer", "customers", "accounting", "cdn", "cdn1", "cdn2", "static", "static1", "static2", "assets", "asset", "static-assets", "img", "image", "images", "js", "css", "fonts", "font", "video", "videos", "audio", "audios", "pdf", "pdfs", "secure", "ssl", "tls", "cert", "certs", "certbot", "letsencrypt", "crt", "pem", "pfx", "key", "keys", "pub", "priv", "private", "public", "signature", "signatures", "sign", "valid", "validity", "expiry", "expired", "renew", "renewal", "renewed", "rotate", "rotation", "rotated", "revoked", "revoke", "reissue", "vpn", "vpn1", "vpn2", "remote", "remote1", "rdp", "ssh", "bastion", "jump", "jumpbox", "terminal", "term", "proxy", "proxy1", "proxy2", "router", "router1", "loadbalancer", "lb", "lb1", "lb2", "load-balancer", "firewall", "fw", "fw1", "edge", "edge1", "endpoint", "endpoint1", "ingress", "egress", "tunnel", "tunnel1", "db", "db1", "db2", "database", "database1", "redis", "cache", "memcached", "mongo", "mysql", "postgres", "pgsql", "pg", "sqlite", "cassandra", "elastic", "opensearch", "clickhouse", "monitor", "monitoring", "metrics", "metric", "health", "healthcheck", "status", "status1", "logs", "log", "logging", "grafana", "kibana", "prometheus", "nagios", "zabbix", "datadog", "sentry", "newrelic", "splunk", "sumologic", "papertrail", "honeycomb", "git", "git1", "git2", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "cicd", "build", "build1", "buildbot", "travis", "circleci", "argocd", "sonar", "sonarqube", "code", "source", "repo", "repos", "repository", "repositories", "registry", "registry1", "package", "packages", "artifact", "artifacts", "nexus", "jfrog", "maven", "npm", "pypi", "docker", "docker1", "container", "containers", "k8s", "kube", "kubernetes", "helm", "terraform", "ansible", "puppet", "chef", "salt", "pulumi", "cloud", "cloud1", "cloud2", "aws", "azure", "gcp", "google", "digitalocean", "do", "linode", "heroku", "flyio", "fly", "render", "vercel", "netlify", "railway", "supabase", "firebase", "vultr", "hetzner", "ovh", "ionos", "upcloud", "contabo", "aiven", "upstash", "planetscale", "neon", "turso", "chat", "chat1", "messaging", "slack", "discord", "telegram", "whatsapp", "teams", "zoom", "meet", "signal", "matrix", "xmpp", "irc", "pusher", "socketio", "search", "search1", "search2", "meilisearch", "typesense", "algolia", "sphinx", "solr", "lucene", "ai", "ml", "model", "models", "inference", "training", "llm", "nlp", "cv", "vision", "speech", "voice", "recommendation", "recommendations", "embeddings", "vector", "pinecone", "weaviate", "milvus", "qdrant", "chroma", "blockchain", "wallet", "wallets", "crypto", "web3", "ethereum", "eth", "solana", "bitcoin", "btc", "ipfs", "arweave", "storj", "near", "stripe", "paypal", "square", "shopify", "adyen", "braintree", "plaid", "mollie", "razorpay", "xendit", "finance", "fin", "budget", "budgets", "expense", "expenses", "revenue", "profit", "ledger", "ledgers", "journal", "journals", "bank", "banking", "loan", "loans", "credit", "debit", "card", "cards", "transaction", "transactions", "settlement", "settlements", "clearing", "reconciliation", "tax", "taxes", "hr", "hris", "staff", "employee", "employees", "recruiting", "recruit", "hiring", "interview", "interviews", "payroll", "benefits", "performance", "appraisal", "appraisals", "evaluation", "evaluations", "engagement", "retention", "attrition", "turnover", "succession", "leadership", "growth", "career", "careers", "job", "jobs", "vacancy", "vacancies", "position", "positions", "role", "roles", "opening", "openings", "it", "infra", "infrastructure", "network", "net", "netops", "neteng", "sysadmin", "sysop", "sysops", "linux", "unix", "bsd", "windows", "win", "mac", "macos", "ios", "android", "iphone", "ipad", "tablet", "tablets", "phone", "phones", "device", "devices", "hardware", "software", "firmware", "driver", "drivers", "update", "updates", "fix", "fixes", "bug", "bugs", "issue", "issues", "problem", "problems", "error", "errors", "exception", "exceptions", "failure", "failures", "outage", "outages", "downtime", "uptime", "sla", "sli", "slo", "sec", "secops", "soc", "siem", "ids", "ips", "waf", "antivirus", "malware", "ransomware", "phishing", "spam", "bot", "bots", "botnet", "ddos", "attack", "attacks", "breach", "breaches", "intrusion", "intrusions", "hack", "hacks", "hacker", "hackers", "pentest", "vulnerability", "vuln", "scanning", "scans", "gdpr", "hipaa", "pci", "pci-dss", "iso27001", "nist", "fedramp", "cisa", "cis", "center", "centers", "controls", "framework", "frameworks", "standard", "standards", "policy", "policies", "procedure", "procedures", "guideline", "guidelines", "rule", "rules", "regulation", "regulations", "court", "courts", "tribunal", "tribunals", "jurisdiction", "jurisdictions", "enforcement", "penalty", "penalties", "fine", "fines", "sanction", "sanctions", "license", "licenses", "permit", "permits", "certificate", "certificates", "credential", "credentials", "internal", "intranet", "extranet", "office", "corp", "corporate", "work", "workspace", "us", "uk", "eu", "asia", "apac", "au", "ca", "de", "fr", "es", "nl", "be", "ch", "at", "jp", "cn", "kr", "sg", "in", "en", "en-us", "en-gb", "salesforce", "hubspot", "zendesk", "sales", "sales1", "sales2", "crm", "crm1", "crm2", "lead", "leads", "prospect", "prospects", "client", "clients", "vendor", "vendors", "supplier", "suppliers", "ops", "ops1", "ops2", "operations", "operations1", "business", "business1", "hq", "headquarters", "branch", "branches", "location", "locations", "department", "departments", "division", "divisions", "unit", "units", "section", "sections", "area", "areas", "zone", "zones", "region", "regions", "country", "countries", "state", "states", "province", "provinces", "city", "cities", "town", "towns", "village", "villages", "district", "districts", "county", "counties", "municipality", "municipalities", "locality", "localities", "neighborhood", "neighborhoods", "neighbourhood", "neighbourhoods", "suburb", "suburbs", "ward", "wards", "precinct", "precincts", "borough", "boroughs"]
    for sub in common_subdomains:
        candidate = f"{sub}.{domain}"
        try:
            # Check A record
            answers = dns.resolver.resolve(candidate, 'A', lifetime=2)
            for rdata in answers:
                found.append(candidate)
        except: pass
        try:
            # Check AAAA record
            answers = dns.resolver.resolve(candidate, 'AAAA', lifetime=2)
            for rdata in answers:
                found.append(candidate)
        except: pass

    # 6. DnsRecon (Original logic)
    try:
        result = subprocess.run(['dnsrecon', '-d', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        found.extend([line.strip() for line in result.stdout.splitlines() if line.strip() and 'Could not resolve' not in line])
    except: pass

    return found

def read_targets(filename):
    """
    Reads IPs and Domains from a file.
    Returns a list of tuples: [('ip', '192.168.1.1'), ('domain', 'example.com')]
    """
    targets = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Check if it's an IP (digits and dots only)
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    targets.append(('ip', line))
                else:
                    targets.append(('domain', line))
    except FileNotFoundError:
        print(f"{RED}File '{filename}' not found.{RESET}")
    return targets

def process_target(target_type, target_value):
    global total_found_hosts_count
    
    if target_type == 'ip':
        # IP Path: Reverse Lookup -> Find Subdomains
        hostname = reverse_lookup(target_value)
        if hostname:
            results_set.add(hostname)
            total_found_hosts_count += 1
            # Find subdomains associated with this hostname
            subs = get_additional_sources(hostname)
            for s in subs: results_set.add(s)
    else:
        # Domain Path: Direct Search
        subs = get_additional_sources(target_value)
        for s in subs: results_set.add(s)

def main():
    global output_file
    
    input_file = input("Enter the name of the input file (e.g., TARGETS.txt): ").strip()
    output_file = input("Enter the name of the output file (e.g., OUTPUT_HOST.txt): ").strip()

    if os.path.exists(output_file):
        os.remove(output_file)
    
    print(f"{YELLOW}Starting Universal Target Enumeration...{RESET}")

    targets = read_targets(input_file)
    if not targets:
        print(f"{RED}No targets found.{RESET}")
        return

    num_threads = 300
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_target = {executor.submit(process_target, t_type, t_val): (t_type, t_val) for t_type, t_val in targets}
        
        for future in as_completed(future_to_target):
            t_type, t_val = future_to_target[future]
            try:
                future.result()
            except Exception as e:
                print(f"{RED}Error processing {t_type}: {t_val} - {e}{RESET}")

    # Write results
    with open(output_file, 'w') as file:
        for host in sorted(results_set):
            file.write(f"{host}\n")
            
    end_time = time.time()
    duration = end_time - start_time

    print(f"\n{'='*50}")
    print(f"{GREEN}Results Summary:{RESET}")
    print(f"{CYAN}Total Unique Targets Found: {total_found_hosts_count}{RESET}")
    print(f"{CYAN}Results saved to: {output_file}{RESET}")
    print(f"{CYAN}Time taken: {duration:.2f} seconds{RESET}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
