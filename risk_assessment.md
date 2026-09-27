# Risk Assessment - Polytechnic Student Records System

## 1. Assets, Vulnerabilities, Consequences

| Asset | Vulnerability | Consequence |
|---|---|---|
| Student records database | Weak staff passwords | Attacker guesses/brute-forces login → data breach, record tampering |
| Inter-campus file transfer | Unencrypted transfer | Data intercepted or altered in transit (MITM) |
| Records server | Outdated software + guest network access | Unpatched server reachable by anyone on guest network → full compromise |

## 2. Risk Ranking

| Rank | Risk | Likelihood | Impact | Reason |
|---|---|---|---|---|
| 1 | Outdated software + guest access | High | High | No credentials needed; matches suspicious external connection attempts already observed |
| 2 | Weak staff passwords | Medium-High | High | Easy to exploit, gives full legitimate-looking access |
| 3 | Unencrypted file transfer | Medium | Medium-High | Attacker needs network-path position first |

## 3. Controls

| Risk | Control |
|---|---|
| Outdated software + guest access | Segment guest network away from server; regular patching |
| Weak passwords | Strong password policy + MFA |
| Unencrypted transfer | Encrypt transfers (SFTP/TLS) + encrypt files before sending |
