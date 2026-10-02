# JevImpact.py vulnerability scoring

`JevImpact` assesses an AI agent's documented finding with TypeSafe's Jev model, using the same SDK as the existing examples. It returns JSON with `is_vulnerability`, `impactful`, and an `impact_score` from 0 to 1. It accepts structured JSON or a complete text/Markdown report, and is also importable by another agent.

```sh
python3 -m pip install -r requirements.txt
export TYPESAFE_API_KEY='your-key'
python3 JevImpact.py examples/invoice_idor.json
python3 JevImpact.py examples/blind_ssrf.json
python3 JevImpact.py finding.md
cat examples/invoice_idor.json | python3 JevImpact.py - --format json
```

All included findings are synthetic. Supply the actual bug description, exploitation steps, claimed impact, evidence, and deployment/access-policy context when evaluating your own reports. JSON requires `title`, `description`, `exploitation_steps` (a nonempty list of strings), and `impact`; `evidence` (list of strings) and `context` (object) are optional. Unknown JSON fields are rejected to catch integration mistakes. Text input has no fixed layout, but should include the same information.

`examples/blind_ssrf.json` is a second synthetic finding: a backend request reaches an internal-only test service, verified through operator-only logs, while the attacker receives no upstream status code or response content. It documents the intended network boundary and separates demonstrated reachability from unproven data disclosure, state changes, and other downstream effects. No verdict is hardcoded into the example.

The original invoice report is now `examples/invoice_idor.json`. Six additional reports provide three positive and three negative examples. The expected outcomes below are reference labels based on their supplied evidence, not measured model results. They are kept outside the report JSON so Jev evaluates the reports without being given an answer label. Every file can be run with `python3 JevImpact.py examples/<filename>`.

| New example | Expected `is_vulnerability` | Expected `impactful` | Evidence supporting the reference label |
| --- | --- | --- | --- |
| `stored_xss_support_ticket.json` | `true` | `true` | A customer's stored payload executes a benign script in a separate support user's session. |
| `password_reset_account_binding.json` | `true` | `true` | A reset token for account A changes account B's password and permits login as B. |
| `sql_injection_order_search.json` | `true` | `true` | An injected query predicate discloses another customer's private order records. |
| `self_xss_browser_console.json` | `false` | `false` | Execution requires the user's own console; the proposed delivery paths render inert text. |
| `version_banner_backported_fix.json` | `false` | `false` | Deployed code and a controlled comparison show the claimed evaluation bug is fixed despite the old banner. |
| `authorized_admin_role_change.json` | `false` | `false` | The successful operation is explicitly authorized; ordinary-member and cross-tenant attempts fail. |

These labels concern the specific reported behavior. Negative examples do not claim the entire application is free of vulnerabilities. Positive examples demonstrate security consequences without assuming untested follow-on compromise. Scores remain model judgments rather than fixed expected values.

```python
import json
from JevImpact import assess_vulnerability

with open("examples/invoice_idor.json") as stream:
    finding = json.load(stream)

result = assess_vulnerability(finding)
print(result["is_vulnerability"], result["impactful"], result["impact_score"])
```

For repeated assessments, reuse a `TypeSafeClient` and pass `client=client`. Jev's model default follows the SDK configuration; override it with `--model` or `model=...`.

The script asks independent questions about evidence sufficiency, security boundary violations, concrete adverse consequences, severity, and the best assessment reason. A finding is accepted as a vulnerability only when evidence sufficiency and vulnerability probability both reach the threshold (default 0.8). `impactful` additionally requires impact probability to reach that threshold. Low-severity consequences can still be impactful. False means **not established by this report at this threshold**, rather than a guarantee of safety.

Severity uses six descriptive rubric levels: no consequence, limited consequence, meaningful consequence, serious consequence, severe consequence, and critical consequence. Their normalized positions are 0, 0.2, 0.4, 0.6, 0.8, and 1. The returned score is the probability-weighted position on that rubric, divided by five; it is a custom triage score, not CVSS or an exploitation probability. It is zero for findings that are not accepted as impactful. `raw_impact_score` preserves the ungated normalized score for review. Confidence is reported separately and does not multiply severity. The rubric and thresholds should be evaluated against your team's labeled reports before automated decisions.

`needs_review` flags missing evidence, uncertain probabilities, low confidence, or contradictory judgments. `reason` is a selected category and `reason_description` is its fixed description, not a generated explanation. Jev returns typed judgments rather than freeform reasoning. You can adjust acceptance with `--threshold 0.9` and review sensitivity with `--min-confidence 0.7`. Even when both booleans are false, check `needs_review` before discarding a finding.

The report is sent to the configured TypeSafe API. Assessment relies on the supplied documentation; the script does not inspect the target, execute exploit steps, or independently verify observations. Embedded report instructions are explicitly treated as untrusted data. API/input failures return a nonzero exit status and an error JSON object on stderr, never a negative vulnerability verdict; successful assessment JSON goes to stdout.

SDK integration follows the official [Python SDK](https://docs.typesafe.ai/sdk/python), [Noul](https://docs.typesafe.ai/primitives/noul), and [Score](https://docs.typesafe.ai/primitives/score) documentation.


