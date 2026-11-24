#!/usr/bin/env bash
# Phase 5 GCP setup for GitHub Actions CI: keyless Workload Identity Federation (WIF),
# custom least-privilege roles and one service account per CI job. Creates NO keys.
#
# Merged from the two reference implementations (read-only smoke repo + DEV drift/evals/deploy repo).
#
# DEFAULT IS DRY RUN: prints every gcloud command. Review it (or send it to the client's
# cloud admin), then re-run with --apply. Run against DEV/test projects only, never PROD.
#
# Usage:
#   setup-gcp-ci.sh --project <GCP_PROJECT_ID> --repo <OWNER/REPO> [--provider <PROVIDER_ID>]
#                   [--accounts readonly,evals,deployer] [--run-service <name>]... [--region <r>] [--apply]
#
# Look up the numeric GitHub IDs it pins:  gh api repos/<OWNER/REPO> --jq '.id, .owner.id'
# APIs needed: iam, iamcredentials, sts, cloudresourcemanager, ces (+ run for Cloud Run checks).
set -euo pipefail
D="$(cd "$(dirname "$0")/.." && pwd)"          # phase5/ (perms.*.txt live there)
PROJECT=""; REPO=""; PROVIDER="github-repo"; ACCOUNTS="readonly"; APPLY=0; REGION="us-central1"; RUN_SERVICES=()
POOL=github-ci
while [ $# -gt 0 ]; do case "$1" in
  --project) PROJECT="$2"; shift;; --repo) REPO="$2"; shift;; --provider) PROVIDER="$2"; shift;;
  --accounts) ACCOUNTS="$2"; shift;; --run-service) RUN_SERVICES+=("$2"); shift;; --region) REGION="$2"; shift;;
  --apply) APPLY=1;; -h|--help) sed -n 2,15p "$0"; exit 0;; *) echo "unknown arg $1"; exit 2;; esac; shift; done
: "${PROJECT:?--project required}"; : "${REPO:?--repo required}"
case "$PROJECT" in *prod*) echo "Refusing: project name contains 'prod'."; exit 2;; esac

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
REPO_ID="$(gh api "repos/$REPO" --jq .id)"
OWNER_ID="$(gh api "repos/$REPO" --jq .owner.id)"
POOL_PATH="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL}"

run() { if [ "$APPLY" = 1 ]; then echo "+ $*"; "$@"; else printf '%q ' "$@"; echo; fi; }
has() { case ",$ACCOUNTS," in *",$1,"*) return 0;; *) return 1;; esac; }
perms() { paste -sd, "$D/perms.$1.txt"; }

echo "# project=$PROJECT number=$PROJECT_NUMBER repo=$REPO repo_id=$REPO_ID owner_id=$OWNER_ID accounts=$ACCOUNTS apply=$APPLY"

# 0) APIs
run gcloud services enable iam.googleapis.com iamcredentials.googleapis.com sts.googleapis.com \
  cloudresourcemanager.googleapis.com ces.googleapis.com --project="$PROJECT"
[ ${#RUN_SERVICES[@]} -gt 0 ] && run gcloud services enable run.googleapis.com --project="$PROJECT"

# Preflight (read-only): refuse to clobber existing resources when applying.
if [ "$APPLY" = 1 ]; then
  gcloud iam workload-identity-pools providers describe "$PROVIDER" --location=global --workload-identity-pool="$POOL" \
    --project="$PROJECT" >/dev/null 2>&1 && { echo "provider $PROVIDER exists; stop and review"; exit 1; }
fi

# 1) Custom roles (ciEvalRunner and ciDeployer are supersets of ciConfigReader)
declare -A ROLE=( [readonly]=ciConfigReader [evals]=ciEvalRunner [deployer]=ciDeployer )
declare -A TITLE=( [readonly]="CI config reader (CES get/list)" [evals]="CI eval runner (test deployment, tool fakes)" [deployer]="CI scoped DEV deployer" )
for a in readonly evals deployer; do has "$a" || continue
  run gcloud iam roles create "${ROLE[$a]}" --project="$PROJECT" --title="${TITLE[$a]}" \
    --description="GitHub CI via WIF. No conversation reads, no export, no call audio." \
    --stage=GA --permissions="$(perms "${ROLE[$a]}")"
done

# 2) WIF pool + OIDC provider. Condition pins NUMERIC repo/owner IDs (a renamed or recreated
#    repo cannot inherit access), main only, and no pull_request events.
run gcloud iam workload-identity-pools create "$POOL" --project="$PROJECT" --location=global --display-name="GitHub CI"
run gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" --project="$PROJECT" \
  --location=global --workload-identity-pool="$POOL" --display-name="$PROVIDER" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_id=assertion.repository_id,attribute.repository_owner_id=assertion.repository_owner_id,attribute.ref=assertion.ref,attribute.event_name=assertion.event_name" \
  --attribute-condition="assertion.repository_id=='${REPO_ID}' && assertion.repository_owner_id=='${OWNER_ID}' && assertion.ref=='refs/heads/main' && assertion.event_name in ['push','workflow_dispatch','schedule']"

# 3) Service accounts (no keys) + project-level custom role binding
declare -A SA_NAME=( [readonly]=ci-readonly [evals]=ci-evals [deployer]=ci-deployer )
for a in readonly evals deployer; do has "$a" || continue
  SA="${SA_NAME[$a]}@${PROJECT}.iam.gserviceaccount.com"
  run gcloud iam service-accounts create "${SA_NAME[$a]}" --project="$PROJECT" --display-name="CI ${a} (GitHub WIF, keyless)"
  run gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA}" \
    --role="projects/${PROJECT}/roles/${ROLE[$a]}" --condition=None
done

# 4) Who may impersonate which SA
#    readonly: any allowed workflow in this repo (provider already limits to main, no PRs)
has readonly && run gcloud iam service-accounts add-iam-policy-binding "ci-readonly@${PROJECT}.iam.gserviceaccount.com" \
  --project="$PROJECT" --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/${POOL_PATH}/attribute.repository_id/${REPO_ID}"
#    evals: main only
has evals && run gcloud iam service-accounts add-iam-policy-binding "ci-evals@${PROJECT}.iam.gserviceaccount.com" \
  --project="$PROJECT" --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/${POOL_PATH}/attribute.ref/refs/heads/main"
#    deployer: ONLY jobs in the approval-gated GitHub environments (create them with required
#    reviewers and a main-only branch policy). Never bind a write-capable SA to ref=main.
if has deployer; then for env in dev dev-live; do
  run gcloud iam service-accounts add-iam-policy-binding "ci-deployer@${PROJECT}.iam.gserviceaccount.com" \
    --project="$PROJECT" --role=roles/iam.workloadIdentityUser \
    --member="principal://iam.googleapis.com/${POOL_PATH}/subject/repo:${REPO}:environment:${env}"
done; fi

# 5) Cloud Run read access for drift: per service, never project-wide
for svc in "${RUN_SERVICES[@]}"; do
  run gcloud run services add-iam-policy-binding "$svc" --project="$PROJECT" --region="$REGION" \
    --member="serviceAccount:ci-readonly@${PROJECT}.iam.gserviceaccount.com" --role=roles/run.viewer
done

# 6) Verify (expect keys list to show only SYSTEM_MANAGED)
run gcloud iam workload-identity-pools providers describe "$PROVIDER" --project="$PROJECT" \
  --location=global --workload-identity-pool="$POOL" --format='value(name,attributeCondition)'
for a in readonly evals deployer; do has "$a" || continue
  SA="${SA_NAME[$a]}@${PROJECT}.iam.gserviceaccount.com"
  run gcloud iam roles describe "${ROLE[$a]}" --project="$PROJECT" --format='value(includedPermissions)'
  run gcloud iam service-accounts get-iam-policy "$SA" --project="$PROJECT"
  run gcloud iam service-accounts keys list --iam-account="$SA" --project="$PROJECT"
done
echo "# workflow inputs:"
echo "#   workload_identity_provider: ${POOL_PATH}/providers/${PROVIDER}"
echo "#   service_account: ci-<readonly|evals|deployer>@${PROJECT}.iam.gserviceaccount.com"
echo "# If iam.allowedPolicyMemberDomains rejects a principalSet binding: STOP and escalate to the org admin."
