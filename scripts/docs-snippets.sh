#!/usr/bin/env bash
# Compile every documentation fence presented as oasts.yaml against a real OpenAPI document.
set -euo pipefail

cd "$(dirname "$0")/.."
repo_root=$PWD
binary=target/debug/oasts
fallback_fixture=fixtures/docs-snippets
work=""

finish() {
  status=$?
  trap - EXIT
  if [[ -n "$work" && -d "$work" ]]; then
    rm -rf -- "$work"
  fi
  exit "$status"
}
trap finish EXIT

if [[ ! -x "$binary" ]]; then
  cargo build -p oasts
fi

work=$(mktemp -d)
mkdir -p "$work/extracted"
metadata="$work/snippets.tsv"

mapfile -t pages < <(find www/src/content/docs -type f -name '*.mdx' | sort)
if ((${#pages[@]} == 0)); then
  echo "docs-snippets: no MDX pages found" >&2
  exit 1
fi

awk -v extracted="$work/extracted" -v metadata="$metadata" '
  function fail(message) {
    print "docs-snippets: " message > "/dev/stderr"
    failed = 1
    exit 1
  }

  FNR == 1 && in_yaml {
    fail(source ":" start_line " has an unclosed YAML fence")
  }

  /^```yaml([[:space:]]|$)/ {
    in_yaml = 1
    source = FILENAME
    start_line = FNR
    header = $0
    count++
    snippet = extracted "/" count ".yaml"
    printf "%s", "" > snippet
    close(snippet)
    next
  }

  in_yaml && /^```[[:space:]]*$/ {
    kind = "untitled"
    if (index(header, "title=\"oasts.yaml\"") != 0) {
      kind = "config"
    } else if (index(header, "title=\"openapi.yaml\"") != 0) {
      kind = "openapi"
    } else if (index(header, "title=") != 0) {
      kind = "other"
    }
    print kind "\t" source "\t" start_line "\t" snippet >> metadata
    close(metadata)
    in_yaml = 0
    next
  }

  in_yaml {
    print $0 >> snippet
  }

  END {
    if (in_yaml && !failed) {
      fail(source ":" start_line " has an unclosed YAML fence")
    }
  }
' "${pages[@]}"

has_root_key() {
  local snippet=$1 key=$2
  grep -Eq "^${key}:[[:space:]]*(#.*)?$|^${key}:[[:space:]]+[^#[:space:]]" "$snippet"
}

artifact_enabled() {
  local snippet=$1 artifact=$2
  awk -v artifact="$artifact" '
    /^artifacts:[[:space:]]*(#.*)?$/ { in_artifacts = 1; next }
    in_artifacts && /^[^[:space:]]/ { exit }
    in_artifacts && $0 ~ "^  " artifact ":[[:space:]]+true([[:space:]]*(#.*)?)?$" { found = 1 }
    END { exit !found }
  ' "$snippet"
}

declare -A page_documents=()
config_count=0
complete_count=0
fragment_count=0

while IFS=$'\t' read -r kind source line snippet; do
  if [[ "$kind" == openapi ]] && has_root_key "$snippet" openapi; then
    if [[ -n "${page_documents[$source]-}" ]]; then
      echo "docs-snippets: $source has more than one complete openapi.yaml fence" >&2
      exit 1
    fi
    page_documents[$source]=$snippet
  fi

  has_schema=false
  has_input=false
  has_output=false
  has_root_key "$snippet" schemaVersion && has_schema=true
  has_root_key "$snippet" input && has_input=true
  has_root_key "$snippet" output && has_output=true
  # A workspace fence names its documents and output roots under `specs`, so it is already
  # complete without the root-level input/output every other fence is completed with.
  has_root_key "$snippet" specs && has_input=true && has_output=true

  if [[ "$kind" == untitled && "$has_schema" == true && "$has_input" == true && "$has_output" == true ]]; then
    echo "docs-snippets: $source:$line is a complete config without title=\"oasts.yaml\"" >&2
    exit 1
  fi

  if [[ "$kind" == config ]]; then
    config_count=$((config_count + 1))
    if [[ "$has_schema" == true && "$has_input" == true && "$has_output" == true ]]; then
      complete_count=$((complete_count + 1))
    else
      fragment_count=$((fragment_count + 1))
    fi
  fi
done <"$metadata"

if ((config_count == 0)); then
  echo "docs-snippets: no title=\"oasts.yaml\" fences found" >&2
  exit 1
fi

# Entries are "source:line OASTSnnnn". An expected refusal passes only when it emits that error
# code and no other error code; line-keying keeps the exception tied to one exact fence.
expected_refusals=(
  "www/src/content/docs/reference/configuration.mdx:67 OASTS2021"
)
declare -A expected_by_block=()
declare -A seen_expected=()
for entry in "${expected_refusals[@]}"; do
  block=${entry% *}
  code=${entry##* }
  if [[ -z "$block" || ! "$code" =~ ^OASTS[0-9]{4}$ || -n "${expected_by_block[$block]-}" ]]; then
    echo "docs-snippets: invalid expected-refusal entry: $entry" >&2
    exit 1
  fi
  expected_by_block[$block]=$code
done

render_log() {
  local log=$1 case_dir=$2 source=$3 line=$4
  sed \
    -e "s|$case_dir/oasts.yaml|$source:$line|g" \
    -e "s|$case_dir/openapi.yaml|$source (OpenAPI fixture)|g" \
    "$log"
}

status=0
checked=0
while IFS=$'\t' read -r kind source line snippet; do
  [[ "$kind" == config ]] || continue
  checked=$((checked + 1))
  case_dir="$work/case-$checked"
  mkdir -p "$case_dir"

  is_workspace=false
  has_root_key "$snippet" specs && is_workspace=true
  is_complete=false
  if [[ "$is_workspace" == true ]]; then
    has_root_key "$snippet" schemaVersion && is_complete=true
  elif has_root_key "$snippet" schemaVersion && has_root_key "$snippet" input &&
    has_root_key "$snippet" output; then
    is_complete=true
  fi
  needs_client=false
  if has_root_key "$snippet" client || artifact_enabled "$snippet" client; then
    needs_client=true
  fi

  {
    has_root_key "$snippet" schemaVersion || printf 'schemaVersion: 1\n'
    if [[ "$is_workspace" == false ]]; then
      has_root_key "$snippet" input || printf 'input:\n  path: ./openapi.yaml\n'
      has_root_key "$snippet" output || printf 'output: ./generated\n'
    fi
    if [[ "$is_complete" == false && "$needs_client" == true ]] && ! has_root_key "$snippet" artifacts; then
      printf 'artifacts:\n  types: true\n  client: true\n'
    fi
    if [[ "$is_complete" == false && "$needs_client" == true ]] && ! has_root_key "$snippet" validation; then
      printf 'validation:\n  engine: "off"\n  unchecked: allow\n'
    fi
    cat "$snippet"
  } >"$case_dir/oasts.yaml"

  cp -r "$fallback_fixture/." "$case_dir"
  if [[ -n "${page_documents[$source]-}" ]]; then
    cp "${page_documents[$source]}" "$case_dir/openapi.yaml"
  elif grep -q '^    schemasBySource:' "$snippet"; then
    cp "$fallback_fixture/naming-openapi.yaml" "$case_dir/openapi.yaml"
  fi

  log="$case_dir/check.log"
  if (cd "$case_dir" && "$repo_root/$binary" check --config oasts.yaml) >"$log" 2>&1; then
    cli_status=0
  else
    cli_status=$?
  fi

  block="$source:$line"
  expected=${expected_by_block[$block]-}
  if [[ -n "$expected" ]]; then
    seen_expected[$block]=true
    mapfile -t error_codes < <(grep -Eo 'error\[OASTS[0-9]{4}\]' "$log" | sed -E 's/error\[(OASTS[0-9]{4})\]/\1/' | sort -u)
    if ((cli_status == 0)); then
      echo "docs-snippets: $block unexpectedly passed; expected $expected" >&2
      status=1
    elif ((${#error_codes[@]} != 1)) || [[ "${error_codes[0]-}" != "$expected" ]]; then
      echo "docs-snippets: $block failed with a new error; expected only $expected" >&2
      render_log "$log" "$case_dir" "$source" "$line" >&2
      status=1
    else
      echo "expected refusal: $block ($expected)"
    fi
  elif ((cli_status != 0)); then
    echo "docs-snippets: $block failed" >&2
    render_log "$log" "$case_dir" "$source" "$line" >&2
    status=1
  fi
done <"$metadata"

for block in "${!expected_by_block[@]}"; do
  if [[ -z "${seen_expected[$block]-}" ]]; then
    echo "docs-snippets: expected-refusal entry does not name a config fence: $block" >&2
    status=1
  fi
done

if ((status != 0)); then
  exit "$status"
fi
echo "docs-snippets: checked $checked configs ($complete_count complete, $fragment_count completed with required keys)"
