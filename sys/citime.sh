#!/bin/sh
set -eu

repo=radareorg/radare2
job=ubuntu-tcc-test

printf '| # | commit | date | message | conclusion | started | completed | duration |\n'
printf '|---:|---|---|---|---|---|---|---:|\n'

i=0
gh api "repos/$repo/commits?sha=master&per_page=50" --jq '.[] | @base64' |
while read -r row; do
	i=$((i + 1))
	sha=$(printf '%s' "$row" | base64 -d | jq -r '.sha')
	date=$(printf '%s' "$row" | base64 -d | jq -r '.commit.committer.date')
	msg=$(printf '%s' "$row" | base64 -d | jq -r '.commit.message | split("\n")[0]')

	cr=$(gh api "repos/$repo/commits/$sha/check-runs?check_name=$job" \
		--jq '.check_runs[0] // empty')

	if [ -z "$cr" ]; then
		printf '| %d | `%s` | %s | %s | missing | — | — | — |\n' \
			"$i" "$(printf %.7s "$sha")" "$date" "$msg"
		continue
	fi

	conclusion=$(printf '%s' "$cr" | jq -r '.conclusion // .status')
	started=$(printf '%s' "$cr" | jq -r '.started_at // empty')
	completed=$(printf '%s' "$cr" | jq -r '.completed_at // empty')

	if [ -n "$started" ] && [ -n "$completed" ] && [ "$completed" != "null" ]; then
		secs=$(( $(date -u -d "$completed" +%s) - $(date -u -d "$started" +%s) ))
		duration=$(printf '%dm %02ds' $((secs / 60)) $((secs % 60)))
	else
		duration='—'
	fi

	printf '| %d | `%s` | %s | %s | %s | %s | %s | %s |\n' \
		"$i" "$(printf %.7s "$sha")" "$date" "$msg" "$conclusion" "$started" "$completed" "$duration"
done
