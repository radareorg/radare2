if [ -z "${GITHUB_ACCESS_TOKEN}" ]; then
	echo "Please define GITHUB_ACCESS_TOKEN"
	exit 1
fi

curl -s \
	-H "Accept: application/vnd.github+json" \
	-H "Authorization: Bearer $GITHUB_ACCESS_TOKEN" \
	-H "X-GitHub-Api-Version: 2022-11-28" \
	"https://api.github.com/repos/radareorg/radare2/actions/runs" > gha.json
# ?created=2023-06-01..2023-04-02"
