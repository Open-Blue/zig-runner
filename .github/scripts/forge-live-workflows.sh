# The repositories' files for forge-live.sh: sourced, it defines `act_action` (a composite action
# that says who ran it, in an output) and `workflow NAME URL PORT PREFIX` (the workflow's text).

act_action='name: hello
inputs:
  who:
    default: nobody
outputs:
  ran:
    value: ${{ steps.say.outputs.ran }}
runs:
  using: composite
  steps:
    - id: say
      shell: bash
      run: |
        echo "hello from ${{ inputs.who }}"
        echo "ran=${{ inputs.who }}" >> "$GITHUB_OUTPUT"
'

workflow() { # name url port prefix
	local name=$1 url=$2 port=$3 prefix=$4
	case $name in
	actions)
		cat <<'EOF'
name: actions
on: workflow_dispatch
jobs:
  j:
    runs-on: live
    steps:
      - id: a1
        uses: self:zradmin/act@v1
        with: {who: self}
      - id: a2
        uses: self:zradmin/act/sub@v1
        with: {who: selfsub}
      - id: a3
        uses: zradmin/act@v1
        with: {who: default}
      - id: a4
        uses: @URL@/zradmin/act@v1
        with: {who: url}
      - id: a5
        uses: $/.gitea/actions/mine
        with: {who: repo}
      - run: |
          test "${{ steps.a1.outputs.ran }}" = self
          test "${{ steps.a2.outputs.ran }}" = selfsub
          test "${{ steps.a3.outputs.ran }}" = default
          test "${{ steps.a4.outputs.ran }}" = url
          test "${{ steps.a5.outputs.ran }}" = repo
EOF
		;;
	env)
		cat <<'EOF'
name: env
on: workflow_dispatch
jobs:
  j:
    runs-on: live
    steps:
      - run: |
          set -eu
          flag=@PREFIX@_ACTIONS
          test "${!flag}" = true
          version=@PREFIX@_ACTIONS_RUNNER_VERSION
          test -n "${!version}"
          test "$GITHUB_SERVER_URL" = "@URL@"
          test "$GITHUB_REPOSITORY" = zradmin/main
          test -z "${GITHUB_TOKEN:-}${FORGEJO_TOKEN:-}${GITEA_TOKEN:-}"
          if [ "@PREFIX@" = FORGEJO ]; then
            test "$FORGEJO_SHA" = "$GITHUB_SHA"
            test "$FORGEJO_REPOSITORY" = "$GITHUB_REPOSITORY"
            test "$FORGEJO_SERVER_URL" = "$GITHUB_SERVER_URL"
          else
            test -n "$GITEA_RUN_ID"
            test "$GITEA_RUN_ID" = "$GITHUB_RUN_ID"
          fi
          test "${{ github.server_url }}" = "@URL@"
EOF
		;;
	services)
		cat <<'EOF'
name: services
on: workflow_dispatch
jobs:
  j:
    runs-on: live
    services:
      cache:
        image: redis:7-alpine
        ports: ["6379:6379"]
        options: --health-cmd "redis-cli ping" --health-interval 2s --health-retries 15
      other:
        image: redis:7-alpine
        cmd: ["redis-server", "--port", "6380"]
        ports: ["6380:6380"]
    steps:
      - run: |
          set -eu
          ping() {
            exec 3<>"/dev/tcp/$1/$2"
            printf 'PING\r\n' >&3
            read -r line <&3
            exec 3>&-
            echo "$1:$2 answers $line"
            case $line in +PONG*) ;; *) return 1 ;; esac
          }
          ping cache 6379
          ping localhost 6379
          ping other 6380
          ping localhost 6380
EOF
		;;
	features)
		cat <<'EOF'
name: features
on: workflow_dispatch
jobs:
  j:
    runs-on: live
    steps:
      - uses: actions/checkout@v4
      - id: out
        run: |
          test -f README.md
          echo "x=1" >> "$GITHUB_OUTPUT"
          echo "::add-mask::sekrit"
          echo "sekrit is masked"
      - run: test "${{ steps.out.outputs.x }}" = 1
      - name: this one fails on purpose
        run: exit 3
EOF
		;;
	esac | sed "s|@URL@|$url|g; s|@PREFIX@|$prefix|g"
}
