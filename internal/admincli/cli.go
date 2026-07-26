// Package admincli implements the gssh-admin admin CLI (phase 6): grant
// management (CRUD) and declarative YAML sync against the gssh-server's
// admin API. Authentication like gssh: OIDC ID token (PKCE or device flow),
// alternatively via GSSH_ID_TOKEN/--token.
package admincli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/guided-traffic/guided-ssh/internal/cli"
	"github.com/guided-traffic/guided-ssh/internal/version"
)

// envIDToken passes a ready-made ID token (e.g. from CI) and skips the
// interactive OIDC flow.
const envIDToken = "GSSH_ID_TOKEN" //nolint:gosec // env var name, not a secret

// envClientSecret activates the client-credentials flow (service account,
// e.g. a GitOps sync cronjob): the token is fetched non-interactively from
// the issuer's token endpoint; envClientID overrides the configured
// client_id.
const (
	envClientID     = "GSSH_CLIENT_ID"
	envClientSecret = "GSSH_CLIENT_SECRET" //nolint:gosec // env var name, not a secret
)

// Run executes the admin CLI and returns the exit code (0 ok, 1 error,
// 2 usage error).
func Run(stdout, stderr io.Writer, args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	command, rest := args[0], args[1:]
	switch command {
	case "grant":
		return runGrantCmd(ctx, rest, stdout, stderr)
	case "ci-grant":
		return runCIGrantCmd(ctx, rest, stdout, stderr)
	case "apply":
		return runApplyCmd(ctx, rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gssh-admin: unknown command %q\n\n", command)
		usage(stderr)
		return 2
	}
}

// usage prints the command overview.
func usage(w io.Writer) {
	fmt.Fprint(w, `gssh-admin — manage access rules (grants) for guided-ssh

commands:
  grant list
        show all access rules
  grant create --group <name> --principals <p1,p2> [--tags k=v,…]
               [--sudo] [--max-validity 8h] [--issuer url]
        create an access rule (group is created if needed)
  grant update <id> [--principals …] [--tags …] [--sudo=true|false] [--max-validity …]
        change an access rule (only the given fields)
  grant delete <id>
        delete an access rule
  ci-grant list
        show all CI access rules (GitLab pipelines)
  ci-grant create --project <path> --principals <p1,p2> [--ref pattern]
                  [--protected-only=true|false] [--environment pattern]
                  [--tags k=v,…] [--max-validity 1h]
        create a CI access rule (project or group path)
  ci-grant update <id> [flags as for create except --project]
        change a CI access rule (only the given fields)
  ci-grant delete <id>
        delete a CI access rule
  apply -f grants.yaml
        declarative sync: the file is the target state (GitOps);
        the ci_grants section is only synced if present
  version
        print the version

common flags: --config <path>, --token <id-token>, --device
authentication: --token, else GSSH_ID_TOKEN, else client credentials
(GSSH_CLIENT_SECRET set; GSSH_CLIENT_ID overrides the configured client_id —
for service accounts, e.g. GitOps sync), else OIDC login (browser or
--device); requires membership in the server's admin group.
`)
}

// commonFlags registers the flags shared by all commands.
type commonFlags struct {
	configPath string
	token      string
	device     bool
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.configPath, "config", "", "path to the configuration file")
	fs.StringVar(&c.token, "token", "", "ready-made OIDC ID token (skips login)")
	fs.BoolVar(&c.device, "device", false, "device flow instead of browser (headless)")
}

// connect loads the configuration, obtains an ID token, and builds the
// client.
func (c *commonFlags) connect(ctx context.Context, stderr io.Writer) (*client, error) {
	path := cli.ResolveConfigPath(c.configPath)
	if path == "" {
		return nil, errors.New("no configuration path could be determined (HOME not set?)")
	}
	cfg, err := cli.LoadConfig(path)
	if err != nil {
		return nil, err
	}
	token := c.token
	if token == "" {
		token = os.Getenv(envIDToken)
	}
	if token == "" {
		if secret := os.Getenv(envClientSecret); secret != "" {
			token, err = cli.FetchServiceToken(ctx, cfg, os.Getenv(envClientID), secret)
		} else {
			token, err = cli.FetchIDToken(ctx, cfg, c.device, stderr)
		}
		if err != nil {
			return nil, err
		}
	}
	return newClient(cfg, token)
}

// runGrantCmd dispatches to the grant subcommands.
func runGrantCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "gssh-admin: grant requires a subcommand (list, create, update, delete)")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runGrantList(ctx, rest, stdout, stderr)
	case "create":
		return runGrantCreate(ctx, rest, stdout, stderr)
	case "update":
		return runGrantUpdate(ctx, rest, stdout, stderr)
	case "delete":
		return runGrantDelete(ctx, rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "gssh-admin: unknown grant subcommand %q\n", sub)
		return 2
	}
}

// fail prints the error and returns exit code 1.
func fail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "gssh-admin: %v\n", err)
	return 1
}

func runGrantList(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin grant list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	apiClient, err := common.connect(ctx, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	grants, err := apiClient.listGrants(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	printGrants(stdout, grants)
	return 0
}

// printGrants prints grants as a table.
func printGrants(w io.Writer, grants []Grant) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tGROUP\tTAGS\tPRINCIPALS\tSUDO\tMAX-VALIDITY")
	for _, g := range grants {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\n",
			g.ID, g.Group, formatTags(g.TagSelector),
			strings.Join(g.Principals, ","), g.Sudo,
			time.Duration(g.MaxValiditySeconds)*time.Second)
	}
	_ = tw.Flush()
}

// formatTags renders a tag selector as k=v,…; empty = all hosts.
func formatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return "*"
	}
	pairs := make([]string, 0, len(tags))
	for k, v := range tags {
		pairs = append(pairs, k+"="+v)
	}
	slices.Sort(pairs) // stable output
	return strings.Join(pairs, ",")
}

// parseTags parses "k=v,k2=v2" into a map.
func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("invalid tag %q (expected key=value)", pair)
		}
		tags[key] = value
	}
	return tags, nil
}

// splitList parses a comma-separated list, skipping empty entries.
func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func runGrantCreate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin grant create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	group := fs.String("group", "", "IdP group (required)")
	issuer := fs.String("issuer", "", "issuer of the group (default: token's issuer)")
	tagsFlag := fs.String("tags", "", "tag selector, e.g. env=prod,role=web (empty = all hosts)")
	principalsFlag := fs.String("principals", "", "target principals, e.g. deploy,root (required)")
	sudo := fs.Bool("sudo", false, "mark as sudo permission")
	maxValidity := fs.Duration("max-validity", 16*time.Hour, "maximum certificate validity")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	principals := splitList(*principalsFlag)
	if *group == "" || len(principals) == 0 {
		fmt.Fprintln(stderr, "gssh-admin: --group and --principals are required")
		return 2
	}
	tags, err := parseTags(*tagsFlag)
	if err != nil {
		return fail(stderr, err)
	}
	apiClient, err := common.connect(ctx, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	created, err := apiClient.createGrant(ctx, &Grant{
		Group:              *group,
		Issuer:             *issuer,
		TagSelector:        tags,
		Principals:         principals,
		Sudo:               *sudo,
		MaxValiditySeconds: int64(*maxValidity / time.Second),
	})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "grant created: %s (group %s)\n", created.ID, created.Group)
	return 0
}

func runGrantUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin grant update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	tagsFlag := fs.String("tags", "", "new tag selector (k=v,…)")
	principalsFlag := fs.String("principals", "", "new target principals (comma list)")
	sudo := fs.Bool("sudo", false, "sudo permission")
	maxValidity := fs.Duration("max-validity", 0, "new maximum validity")
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "gssh-admin: grant update <id> [flags]")
		return 2
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	changed := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { changed[f.Name] = true })

	apiClient, err := common.connect(ctx, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	current, err := apiClient.getGrant(ctx, id)
	if err != nil {
		return fail(stderr, err)
	}
	if changed["tags"] {
		tags, err := parseTags(*tagsFlag)
		if err != nil {
			return fail(stderr, err)
		}
		current.TagSelector = tags
	}
	if changed["principals"] {
		current.Principals = splitList(*principalsFlag)
	}
	if changed["sudo"] {
		current.Sudo = *sudo
	}
	if changed["max-validity"] {
		current.MaxValiditySeconds = int64(*maxValidity / time.Second)
	}
	updated, err := apiClient.updateGrant(ctx, id, current)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "grant updated: %s (group %s)\n", updated.ID, updated.Group)
	return 0
}

func runGrantDelete(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin grant delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "gssh-admin: grant delete <id>")
		return 2
	}
	id := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	apiClient, err := common.connect(ctx, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	if err := apiClient.deleteGrant(ctx, id); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "grant deleted: %s\n", id)
	return 0
}

func runApplyCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	file := fs.String("f", "", "path to grants.yaml (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" {
		fmt.Fprintln(stderr, "gssh-admin: apply -f <grants.yaml>")
		return 2
	}
	grants, ciGrants, ciPresent, err := loadGrantsFile(*file)
	if err != nil {
		return fail(stderr, err)
	}
	apiClient, err := common.connect(ctx, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	result, err := apiClient.applyGrants(ctx, grants)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "sync complete: %d created, %d updated, %d deleted, %d unchanged\n",
		result.Created, result.Updated, result.Deleted, result.Unchanged)
	if ciPresent {
		ciResult, err := apiClient.applyCIGrants(ctx, ciGrants)
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "ci-sync complete: %d created, %d updated, %d deleted, %d unchanged\n",
			ciResult.Created, ciResult.Updated, ciResult.Deleted, ciResult.Unchanged)
	}
	return 0
}
