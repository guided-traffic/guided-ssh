package admincli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// runCIGrantCmd dispatches to the ci-grant subcommands (phase 7).
func runCIGrantCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "gssh-admin: ci-grant requires a subcommand (list, create, update, delete)")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runCIGrantList(ctx, rest, stdout, stderr)
	case "create":
		return runCIGrantCreate(ctx, rest, stdout, stderr)
	case "update":
		return runCIGrantUpdate(ctx, rest, stdout, stderr)
	case "delete":
		return runCIGrantDelete(ctx, rest, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "gssh-admin: unknown ci-grant subcommand %q\n", sub)
		return 2
	}
}

func runCIGrantList(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin ci-grant list", flag.ContinueOnError)
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
	grants, err := apiClient.listCIGrants(ctx)
	if err != nil {
		return fail(stderr, err)
	}
	printCIGrants(stdout, grants)
	return 0
}

// printCIGrants prints CI grants as a table.
func printCIGrants(w io.Writer, grants []CIGrant) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tPROJECT\tREF\tPROTECTED\tENV\tTAGS\tPRINCIPALS\tMAX-VALIDITY")
	for _, g := range grants {
		ref := g.RefPattern
		if ref == "" {
			ref = "*"
		}
		env := g.EnvironmentPattern
		if env == "" {
			env = "*"
		}
		protectedOnly := true
		if g.ProtectedOnly != nil {
			protectedOnly = *g.ProtectedOnly
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%t\t%s\t%s\t%s\t%s\n",
			g.ID, g.Project, ref, protectedOnly, env, formatTags(g.TagSelector),
			strings.Join(g.Principals, ","),
			time.Duration(g.MaxValiditySeconds)*time.Second)
	}
	_ = tw.Flush()
}

// ciGrantFlags are the content flags shared by ci-grant create/update.
type ciGrantFlags struct {
	refPattern    string
	protectedOnly bool
	environment   string
	tags          string
	principals    string
	maxValidity   time.Duration
}

func (c *ciGrantFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.refPattern, "ref", "", "ref glob, e.g. main or release/* (empty = all refs)")
	fs.BoolVar(&c.protectedOnly, "protected-only", true, "protected refs only (ref_protected)")
	fs.StringVar(&c.environment, "environment", "", "environment glob (empty = no condition)")
	fs.StringVar(&c.tags, "tags", "", "tag selector, e.g. env=prod,role=web (empty = all hosts)")
	fs.StringVar(&c.principals, "principals", "", "target principals, e.g. deploy (required for create)")
	fs.DurationVar(&c.maxValidity, "max-validity", time.Hour, "maximum certificate validity")
}

func runCIGrantCreate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin ci-grant create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	var grantFlags ciGrantFlags
	grantFlags.register(fs)
	project := fs.String("project", "", "gitlab project or group path (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	principals := splitList(grantFlags.principals)
	if *project == "" || len(principals) == 0 {
		fmt.Fprintln(stderr, "gssh-admin: --project and --principals are required")
		return 2
	}
	tags, err := parseTags(grantFlags.tags)
	if err != nil {
		return fail(stderr, err)
	}
	apiClient, err := common.connect(ctx, stderr)
	if err != nil {
		return fail(stderr, err)
	}
	created, err := apiClient.createCIGrant(ctx, &CIGrant{
		Project:            *project,
		RefPattern:         grantFlags.refPattern,
		ProtectedOnly:      &grantFlags.protectedOnly,
		EnvironmentPattern: grantFlags.environment,
		TagSelector:        tags,
		Principals:         principals,
		MaxValiditySeconds: int64(grantFlags.maxValidity / time.Second),
	})
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "ci-grant created: %s (project %s)\n", created.ID, created.Project)
	return 0
}

func runCIGrantUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin ci-grant update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	var grantFlags ciGrantFlags
	grantFlags.register(fs)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "gssh-admin: ci-grant update <id> [flags]")
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
	current, err := apiClient.getCIGrant(ctx, id)
	if err != nil {
		return fail(stderr, err)
	}
	if changed["ref"] {
		current.RefPattern = grantFlags.refPattern
	}
	if changed["protected-only"] {
		current.ProtectedOnly = &grantFlags.protectedOnly
	}
	if changed["environment"] {
		current.EnvironmentPattern = grantFlags.environment
	}
	if changed["tags"] {
		tags, err := parseTags(grantFlags.tags)
		if err != nil {
			return fail(stderr, err)
		}
		current.TagSelector = tags
	}
	if changed["principals"] {
		current.Principals = splitList(grantFlags.principals)
	}
	if changed["max-validity"] {
		current.MaxValiditySeconds = int64(grantFlags.maxValidity / time.Second)
	}
	updated, err := apiClient.updateCIGrant(ctx, id, current)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "ci-grant updated: %s (project %s)\n", updated.ID, updated.Project)
	return 0
}

func runCIGrantDelete(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin ci-grant delete", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "gssh-admin: ci-grant delete <id>")
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
	if err := apiClient.deleteCIGrant(ctx, id); err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "ci-grant deleted: %s\n", id)
	return 0
}
