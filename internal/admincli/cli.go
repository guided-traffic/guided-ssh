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

// envIDToken übergibt ein fertiges ID-Token (z. B. aus CI) und überspringt
// den interaktiven OIDC-Flow.
const envIDToken = "GSSH_ID_TOKEN" //nolint:gosec // Name der Env-Variable, kein Secret

// Run führt das Admin-CLI aus und liefert den Exit-Code (0 ok, 1 Fehler,
// 2 Aufruffehler).
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
	case "apply":
		return runApplyCmd(ctx, rest, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gssh-admin: unbekanntes kommando %q\n\n", command)
		usage(stderr)
		return 2
	}
}

// usage gibt die Kommandoübersicht aus.
func usage(w io.Writer) {
	fmt.Fprint(w, `gssh-admin — zugriffsregeln (grants) verwalten (guided-ssh)

kommandos:
  grant list
        alle zugriffsregeln anzeigen
  grant create --group <name> --principals <p1,p2> [--tags k=v,…]
               [--sudo] [--max-validity 8h] [--issuer url]
        zugriffsregel anlegen (gruppe wird bei bedarf angelegt)
  grant update <id> [--principals …] [--tags …] [--sudo=true|false] [--max-validity …]
        zugriffsregel ändern (nur angegebene felder)
  grant delete <id>
        zugriffsregel löschen
  apply -f grants.yaml
        deklarativer abgleich: datei ist der zielzustand (gitops)
  version
        version ausgeben

gemeinsame flags: --config <pfad>, --token <id-token>, --device
authentifizierung: --token, sonst GSSH_ID_TOKEN, sonst oidc-login (browser
bzw. --device); erfordert mitgliedschaft in der admin-gruppe des servers.
`)
}

// commonFlags registriert die für alle Kommandos gemeinsamen Flags.
type commonFlags struct {
	configPath string
	token      string
	device     bool
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&c.configPath, "config", "", "pfad zur konfigurationsdatei")
	fs.StringVar(&c.token, "token", "", "fertiges oidc-id-token (überspringt den login)")
	fs.BoolVar(&c.device, "device", false, "device-flow statt browser (headless)")
}

// connect lädt die Konfiguration, besorgt ein ID-Token und baut den Client.
func (c *commonFlags) connect(ctx context.Context, stderr io.Writer) (*client, error) {
	path := cli.ResolveConfigPath(c.configPath)
	if path == "" {
		return nil, errors.New("kein konfigurationspfad ermittelbar (HOME nicht gesetzt?)")
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
		token, err = cli.FetchIDToken(ctx, cfg, c.device, stderr)
		if err != nil {
			return nil, err
		}
	}
	return newClient(cfg, token)
}

// runGrantCmd verzweigt in die grant-Subkommandos.
func runGrantCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "gssh-admin: grant braucht ein subkommando (list, create, update, delete)")
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
		fmt.Fprintf(stderr, "gssh-admin: unbekanntes grant-subkommando %q\n", sub)
		return 2
	}
}

// fail gibt den Fehler aus und liefert Exit-Code 1.
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

// printGrants gibt Grants tabellarisch aus.
func printGrants(w io.Writer, grants []Grant) {
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tGRUPPE\tTAGS\tPRINCIPALS\tSUDO\tMAX-LAUFZEIT")
	for _, g := range grants {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%t\t%s\n",
			g.ID, g.Group, formatTags(g.TagSelector),
			strings.Join(g.Principals, ","), g.Sudo,
			time.Duration(g.MaxValiditySeconds)*time.Second)
	}
	_ = tw.Flush()
}

// formatTags rendert einen Tag-Selektor als k=v,…; leer = alle Hosts.
func formatTags(tags map[string]string) string {
	if len(tags) == 0 {
		return "*"
	}
	pairs := make([]string, 0, len(tags))
	for k, v := range tags {
		pairs = append(pairs, k+"="+v)
	}
	slices.Sort(pairs) // stabile Ausgabe
	return strings.Join(pairs, ",")
}

// parseTags parst "k=v,k2=v2" in eine Map.
func parseTags(raw string) (map[string]string, error) {
	tags := map[string]string{}
	if raw == "" {
		return tags, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(pair, "=")
		if !found || key == "" {
			return nil, fmt.Errorf("ungültiges tag %q (erwartet key=value)", pair)
		}
		tags[key] = value
	}
	return tags, nil
}

// splitList parst eine Komma-Liste ohne Leereinträge.
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
	group := fs.String("group", "", "idp-gruppe (pflicht)")
	issuer := fs.String("issuer", "", "issuer der gruppe (default: issuer des tokens)")
	tagsFlag := fs.String("tags", "", "tag-selektor, z. B. env=prod,role=web (leer = alle hosts)")
	principalsFlag := fs.String("principals", "", "ziel-principals, z. B. deploy,root (pflicht)")
	sudo := fs.Bool("sudo", false, "sudo-berechtigung markieren")
	maxValidity := fs.Duration("max-validity", 16*time.Hour, "maximale zertifikatslaufzeit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	principals := splitList(*principalsFlag)
	if *group == "" || len(principals) == 0 {
		fmt.Fprintln(stderr, "gssh-admin: --group und --principals sind pflicht")
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
	fmt.Fprintf(stdout, "grant angelegt: %s (gruppe %s)\n", created.ID, created.Group)
	return 0
}

func runGrantUpdate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin grant update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	tagsFlag := fs.String("tags", "", "neuer tag-selektor (k=v,…)")
	principalsFlag := fs.String("principals", "", "neue ziel-principals (komma-liste)")
	sudo := fs.Bool("sudo", false, "sudo-berechtigung")
	maxValidity := fs.Duration("max-validity", 0, "neue maximale laufzeit")
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
	fmt.Fprintf(stdout, "grant aktualisiert: %s (gruppe %s)\n", updated.ID, updated.Group)
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
	fmt.Fprintf(stdout, "grant gelöscht: %s\n", id)
	return 0
}

func runApplyCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gssh-admin apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs)
	file := fs.String("f", "", "pfad zur grants.yaml (pflicht)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *file == "" {
		fmt.Fprintln(stderr, "gssh-admin: apply -f <grants.yaml>")
		return 2
	}
	grants, err := loadGrantsFile(*file)
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
	fmt.Fprintf(stdout, "abgleich fertig: %d angelegt, %d aktualisiert, %d gelöscht, %d unverändert\n",
		result.Created, result.Updated, result.Deleted, result.Unchanged)
	return 0
}
