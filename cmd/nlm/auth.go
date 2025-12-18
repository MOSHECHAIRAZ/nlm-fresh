package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tmc/nlm/internal/auth"
	"golang.org/x/term"
)

// maskProfileName masks sensitive profile names in debug output
func maskProfileName(profile string) string {
	if profile == "" {
		return ""
	}
	if len(profile) > 8 {
		return profile[:4] + "****" + profile[len(profile)-4:]
	} else if len(profile) > 2 {
		return profile[:2] + "****"
	}
	return "****"
}

// AuthOptions contains the CLI options for the auth command
type AuthOptions struct {
	TryAllProfiles  bool
	ProfileName     string
	TargetURL       string
	CheckNotebooks  bool
	Debug           bool
	Help            bool
	KeepOpenSeconds int
	ServerMode      bool // New flag for extension automation
}

func parseAuthFlags(args []string) (*AuthOptions, []string, error) {
	authFlags := flag.NewFlagSet("auth", flag.ContinueOnError)

	opts := &AuthOptions{
		ProfileName: chromeProfile,
		TargetURL:   "https://notebooklm.google.com",
	}

	authFlags.BoolVar(&opts.TryAllProfiles, "all", false, "Try all available browser profiles")
	authFlags.BoolVar(&opts.TryAllProfiles, "a", false, "Try all available browser profiles (shorthand)")
	authFlags.StringVar(&opts.ProfileName, "profile", opts.ProfileName, "Specific Chrome profile to use")
	authFlags.StringVar(&opts.ProfileName, "p", opts.ProfileName, "Specific Chrome profile to use (shorthand)")
	authFlags.StringVar(&opts.TargetURL, "url", opts.TargetURL, "Target URL to authenticate against")
	authFlags.StringVar(&opts.TargetURL, "u", opts.TargetURL, "Target URL to authenticate against (shorthand)")
	authFlags.BoolVar(&opts.CheckNotebooks, "notebooks", false, "Check notebook count for profiles")
	authFlags.BoolVar(&opts.CheckNotebooks, "n", false, "Check notebook count for profiles (shorthand)")
	authFlags.BoolVar(&opts.Debug, "debug", debug, "Enable debug output")
	authFlags.BoolVar(&opts.Debug, "d", debug, "Enable debug output (shorthand)")
	authFlags.BoolVar(&opts.Help, "help", false, "Show help for auth command")
	authFlags.BoolVar(&opts.Help, "h", false, "Show help for auth command (shorthand)")
	authFlags.IntVar(&opts.KeepOpenSeconds, "keep-open", 0, "Keep browser open for N seconds after successful auth")
	authFlags.IntVar(&opts.KeepOpenSeconds, "k", 0, "Keep browser open for N seconds after successful auth (shorthand)")

	// The new flag for automation
	authFlags.BoolVar(&opts.ServerMode, "server", false, "Start local server to receive credentials from Chrome Extension")

	authFlags.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nlm auth [login] [options] [profile-name]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		authFlags.PrintDefaults()
	}

	filteredArgs := make([]string, 0, len(args))
	for _, arg := range args {
		if arg != "login" {
			filteredArgs = append(filteredArgs, arg)
		}
	}

	err := authFlags.Parse(filteredArgs)
	if err != nil {
		return nil, nil, err
	}

	if opts.Help {
		authFlags.Usage()
		return nil, nil, fmt.Errorf("help shown")
	}

	remainingArgs := authFlags.Args()
	if !opts.TryAllProfiles && opts.ProfileName == "" && len(remainingArgs) > 0 {
		opts.ProfileName = remainingArgs[0]
		remainingArgs = remainingArgs[1:]
	}

	if !opts.TryAllProfiles && opts.ProfileName == "" {
		opts.ProfileName = "Default"
		if v := os.Getenv("NLM_BROWSER_PROFILE"); v != "" {
			opts.ProfileName = v
		}
	}

	return opts, remainingArgs, nil
}

func handleAuth(args []string, debug bool) (string, string, error) {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-help" || arg == "help" {
			parseAuthFlags([]string{"--help"})
			return "", "", nil
		}
	}

	opts, _, err := parseAuthFlags(args)
	if err != nil {
		if err.Error() == "help shown" {
			return "", "", nil
		}
		return "", "", fmt.Errorf("error parsing auth flags: %w", err)
	}

	// === NEW LOGIC: Server Mode ===
	if opts.ServerMode {
		return startLocalAuthServer()
	}
	// ==============================

	isTty := term.IsTerminal(int(os.Stdin.Fd()))
	forceBrowser := false
	for _, arg := range args {
		if arg == "login" {
			forceBrowser = true
			break
		}
	}

	if !isTty && !forceBrowser {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			input, err := io.ReadAll(os.Stdin)
			if err != nil {
				return "", "", fmt.Errorf("failed to read stdin: %w", err)
			}
			if len(input) > 0 {
				return detectAuthInfo(string(input))
			}
		}
	}

	if opts.TryAllProfiles {
		fmt.Fprintf(os.Stderr, "nlm: trying all browser profiles...\n")
	} else {
		maskedProfile := maskProfileName(opts.ProfileName)
		fmt.Fprintf(os.Stderr, "nlm: launching browser to login... (profile:%v)\n", maskedProfile)
	}

	useDebug := opts.Debug || debug
	a := auth.New(useDebug)
	authOpts := []auth.Option{auth.WithScanBeforeAuth(), auth.WithTargetURL(opts.TargetURL)}

	if opts.TryAllProfiles {
		authOpts = append(authOpts, auth.WithTryAllProfiles())
	} else {
		authOpts = append(authOpts, auth.WithProfileName(opts.ProfileName))
	}
	if opts.CheckNotebooks {
		authOpts = append(authOpts, auth.WithCheckNotebooks())
	}
	if opts.KeepOpenSeconds > 0 {
		authOpts = append(authOpts, auth.WithKeepOpenSeconds(opts.KeepOpenSeconds))
	}

	token, cookies, err := a.GetAuth(authOpts...)
	if err != nil {
		return "", "", fmt.Errorf("browser auth failed: %w", err)
	}

	return persistAuthToDisk(cookies, token, opts.ProfileName)
}

// startLocalAuthServer listens for credentials from the Chrome Extension
func startLocalAuthServer() (string, string, error) {
	port := "36400"
	fmt.Printf("🔵 nlm is listening for credentials on http://127.0.0.1:%s...\n", port)
	fmt.Println("👉 Please click the 'Extract Credentials' button in the Chrome Extension now.")

	resultChan := make(chan struct {
		token   string
		cookies string
	})

	server := &http.Server{Addr: ":" + port}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS to allow extension to talk to us
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var data struct {
			Token   string `json:"NLM_AUTH_TOKEN"`
			Cookies string `json:"NLM_COOKIES"`
		}

		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		fmt.Fprintln(w, "Received!")
		resultChan <- struct{ token, cookies string }{data.Token, data.Cookies}
	})

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
	}()

	// Wait for result or timeout (2 minutes)
	select {
	case res := <-resultChan:
		server.Close()
		fmt.Println("✅ Credentials received from extension!")
		return persistAuthToDisk(res.cookies, res.token, "Extension")
	case <-time.After(120 * time.Second):
		server.Close()
		return "", "", fmt.Errorf("timeout waiting for extension")
	}
}

func detectAuthInfo(cmd string) (string, string, error) {
	cookieRe := regexp.MustCompile(`-H ['"]cookie: ([^'"]+)['"]`)
	cookieMatch := cookieRe.FindStringSubmatch(cmd)
	if len(cookieMatch) < 2 {
		return "", "", fmt.Errorf("no cookies found in input")
	}
	cookies := cookieMatch[1]

	atRe := regexp.MustCompile(`at=([^&\s]+)`)
	atMatch := atRe.FindStringSubmatch(cmd)
	if len(atMatch) < 2 {
		return "", "", fmt.Errorf("no auth token found")
	}
	authToken := atMatch[1]
	persistAuthToDisk(cookies, authToken, "")
	return authToken, cookies, nil
}

func persistAuthToDisk(cookies, authToken, profileName string) (string, string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", "", fmt.Errorf("get home dir: %w", err)
	}

	nlmDir := filepath.Join(homeDir, ".nlm")
	if err := os.MkdirAll(nlmDir, 0700); err != nil {
		return "", "", fmt.Errorf("create .nlm directory: %w", err)
	}

	envFile := filepath.Join(nlmDir, "env")
	content := fmt.Sprintf("NLM_COOKIES=%q\nNLM_AUTH_TOKEN=%q\nNLM_BROWSER_PROFILE=%q\n",
		cookies,
		authToken,
		profileName,
	)

	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		return "", "", fmt.Errorf("write env file: %w", err)
	}

	fmt.Printf("✅ Credentials successfully saved to: %s\n", envFile)
	return authToken, cookies, nil
}

func loadStoredEnv() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	data, err := os.ReadFile(filepath.Join(home, ".nlm", "env"))
	if err != nil {
		return
	}

	s := bufio.NewScanner(strings.NewReader(string(data)))
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if _, isSet := os.LookupEnv(key); isSet {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		os.Setenv(key, value)
	}
}

func refreshCredentials(debugFlag bool) error {
	debug := debugFlag
	for _, arg := range os.Args {
		if arg == "-debug" || arg == "--debug" {
			debug = true
			break
		}
	}
	loadStoredEnv()
	cookies := os.Getenv("NLM_COOKIES")
	if cookies == "" {
		return fmt.Errorf("no stored credentials found")
	}
	refreshClient, err := auth.NewRefreshClient(cookies)
	if err != nil {
		return fmt.Errorf("failed to create refresh client: %w", err)
	}
	if debug {
		refreshClient.SetDebug(true)
		fmt.Fprintf(os.Stderr, "nlm: refreshing credentials...\n")
	}
	gsessionID := "LsWt3iCG3ezhLlQau_BO2Gu853yG1uLi0RnZlSwqVfg"
	if err := refreshClient.RefreshCredentials(gsessionID); err != nil {
		return fmt.Errorf("failed to refresh credentials: %w", err)
	}
	fmt.Fprintf(os.Stderr, "nlm: credentials refreshed successfully\n")
	return nil
}
