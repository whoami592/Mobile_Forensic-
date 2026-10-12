// Mobile Forensics Toolkit
// coded by Mr Sabaz Ali Khan - Cyber Security Engineer
//
// Read-only analysis of LAWFULLY ACQUIRED mobile data (extracted backups,
// filesystem dumps, evidence folders). No device exploitation, no writes
// to evidence. Standard library only.
package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const banner = `⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⡃⣦⣸⣿⣾⣿⣟⣯⢀⡀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣯⡐⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⣸⣾⣷⣴⣶⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⣷⣶⣦⣼⣿⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠲⣠⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⣿⣧⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣼⣿⣷⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⠣⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠤⣠⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢀⠀⠀⠀⠀⠀⠀⠀
⡀⠤⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢀⡇⠀⠀⠀⠀⠀⠀
⠈⠙⣿⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⣿⣿⣿⡉⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀
⠀⣾⣿⣿⣿⣿⣟⢿⣿⡄⠀⠀⠀⠈⣿⣿⠇⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡖⠊⠀⠀⠀⠀⠀
⠀⠹⣿⣿⣿⣿⣭⡇⢉⡿⠀⠀⠀⢸⣿⣯⣀⣀⡤⠼⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀
⠈⢉⣹⢿⣿⣧⣸⡗⠚⠁⠀⠀⠀⠀⠉⠉⠉⠁⢀⣼⠄⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣳⣶⠀⠀⠀⠀⠀
⠀⣠⣾⡿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⣉⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀
⠀⢿⣿⣷⣿⣿⣿⣿⣶⣶⢶⣶⣄⠀⠀⢠⣶⣿⣿⡏⠙⠜⠋⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣷⠀⣠⠆⠀
⠀⠀⢀⠹⣿⣿⣿⡗⢉⠈⠬⠁⣛⠀⠀⠘⣿⣿⡯⠁⠠⠶⠾⠛⠉⠉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠃⠀⠀
⠀⠀⠸⣦⣼⣿⣿⣷⠀⠙⠚⠋⠀⢨⠀⠀⣿⣿⡄⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠦⠤⢄⣠⠎
⠀⠀⠀⠈⠛⢻⠿⣿⣧⠀⠀⠀⠀⢸⠀⠀⣿⣿⣷⣄⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀
⠀⠀⠀⠀⠀⠀⠀⢿⣿⣷⡄⠀⠀⠀⠀⠀⣿⣯⣭⣿⣷⣄⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠠⢤⣤⣿⣿⣿⣄⠀⠀⠠⠠⣿⡿⣿⠏⠁⠀⢳⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⣹⣿⣷⡀⠀⣀⣈⠀⣈⣤⠤⢴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠘⣿⣿⣦⡀⠀⠀⣁⣀⣰⡿⠿⢿⠟⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣷⡄⠀⠈⢙⠁⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡼⠟⠀⠀⠙⣦⣄⣈⣥⣤⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣯⠀⠀⠈⠙⠿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⣾⡿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⣸⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⡍⠻⠿⠿⠋⠁⠀⠀⠀⠐⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀`

const (
	toolName = "MOBILE FORENSICS TOOLKIT"
	version  = "1.0.0"
	credit   = "coded by Mr Sabaz Ali Khan - Cyber Security Engineer"
	maxScan  = 64 << 20 // max bytes read per file for IOC / table extraction
)

// ---------------------------------------------------------------- knowledge

// Known mobile artifact file names (lower-case) -> description.
var knownArtifacts = map[string]string{
	// iOS
	"sms.db":                       "iOS Messages (iMessage/SMS)",
	"addressbook.sqlitedb":         "iOS Contacts",
	"callhistory.storedata":        "iOS Call History",
	"manifest.db":                  "iOS Backup Manifest",
	"manifest.plist":               "iOS Backup Manifest (plist)",
	"info.plist":                   "iOS Backup Device Info",
	"status.plist":                 "iOS Backup Status",
	"knownnetworks.plist":          "iOS Known Wi-Fi Networks",
	"notestore.sqlite":             "iOS Notes",
	"photos.sqlite":                "iOS Photos Library DB",
	"safari/history.db":            "iOS Safari History",
	"history.db":                   "Safari/Browser History",
	"consolidated.db":              "iOS Legacy Location Cache",
	"cache.sqlite":                 "iOS Location Cache",
	"chatstorage.sqlite":           "WhatsApp (iOS) Chats",
	"locationd":                    "iOS Location Services",
	// Android
	"mmssms.db":                    "Android SMS/MMS",
	"contacts2.db":                 "Android Contacts",
	"calllog.db":                   "Android Call Log",
	"msgstore.db":                  "WhatsApp (Android) Messages",
	"wa.db":                        "WhatsApp (Android) Contacts",
	"telegram.db":                  "Telegram DB",
	"cache4.db":                    "Telegram Cache DB",
	"packages.xml":                 "Android Installed Packages",
	"packages.list":                "Android Installed Package List",
	"accounts.db":                  "Android Accounts",
	"accounts_ce.db":               "Android Accounts (CE)",
	"settings.db":                  "Android Settings",
	"webview.db":                   "Android WebView Data",
	"webviewcookieschromium.db":    "Android WebView Cookies",
	"wpa_supplicant.conf":          "Android Saved Wi-Fi Networks",
	"wificonfigstore.xml":          "Android Saved Wi-Fi (Config Store)",
	"bookmarks.db":                 "Browser Bookmarks",
	"downloads.db":                 "Android Download History",
	"usagestats":                   "Android Usage Stats",
	"gmm_storage.db":               "Google Maps Storage",
	"signal.sqlite":                "Signal DB",
	"cookies":                      "Browser Cookies",
	"login data":                   "Browser Saved Logins (Chromium)",
	"web data":                     "Browser Autofill (Chromium)",
}

type signature struct {
	magic  []byte
	offset int
	name   string
}

var signatures = []signature{
	{[]byte("SQLite format 3\x00"), 0, "SQLite database"},
	{[]byte("bplist00"), 0, "Binary plist"},
	{[]byte("<?xml"), 0, "XML / text plist"},
	{[]byte{0xFF, 0xD8, 0xFF}, 0, "JPEG image"},
	{[]byte{0x89, 'P', 'N', 'G'}, 0, "PNG image"},
	{[]byte("GIF8"), 0, "GIF image"},
	{[]byte("%PDF"), 0, "PDF document"},
	{[]byte{'P', 'K', 3, 4}, 0, "ZIP / APK / IPA / DOCX container"},
	{[]byte("dex\n"), 0, "Android DEX bytecode"},
	{[]byte{0x7F, 'E', 'L', 'F'}, 0, "ELF binary"},
	{[]byte{0xCA, 0xFE, 0xBA, 0xBE}, 0, "Mach-O fat / Java class"},
	{[]byte{0xCF, 0xFA, 0xED, 0xFE}, 0, "Mach-O 64-bit"},
	{[]byte("ftyp"), 4, "MP4 / MOV / HEIC media"},
	{[]byte("ID3"), 0, "MP3 audio"},
	{[]byte("OggS"), 0, "Ogg audio"},
	{[]byte("#!AMR"), 0, "AMR audio (voice note)"},
	{[]byte{0x1F, 0x8B}, 0, "GZIP archive"},
	{[]byte("7z\xBC\xAF"), 0, "7-Zip archive"},
}

var (
	reURL   = regexp.MustCompile(`https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,200}`)
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,100}\.[A-Za-z]{2,10}`)
	reIPv4  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	reTable = regexp.MustCompile(`CREATE TABLE (?:IF NOT EXISTS )?["'\x60\[]?([A-Za-z0-9_]+)`)
)

// ------------------------------------------------------------------ helpers

type fileInfo struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified_utc"`
	Type     string    `json:"type"`
	Artifact string    `json:"artifact,omitempty"`
}

func identify(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unreadable"
	}
	defer f.Close()
	buf := make([]byte, 32)
	n, _ := f.Read(buf)
	buf = buf[:n]
	for _, s := range signatures {
		end := s.offset + len(s.magic)
		if len(buf) >= end && bytes.Equal(buf[s.offset:end], s.magic) {
			return s.name
		}
	}
	return "unknown / raw data"
}

func hashFile(path string) (m, s1, s256 string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	hm, h1, h2 := md5.New(), sha1.New(), sha256.New()
	if _, err = io.Copy(io.MultiWriter(hm, h1, h2), f); err != nil {
		return
	}
	return hex.EncodeToString(hm.Sum(nil)), hex.EncodeToString(h1.Sum(nil)), hex.EncodeToString(h2.Sum(nil)), nil
}

func walk(root string, fn func(path string, info os.FileInfo)) error {
	return filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] skip %s: %v\n", p, err)
			return nil
		}
		if info.Mode().IsRegular() {
			fn(p, info)
		}
		return nil
	})
}

func readCapped(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, maxScan))
	return b
}

func matchArtifact(path string) string {
	lp := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(lp)
	if d, ok := knownArtifacts[base]; ok {
		return d
	}
	for k, d := range knownArtifacts {
		if strings.Contains(k, "/") && strings.HasSuffix(lp, k) {
			return d
		}
	}
	// iOS backups store files by SHA-1 name; flag the Manifest instead.
	return ""
}

func logCustody(action, target string) {
	host, _ := os.Hostname()
	fmt.Printf("[custody] %s | action=%s | target=%s | host=%s\n",
		time.Now().UTC().Format(time.RFC3339), action, target, host)
}

func mustDir(fs *flag.FlagSet) string {
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "[!] missing evidence path")
		fs.Usage()
		os.Exit(2)
	}
	p := fs.Arg(0)
	if _, err := os.Stat(p); err != nil {
		fmt.Fprintf(os.Stderr, "[!] cannot access %s: %v\n", p, err)
		os.Exit(1)
	}
	return p
}

// ----------------------------------------------------------------- commands

func cmdScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	out := fs.String("o", "", "write JSON findings to file")
	fs.Usage = func() { fmt.Println("usage: toolkit scan [-o findings.json] <evidence_dir>") }
	fs.Parse(args)
	root := mustDir(fs)
	logCustody("scan", root)

	var all []fileInfo
	types := map[string]int{}
	walk(root, func(p string, info os.FileInfo) {
		fi := fileInfo{Path: p, Size: info.Size(), Modified: info.ModTime().UTC(), Type: identify(p), Artifact: matchArtifact(p)}
		types[fi.Type]++
		all = append(all, fi)
	})

	fmt.Printf("\n=== Known mobile artifacts ===\n")
	found := 0
	for _, fi := range all {
		if fi.Artifact != "" {
			found++
			fmt.Printf("  [+] %-34s %s (%d bytes)\n      %s\n", fi.Artifact, fi.Type, fi.Size, fi.Path)
		}
	}
	if found == 0 {
		fmt.Println("  (none matched by name)")
	}

	fmt.Printf("\n=== File type summary (%d files) ===\n", len(all))
	keys := make([]string, 0, len(types))
	for k := range types {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return types[keys[i]] > types[keys[j]] })
	for _, k := range keys {
		fmt.Printf("  %6d  %s\n", types[k], k)
	}

	if *out != "" {
		b, _ := json.MarshalIndent(all, "", "  ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "[!] write failed:", err)
			return
		}
		fmt.Printf("\n[+] findings saved: %s\n", *out)
	}
}

func cmdHash(args []string) {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	out := fs.String("o", "manifest.csv", "output manifest CSV")
	examiner := fs.String("examiner", "", "examiner name for the manifest header")
	fs.Usage = func() { fmt.Println("usage: toolkit hash [-o manifest.csv] [-examiner NAME] <evidence_path>") }
	fs.Parse(args)
	root := mustDir(fs)
	logCustody("hash", root)

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		os.Exit(1)
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"# " + toolName + " " + version, credit})
	w.Write([]string{"# generated_utc", time.Now().UTC().Format(time.RFC3339), "examiner", *examiner})
	w.Write([]string{"path", "size", "modified_utc", "md5", "sha1", "sha256"})
	n := 0
	walk(root, func(p string, info os.FileInfo) {
		m, s1, s2, err := hashFile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s: %v\n", p, err)
			return
		}
		w.Write([]string{p, strconv.FormatInt(info.Size(), 10), info.ModTime().UTC().Format(time.RFC3339), m, s1, s2})
		n++
	})
	w.Flush()
	fmt.Printf("[+] hashed %d files -> %s\n", n, *out)
}

func cmdTimeline(args []string) {
	fs := flag.NewFlagSet("timeline", flag.ExitOnError)
	out := fs.String("o", "", "write timeline CSV to file (default: print top 50)")
	fs.Usage = func() { fmt.Println("usage: toolkit timeline [-o timeline.csv] <evidence_dir>") }
	fs.Parse(args)
	root := mustDir(fs)
	logCustody("timeline", root)

	var all []fileInfo
	walk(root, func(p string, info os.FileInfo) {
		all = append(all, fileInfo{Path: p, Size: info.Size(), Modified: info.ModTime().UTC(), Artifact: matchArtifact(p)})
	})
	sort.Slice(all, func(i, j int) bool { return all[i].Modified.After(all[j].Modified) })

	if *out == "" {
		for i, fi := range all {
			if i >= 50 {
				break
			}
			fmt.Printf("%s  %10d  %s\n", fi.Modified.Format("2006-01-02 15:04:05"), fi.Size, fi.Path)
		}
		return
	}
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!]", err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{"modified_utc", "size", "artifact", "path"})
	for _, fi := range all {
		w.Write([]string{fi.Modified.Format(time.RFC3339), strconv.FormatInt(fi.Size, 10), fi.Artifact, fi.Path})
	}
	w.Flush()
	fmt.Printf("[+] timeline of %d files -> %s\n", len(all), *out)
}

func cmdIOCs(args []string) {
	fs := flag.NewFlagSet("iocs", flag.ExitOnError)
	out := fs.String("o", "", "write indicators JSON to file")
	fs.Usage = func() { fmt.Println("usage: toolkit iocs [-o iocs.json] <evidence_dir>") }
	fs.Parse(args)
	root := mustDir(fs)
	logCustody("iocs", root)

	res := map[string]map[string]int{"urls": {}, "emails": {}, "ipv4": {}}
	walk(root, func(p string, info os.FileInfo) {
		data := readCapped(p)
		if len(data) == 0 {
			return
		}
		for _, m := range reURL.FindAll(data, -1) {
			res["urls"][string(m)]++
		}
		for _, m := range reEmail.FindAll(data, -1) {
			res["emails"][string(m)]++
		}
		for _, m := range reIPv4.FindAll(data, -1) {
			res["ipv4"][string(m)]++
		}
	})
	for _, cat := range []string{"urls", "emails", "ipv4"} {
		type kv struct {
			K string
			V int
		}
		var list []kv
		for k, v := range res[cat] {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].V > list[j].V })
		fmt.Printf("\n=== %s (%d unique) ===\n", strings.ToUpper(cat), len(list))
		for i, e := range list {
			if i >= 25 {
				fmt.Println("  ...")
				break
			}
			fmt.Printf("  %5d  %s\n", e.V, e.K)
		}
	}
	if *out != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		os.WriteFile(*out, b, 0o644)
		fmt.Printf("\n[+] indicators saved: %s\n", *out)
	}
}

func cmdTables(args []string) {
	fs := flag.NewFlagSet("tables", flag.ExitOnError)
	fs.Usage = func() { fmt.Println("usage: toolkit tables <database.db>") }
	fs.Parse(args)
	p := mustDir(fs)
	logCustody("tables", p)

	if identify(p) != "SQLite database" {
		fmt.Println("[!] not a SQLite database")
		return
	}
	seen := map[string]bool{}
	for _, m := range reTable.FindAllSubmatch(readCapped(p), -1) {
		seen[string(m[1])] = true
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Printf("[+] %d tables referenced in schema:\n", len(names))
	for _, n := range names {
		fmt.Println("   -", n)
	}
	fmt.Println("\n[i] open a COPY of this file in a SQLite viewer for row-level review.")
}

func cmdApk(args []string) {
	fs := flag.NewFlagSet("apk", flag.ExitOnError)
	fs.Usage = func() { fmt.Println("usage: toolkit apk <app.apk|app.ipa>") }
	fs.Parse(args)
	p := mustDir(fs)
	logCustody("apk", p)
	listArchive(p)
}

func usage() {
	fmt.Print(`
USAGE:  toolkit <command> [options] <path>

COMMANDS:
  scan      identify known Android/iOS artifacts + file types in an evidence folder
  hash      MD5/SHA1/SHA256 manifest of all files (integrity / chain of custody)
  timeline  modification-time timeline (CSV export)
  iocs      extract URLs, emails and IPv4 addresses from files
  tables    list tables referenced in a SQLite database
  apk       list contents of an APK/IPA archive

NOTES:
  * Works on lawfully acquired data (backups, dumps). Evidence is only READ.
  * Always work on a forensic copy and record hashes before analysis.
`)
}

func main() {
	fmt.Println(banner)
	fmt.Printf("\n   %s v%s\n   %s\n\n", toolName, version, credit)

	if len(os.Args) < 2 {
		usage()
		return
	}
	args := os.Args[2:]
	switch strings.ToLower(os.Args[1]) {
	case "scan":
		cmdScan(args)
	case "hash":
		cmdHash(args)
	case "timeline":
		cmdTimeline(args)
	case "iocs":
		cmdIOCs(args)
	case "tables":
		cmdTables(args)
	case "apk":
		cmdApk(args)
	default:
		usage()
	}
}
