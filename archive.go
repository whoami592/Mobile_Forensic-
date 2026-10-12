// coded by Mr Sabaz Ali Khan - Cyber Security Engineer
package main

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
)

// Entries worth a closer look when triaging an APK / IPA.
var interestingEntries = map[string]string{
	"androidmanifest.xml": "app manifest (permissions, components)",
	"classes.dex":         "main DEX bytecode",
	"resources.arsc":      "compiled resources",
	"info.plist":          "iOS app metadata",
	"embedded.mobileprovision": "iOS provisioning profile",
	"lib/":                "native libraries",
	"assets/":             "bundled assets",
	"meta-inf/":           "signing information",
}

func listArchive(path string) {
	r, err := zip.OpenReader(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "[!] not a readable ZIP/APK/IPA:", err)
		return
	}
	defer r.Close()

	fmt.Printf("[+] %d entries in %s\n\n", len(r.File), path)
	dex := 0
	for _, f := range r.File {
		name := strings.ToLower(f.Name)
		if strings.HasSuffix(name, ".dex") {
			dex++
		}
		note := ""
		for k, v := range interestingEntries {
			if name == k || (strings.HasSuffix(k, "/") && strings.Contains(name, k)) ||
				strings.HasSuffix(name, "/"+k) {
				note = "  <- " + v
				break
			}
		}
		if note != "" {
			fmt.Printf("  %-60s %10d%s\n", f.Name, f.UncompressedSize64, note)
		}
	}
	fmt.Printf("\n[i] DEX files: %d  (multiple DEX files are common in large apps)\n", dex)
	fmt.Println("[i] decode AndroidManifest.xml with apktool/aapt for permission review.")
}
