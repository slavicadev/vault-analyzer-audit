package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

//go:embed rules.json
var defaultRulesFS embed.FS

// --- CONFIGURATION ---

type Rule struct {
	Pattern string `json:"pattern"`
	Advice  string `json:"advice"`
}

type VaultAudit struct {
	Time    string `json:"time"`
	Error   string `json:"error"`
	Request struct {
		Operation     string `json:"operation"`
		Path          string `json:"path"`
		RemoteAddress string `json:"remote_address"`
		Namespace     struct {
			Path string `json:"path"`
		} `json:"namespace"`
	} `json:"request"`
}

type Stats struct {
	Signature string
	Path      string
	ErrorMsg  string
	Count     int
	FirstTime time.Time
	LastTime  time.Time
	UniqueIPs map[string]bool
}

// --- MAIN EXECUTION ---

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: ./vault-analyzer <filename>")
		os.Exit(1)
	}

	targetFile := os.Args[1]
	
	// --- HYBRID RULE LOADING ---
	rules := loadRules()

	file, err := os.Open(targetFile)
	if err != nil {
		fmt.Printf("Error: Could not open file '%s'\n", targetFile)
		return
	}
	defer file.Close()

	// 2. PARSING & ACCUMULATION
	analysis := make(map[string]*Stats) 
	pathStats := make(map[string]int)
	rawErrorStats := make(map[string]int)

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		start := strings.Index(line, "{")
		if start == -1 { continue }

		var entry VaultAudit
		if err := json.Unmarshal([]byte(line[start:]), &entry); err != nil { continue }
		if entry.Error == "" { continue }

		// --- NO NORMALIZATION (Raw is Truth) ---
		rawErr := entry.Error

		// Collect Stats
		pathStats[entry.Request.Path]++
		rawErrorStats[rawErr]++

		cleanKey := strings.TrimSpace(rawErr)
		sig := fmt.Sprintf("%s|%s", entry.Request.Path, cleanKey)
		t, _ := time.Parse(time.RFC3339, entry.Time)

		if _, exists := analysis[sig]; !exists {
			analysis[sig] = &Stats{
				Signature: sig,
				Path:      entry.Request.Path,
				ErrorMsg:  rawErr, 
				FirstTime: t,
				LastTime:  t,
				UniqueIPs: make(map[string]bool),
			}
		}

		stat := analysis[sig]
		stat.Count++
		if t.Before(stat.FirstTime) { stat.FirstTime = t }
		if t.After(stat.LastTime) { stat.LastTime = t }
		if entry.Request.RemoteAddress != "" {
			stat.UniqueIPs[entry.Request.RemoteAddress] = true
		}
	}

	// 3. SORTING
	var sorted []*Stats
	for _, s := range analysis {
		sorted = append(sorted, s)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Count > sorted[j].Count
	})

	// 4. PRINTING REPORT
	fmt.Println("VAULT AUDIT ANALYSIS REPORT")
	fmt.Println(strings.Repeat("=", 80))
	
	for _, inc := range sorted {
		category := "DATA"
		if strings.HasPrefix(inc.Path, "sys/") {
			category = "SYS"
		} else if strings.HasPrefix(inc.Path, "auth/") {
			category = "AUTH"
		}

		advice := ""
		flatErr := strings.ReplaceAll(inc.ErrorMsg, "\n", " ")
		fullSig := fmt.Sprintf("%s %s", inc.Path, flatErr)
		
		for _, r := range rules {
			if strings.Contains(fullSig, r.Pattern) {
				advice = r.Advice
				break
			}
		}
		if advice == "" {
			advice = "Investigate this error pattern."
		}

		duration := inc.LastTime.Sub(inc.FirstTime)
		
		fmt.Printf("%-12s [%s]\n", "CATEGORY:", category)
		fmt.Printf("%-12s %d\n", "COUNT:", inc.Count)
		fmt.Printf("%-12s %s\n", "PATH:", inc.Path)
		fmt.Printf("%-12s %s\n", "ERROR:", cleanForDisplay(inc.ErrorMsg))
		
		fmt.Printf("%-12s %s -> %s (%s)\n", 
			"TIMEFRAME:",
			inc.FirstTime.Format("15:04:05"), 
			inc.LastTime.Format("15:04:05"), 
			duration)
			
		fmt.Printf("%-12s %v\n", "SOURCES:", mapToSortedSlice(inc.UniqueIPs))
		fmt.Printf("%-12s %s\n", "ANALYSIS:", advice)
		fmt.Println(strings.Repeat("-", 80))
	}

	// 5. SUMMARY 
	printSummary(pathStats, rawErrorStats)
}

// --- HELPER FUNCTIONS ---

func cleanForDisplay(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	s = strings.Join(strings.Fields(s), " ")
	return s
}

func loadRules() []Rule {
	var ruleData []byte
	var err error

	// 1. Check Disk
	ruleData, err = os.ReadFile("rules.json")
	if err == nil {
		fmt.Println("✅ Using local 'rules.json' override.")
	} else {
		// 2. Fallback to Embedded Binary
		ruleData, _ = defaultRulesFS.ReadFile("rules.json")
	}

	var r []Rule
	if len(ruleData) > 0 {
		json.Unmarshal(ruleData, &r)
	}
	return r
}

func printSummary(pathStats map[string]int, errorStats map[string]int) {
	fmt.Println("\nEXECUTIVE SUMMARY")
	fmt.Println(strings.Repeat("=", 80))

	fmt.Println("TOP FAILING PATHS (JSON):")
	printJSONStats(pathStats, "Path", 3)
	fmt.Println("")

	fmt.Println("TOP ERROR TYPES (JSON):")
	printRawErrorJSON(errorStats, 5) 
	fmt.Println(strings.Repeat("=", 80))
}

func printJSONStats(stats map[string]int, keyName string, n int) {
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range stats {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	for i, kv := range ss {
		if i >= n { break }
		cleanKey := strings.ReplaceAll(kv.Key, "\"", "\\\"")
		cleanKey = strings.ReplaceAll(cleanKey, "\n", "\\n")
		fmt.Printf("{\n  \"%s\": \"%s\",\n  \"Count\": %d\n}\n", keyName, cleanKey, kv.Value)
	}
}

func printRawErrorJSON(stats map[string]int, n int) {
	type kv struct {
		Key   string
		Value int
	}
	var ss []kv
	for k, v := range stats {
		ss = append(ss, kv{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	for i, kv := range ss {
		if i >= n { break }
		jsonKey := fmt.Sprintf("%q", kv.Key)
		fmt.Printf("{\n  \"Errors\": %s,\n  \"Count\": %d\n}\n", jsonKey, kv.Value)
	}
}

func mapToSortedSlice(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m { s = append(s, k) }
	sort.Strings(s)
	return s
}