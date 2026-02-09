# Vault Audit Analyzer

## Prerequisites
You need **Go (Golang)** installed to run this tool.
* **Mac:** `brew install go`
* **Windows/Linux:** [Download Go Here](https://go.dev/dl/)

## Quick Start (Run from Source)
1. **Clone the repository:**
   ```bash
   git clone https://github.com/slavicadev/vault-analyzer-audit.git
   cd vault-analyzer-audit
2. **Run the tool directly with Go:**
   ```bash
   go run main.go path/to/audit.log

## Configuration (Rules)

* **Default Rules:** The tool comes with built-in rules (embedded in the code), so it works out-of-the-box.
* **Custom Rules:** To override the defaults, simply create a `rules.json` file in this folder. The tool will automatically prioritize your local file.

## 🤝 How to Contribute (Add New Rules)
If you found a new error pattern, you can help by adding it.

**The Easy Way (Browser only):**
1. Open [`rules.json`](rules.json) in this repository.
2. Click the **(Pencil Icon)** in the top right to edit the file.
3. Add your new rule to the list following this format:
   ```json
   {
     "pattern": "unique error string from log",
     "advice": "Actionable advice on how to fix it."
   },


