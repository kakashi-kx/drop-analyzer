#!/usr/bin/env python3
# dropreport v0.1 — One-command incident dropzone analyzer
# Part of drop-analyzer: https://github.com/kakashi-kx/drop-analyzer

import os
import sys
import tempfile
import hashlib
import math
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import box

console = Console()

# Configuration
TEMP_DIR = Path(tempfile.mkdtemp(prefix="dropreport_"))
EXTRACTED = TEMP_DIR / "extracted"
EXTRACTED.mkdir(exist_ok=True)

# Threat weights
WEIGHTS = {
    "cobaltstrike_beacon": 96,
    "malicious_lnk": 89,
    "macro_malicious": 91,
    "high_entropy": 75,
    "exe_packed": 80,
}

# Built-in YARA rules
YARA_RULES = '''
rule CobaltStrike_Beacon {
    strings:
        $mz = "MZ"
        $s1 = "ReflectiveLoader" ascii
        $s2 = "%s as %s\\%s" ascii
        $s3 = "www.reversing.cc" ascii
    condition:
        $mz at 0 and 2 of ($s*)
}

rule Malicious_LNK {
    strings:
        $lnk = { 4c 00 00 00 01 14 02 00 }
        $ps = "powershell" nocase
        $enc = "-enc " ascii
        $enc2 = "-EncodedCommand" ascii
    condition:
        $lnk at 0 and (any of ($ps, $enc, $enc2))
}

rule Macro_Malicious {
    strings:
        $autoopen = "AutoOpen" ascii
        $shell = "Shell" ascii
        $wscript = "WScript.Shell" ascii
        $powershell = "powershell" nocase
    condition:
        all of them
}
'''

def sha256(file_path):
    """Calculate SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hasher.update(chunk)
    return hasher.hexdigest()

def entropy(file_path):
    """Calculate Shannon entropy of a file (0-8)."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except:
        return 0.0
        
    if not data:
        return 0.0
        
    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    # Calculate entropy
    ent = 0.0
    for count in freq:
        if count > 0:
            probability = count / len(data)
            ent -= probability * math.log2(probability)
    
    return round(ent, 2)

def run_cmd(cmd):
    """Execute shell command and return output."""
    try:
        result = subprocess.check_output(
            cmd, 
            shell=True, 
            stderr=subprocess.STDOUT,
            timeout=10
        ).decode('utf-8', errors='ignore')
        return result
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8', errors='ignore')
    except Exception:
        return ""

def extract_archive(archive_path):
    """Extract archive using 7z."""
    console.log(f"[dim]Extracting {archive_path.name}...[/dim]")
    
    # Check if 7z is available
    if not run_cmd("which 7z").strip():
        console.print("[red]Error: 7z not found. Install with: sudo apt install p7zip-full[/]")
        return False
    
    # Extract archive
    cmd = f"7z x -y -o{EXTRACTED} '{archive_path}' >/dev/null 2>&1"
    result = run_cmd(cmd)
    
    # Verify extraction worked
    extracted_files = list(EXTRACTED.rglob("*"))
    if not extracted_files:
        console.print("[yellow]Warning: No files extracted. Archive might be empty or corrupted.[/]")
    
    return len(extracted_files) > 0

def quick_scan_file(file_path):
    """Analyze a single file for suspicious indicators."""
    findings = []
    score = 0
    
    # Skip very small files
    file_size = file_path.stat().st_size
    if file_size < 20:
        return None
    
    # 1. High entropy detection
    if file_size > 100:
        ent = entropy(file_path)
        if ent > 7.0:
            findings.append(f"High entropy ({ent}/8.0)")
            score += WEIGHTS["high_entropy"]
    
    # 2. YARA rule matching
    try:
        import yara
        rules = yara.compile(source=YARA_RULES)
        matches = rules.match(str(file_path))
        
        for match in matches:
            rule_name = match.rule.lower().replace("_", "")
            findings.append(f"YARA: {match.rule}")
            score += WEIGHTS.get(rule_name, 80)
    except ImportError:
        findings.append("YARA engine not available")
    except Exception as e:
        pass
    
    # 3. Executable packing detection
    if file_path.suffix.lower() in ['.exe', '.dll', '.sys']:
        output = run_cmd(f"file '{file_path}'")
        if "UPX" in output or "ASPack" in output or "packed" in output.lower():
            findings.append("Packed executable")
            score += WEIGHTS["exe_packed"]
    
    # 4. Suspicious LNK files
    if file_path.suffix.lower() == '.lnk':
        output = run_cmd(f"strings '{file_path}'")
        if "powershell" in output.lower():
            if "-enc" in output or "-EncodedCommand" in output or "IEX" in output:
                findings.append("Malicious LNK (PowerShell)")
                score += WEIGHTS["malicious_lnk"]
    
    # 5. Office document analysis
    office_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf']
    if file_path.suffix.lower() in office_extensions:
        output = run_cmd(f"strings '{file_path}' | grep -i -E 'AutoOpen|AutoExec|Shell|WScript' | head -5")
        if output:
            findings.append("Suspicious Office macro")
            score += 40
    
    # Return results if score > 0
    if score > 0 or findings:
        return {
            "path": file_path.relative_to(EXTRACTED),
            "score": min(score, 100),
            "findings": findings,
            "sha256": sha256(file_path),
            "size": file_size
        }
    
    return None

def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        console.print("[bold red]Usage: dropreport <file_or_folder_or_archive>[/]")
        console.print("[dim]Example: dropreport suspicious.zip[/]")
        sys.exit(1)
    
    target = Path(sys.argv[1]).resolve()
    
    # Validate input
    if not target.exists():
        console.print(f"[red]Error: '{sys.argv[1]}' not found.[/]")
        sys.exit(1)
    
    # Display header
    console.print(Panel.fit(
        "[bold cyan]drop-analyzer v0.1[/] — Instant Incident Dropzone Triage",
        border_style="cyan",
        box=box.DOUBLE
    ))
    
    # Process input
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        
        progress.add_task("Initializing...", total=None)
        
        # Clean extraction directory
        run_cmd(f"rm -rf '{EXTRACTED}'/* 2>/dev/null")
        
        # Handle different input types
        if target.is_file() and target.suffix.lower() in ['.zip', '.7z', '.rar', '.tar', '.gz', '.xz']:
            if not extract_archive(target):
                console.print("[red]Failed to extract archive. Exiting.[/]")
                sys.exit(1)
        elif target.is_dir():
            # Copy directory contents
            run_cmd(f"cp -r '{target}/'* '{EXTRACTED}/' 2>/dev/null || true")
        else:
            # Single file
            run_cmd(f"cp '{target}' '{EXTRACTED}/' 2>/dev/null")
        
        # Collect files to analyze
        all_files = []
        for item in EXTRACTED.rglob("*"):
            if item.is_file() and item.stat().st_size > 0:
                all_files.append(item)
        
        if not all_files:
            console.print("[yellow]No files to analyze.[/]")
            console.print(f"\n[dim]Temporary directory: {TEMP_DIR}[/]")
            sys.exit(0)
        
        console.print(f"[green]✓ Found {len(all_files)} file(s) to analyze[/green]")
        
        # Analyze each file
        results = []
        task = progress.add_task("Analyzing files...", total=len(all_files))
        
        for file_path in all_files:
            try:
                result = quick_scan_file(file_path)
                if result:
                    results.append(result)
            except Exception:
                pass
            finally:
                progress.update(task, advance=1)
    
    # Sort by score (highest first)
    results.sort(key=lambda x: x["score"], reverse=True)
    top_results = results[:10]  # Show top 10
    
    # Display results table
    if top_results:
        table = Table(
            title=f"Top {len(top_results)} Suspicious Artifacts",
            box=box.ROUNDED,
            header_style="bold magenta"
        )
        
        table.add_column("Score", justify="center", style="bold")
        table.add_column("File", style="cyan")
        table.add_column("Size", justify="right")
        table.add_column("Findings", style="yellow")
        
        for result in top_results:
            # Color-code scores
            score = result["score"]
            if score >= 80:
                score_display = f"[bold red]{score}/100[/]"
            elif score >= 60:
                score_display = f"[bold yellow]{score}/100[/]"
            else:
                score_display = f"[green]{score}/100[/]"
            
            # Format size
            size = result["size"]
            if size > 1024*1024:
                size_display = f"{size/(1024*1024):.1f} MB"
            elif size > 1024:
                size_display = f"{size/1024:.1f} KB"
            else:
                size_display = f"{size} B"
            
            # Join findings
            findings = " • ".join(result["findings"][:3])
            
            table.add_row(
                score_display,
                str(result["path"]),
                size_display,
                findings
            )
        
        console.print()
        console.print(table)
        
        if len(results) > 10:
            console.print(f"[dim]... and {len(results) - 10} more files analyzed[/dim]")
    else:
        console.print("\n[green]✓ No suspicious files detected.[/]")
    
    # Footer
    console.print(f"\n[dim]Detailed files in: {TEMP_DIR}")
    console.print("[bold green]★ Star drop-analyzer on GitHub if this helped! ★[/]")

if __name__ == "__main__":
    # Check Python version
    if sys.version_info < (3, 8):
        print("Error: Python 3.8+ required")
        sys.exit(1)
    
    # Check for required modules
    try:
        import rich
    except ImportError:
        print("Error: Required module 'rich' not installed")
        print("Install with: pip install rich")
        sys.exit(1)
    
    main()
