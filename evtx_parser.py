#!/usr/bin/env python3
import argparse
import xmltodict
from Evtx.Evtx import Evtx
from tabulate import tabulate
from colorama import Fore, Style, init
import os
import sys
import re
import csv

# Initialize colorama
init(autoreset=True)

def error(msg):
    print(Fore.RED + Style.BRIGHT + "[ERROR] " + msg + Style.RESET_ALL)

def warn(msg):
    print(Fore.YELLOW + "[WARNING] " + msg + Style.RESET_ALL)

def info(msg):
    print(Fore.CYAN + "[INFO] " + msg + Style.RESET_ALL)

def evtx_to_xml(file_path):
    if not os.path.exists(file_path):
        error(f"File not found: {file_path}")
        sys.exit(1)
    try:
        evtx_record = []
        with Evtx(file_path) as logs:
            for evtx_lines in logs.records():
                evtx_record.append(evtx_lines.xml())
        if not evtx_record:
            warn("No records found in EVTX file.")
        return evtx_record
    except Exception as e:
        error(f"Failed to parse EVTX file: {e}")
        sys.exit(1)

def xml_to_json(file_path):
    xml_record = []
    for xml_lines in evtx_to_xml(file_path):
        try:
            xml_data = xmltodict.parse(xml_lines)
            xml_record.append(xml_data)
        except Exception as e:
            error(f"Failed to convert XML to JSON: {e}")
    if not xml_record:
        warn("No XML records converted to JSON.")
    return xml_record

def parse_and_display(file_path, filter_eventid=None, filter_provider=None, filter_pid=None, filter_regex=None, output_format="table"):
    json_data = xml_to_json(file_path)
    if not json_data:
        error("No JSON data available to parse.")
        return

    table_data = []
    for idx, record in enumerate(json_data, start=1):
        try:
            event = record.get("Event", {})
            system = event.get("System", {})
            execution = system.get("Execution", {})
            eventdata = event.get("EventData")

            pid = execution.get("@ProcessID")
            tid = execution.get("@ThreadID")
            event_id = system.get("EventID")
            provider = system.get("Provider", {}).get("@Name")
            time_created = system.get("TimeCreated", {}).get("@SystemTime")
            computer = system.get("Computer")
            channel = system.get("Channel")
            security_userid = system.get("Security", {}).get("@UserID")

            # Extract ScriptBlockText if present
            script_block = None
            if eventdata and "Data" in eventdata:
                data_field = eventdata.get("Data")
                if isinstance(data_field, list):
                    for d in data_field:
                        if d.get("@Name") == "ScriptBlockText":
                            script_block = d.get("#text")
                elif isinstance(data_field, dict):
                    if data_field.get("@Name") == "ScriptBlockText":
                        script_block = data_field.get("#text")

            # Apply filters
            if filter_eventid and str(event_id) != str(filter_eventid):
                continue
            if filter_provider and provider != filter_provider:
                continue
            if filter_pid and str(pid) != str(filter_pid):
                continue
            if filter_regex and script_block:
                try:
                    if not re.search(filter_regex, script_block, re.IGNORECASE):
                        continue
                except re.error as e:
                    error(f"Invalid regex pattern: {e}")
                    sys.exit(1)

            table_data.append([
                f"{Fore.CYAN}{pid}{Style.RESET_ALL}" if pid else "-",
                f"{Fore.YELLOW}{tid}{Style.RESET_ALL}" if tid else "-",
                f"{Fore.GREEN}{event_id}{Style.RESET_ALL}" if event_id else "-",
                f"{Fore.MAGENTA}{provider}{Style.RESET_ALL}" if provider else "-",
                f"{Fore.BLUE}{time_created}{Style.RESET_ALL}" if time_created else "-",
                f"{Fore.WHITE}{computer}{Style.RESET_ALL}" if computer else "-",
                f"{Fore.LIGHTBLACK_EX}{channel}{Style.RESET_ALL}" if channel else "-",
                f"{Fore.RED}{security_userid}{Style.RESET_ALL}" if security_userid else "-",
                f"{Fore.LIGHTYELLOW_EX}{script_block}{Style.RESET_ALL}" if script_block else "-"
            ])
        except Exception as e:
            error(f"Failed to parse record {idx}: {e}")

    if not table_data:
        warn("No records matched your filters.")
    else:
        if output_format == "csv":
            csv_file = "evtx_output.csv"
            try:
                with open(csv_file, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "ProcessID", "ThreadID", "EventID", "Provider",
                        "TimeCreated", "Computer", "Channel", "UserID", "ScriptBlockText"
                    ])
                    for row in table_data:
                        # Strip ANSI color codes before writing
                        clean_row = [re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", str(cell)) for cell in row]
                        writer.writerow(clean_row)
                info(f"Results exported to {csv_file}")
            except Exception as e:
                error(f"Failed to export CSV: {e}")
        else:
            print(tabulate(
                table_data,
                headers=[
                    f"{Fore.CYAN}ProcessID{Style.RESET_ALL}",
                    f"{Fore.YELLOW}ThreadID{Style.RESET_ALL}",
                    f"{Fore.GREEN}EventID{Style.RESET_ALL}",
                    f"{Fore.MAGENTA}Provider{Style.RESET_ALL}",
                    f"{Fore.BLUE}TimeCreated{Style.RESET_ALL}",
                    f"{Fore.WHITE}Computer{Style.RESET_ALL}",
                    f"{Fore.LIGHTBLACK_EX}Channel{Style.RESET_ALL}",
                    f"{Fore.RED}UserID{Style.RESET_ALL}",
                    f"{Fore.LIGHTYELLOW_EX}ScriptBlockText{Style.RESET_ALL}"
                ],
                tablefmt="fancy_grid"
            ))

def main():
    parser = argparse.ArgumentParser(description="Cyber Hunter EVTX Parser")
    parser.add_argument("-f", "--file", required=True, help="Path to EVTX file")
    parser.add_argument("--eventid", help="Filter by EventID")
    parser.add_argument("--provider", help="Filter by Provider name")
    parser.add_argument("--pid", help="Filter by ProcessID")
    parser.add_argument("--regex", help="Filter ScriptBlockText using regex")
    parser.add_argument("--output", choices=["table", "csv"], default="table", help="Output format")
    parser.add_argument("--help-filters", action="store_true", help="Show filter cheat sheet")
    args = parser.parse_args()

    if args.help_filters:
        print(Fore.CYAN + Style.BRIGHT + "\n=== Filter Cheat Sheet ===\n")
        print(Fore.YELLOW + "--eventid <ID>       " + Style.RESET_ALL + "Filter by EventID (e.g., 4104 for PowerShell script execution)")
        print(Fore.GREEN + "--provider <Name>    " + Style.RESET_ALL + "Filter by Provider (e.g., Microsoft-Windows-PowerShell)")
        print(Fore.MAGENTA + "--pid <ProcessID>    " + Style.RESET_ALL + "Filter by ProcessID")
        print(Fore.LIGHTYELLOW_EX + "--regex <pattern>    " + Style.RESET_ALL + "Filter ScriptBlockText using regex (e.g., 'Invoke-WebRequest')")
        print(Fore.BLUE + "--output <format>    " + Style.RESET_ALL + "Choose output format: table (default) or csv")
        print(Fore.LIGHTBLACK_EX + "Combine filters for precision hunting!\n")
        sys.exit(0)

    parse_and_display(args.file, args.eventid, args.provider, args.pid, args.regex, args.output)

if __name__ == "__main__":
    main()
