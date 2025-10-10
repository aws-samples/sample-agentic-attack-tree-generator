#!/bin/bash
# JQ-style threat extraction for ThreatForest
# Usage: ./threat_jq.sh <file> [query_type]

FILE="$1"
QUERY="${2:-summary}"

if [[ ! -f "$FILE" ]]; then
    echo "❌ File not found: $FILE"
    exit 1
fi

case "$QUERY" in
    "summary")
        echo "📊 THREAT SUMMARY"
        jq -r '
        def get_priority(threat):
            if threat.metadata then
                (threat.metadata[] | select(.key == "Priority") | .value) // "Medium"
            else
                threat.priority // "Medium"
            end;
        
        if .threats then
            "📱 App: " + (.applicationInfo.name // "Unknown") + 
            "\n🔧 Tech: " + ((.applicationInfo.technologies // []) | join(", ")) +
            "\n🎯 Total Threats: " + (.threats | length | tostring) +
            "\n   High: " + ([.threats[] | select(get_priority(.) | ascii_downcase == "high")] | length | tostring) +
            "\n   Medium: " + ([.threats[] | select(get_priority(.) | ascii_downcase == "medium")] | length | tostring) +
            "\n   Low: " + ([.threats[] | select(get_priority(.) | ascii_downcase == "low")] | length | tostring)
        elif .threat_model then
            "📱 Generic Threat Model\n🎯 Threats: " + (.threat_model.threats | length | tostring)
        else
            "❓ Unknown format - use raw query"
        end' "$FILE"
        ;;
    
    "high")
        echo "🚨 HIGH PRIORITY THREATS"
        jq -r '
        def get_priority(threat):
            if threat.metadata then
                (threat.metadata[] | select(.key == "Priority") | .value) // "Medium"
            else
                threat.priority // "Medium"
            end;
        
        .threats[]? | select(get_priority(.) | ascii_downcase == "high") | "• " + .statement' "$FILE"
        ;;
    
    "context")
        echo "📱 APPLICATION CONTEXT"
        jq -r '
        if .applicationInfo then
            "Name: " + (.applicationInfo.name // "Unknown") +
            "\nDescription: " + (.applicationInfo.description // "None") +
            "\nTechnologies: " + ((.applicationInfo.technologies // []) | join(", "))
        else
            "No application context found"
        end' "$FILE"
        ;;
    
    "priorities")
        echo "📊 PRIORITY BREAKDOWN"
        jq -r '
        def get_priority(threat):
            if threat.metadata then
                (threat.metadata[] | select(.key == "Priority") | .value) // "Medium"
            else
                threat.priority // "Medium"
            end;
        
        [.threats[]? | get_priority(.)] | 
        group_by(.) | 
        map({priority: .[0], count: length}) | 
        .[] | 
        .priority + ": " + (.count | tostring)' "$FILE"
        ;;
    
    "extract")
        jq '
        def get_priority(threat):
            if threat.metadata then
                (threat.metadata[] | select(.key == "Priority") | .value) // "Medium"
            else
                threat.priority // "Medium"
            end;
        
        {
            application_context: {
                name: .applicationInfo.name,
                description: .applicationInfo.description,
                technologies: .applicationInfo.technologies
            },
            threats: [.threats[] | {
                id: .id,
                statement: .statement,
                priority: get_priority(.),
                impact: .threatImpact,
                source: .threatSource,
                action: .threatAction
            }],
            summary: {
                total: (.threats | length),
                high: ([.threats[] | select(get_priority(.) | ascii_downcase == "high")] | length),
                medium: ([.threats[] | select(get_priority(.) | ascii_downcase == "medium")] | length),
                low: ([.threats[] | select(get_priority(.) | ascii_downcase == "low")] | length)
            }
        }' "$FILE"
        ;;
    
    "raw")
        echo "🔍 RAW STRUCTURE"
        jq 'keys' "$FILE"
        ;;
    
    *)
        echo "Usage: $0 <file> [summary|high|context|priorities|extract|raw]"
        exit 1
        ;;
esac
