#!/usr/bin/env ruby
# frozen_string_literal: true

# Merges Brakeman (SAST) and OWASP ZAP (DAST) output into one developer-readable
# markdown report. Explanations are written for the engineer fixing the code,
# not for a security auditor, so each CWE gets a plain-language cause + fix.

require "json"
require "optparse"
require "time"
require "fileutils"

CRITICAL_CWES = %w[77 78 89 94 470 502 918].freeze # RCE-class / full compromise if exploited

options = { brakeman: nil, zap: nil, out: "docs/security/latest-report.md" }
OptionParser.new do |opts|
  opts.on("--brakeman PATH") { |v| options[:brakeman] = v }
  opts.on("--zap PATH") { |v| options[:zap] = v }
  opts.on("--out PATH") { |v| options[:out] = v }
end.parse!

glossary_path = File.join(__dir__, "cwe_glossary.json")
GLOSSARY = JSON.parse(File.read(glossary_path))

def cwe_info(cwe_id)
  return { "name" => "Unclassified", "dev_explain" => "No CWE mapping available for this finding; see the raw scanner output for details." } if cwe_id.nil?

  GLOSSARY[cwe_id.to_s] || { "name" => "CWE-#{cwe_id}", "dev_explain" => "See https://cwe.mitre.org/data/definitions/#{cwe_id}.html for details." }
end

def load_json(path)
  return nil if path.nil? || !File.exist?(path) || File.zero?(path)

  JSON.parse(File.read(path))
rescue JSON::ParserError
  nil
end

Finding = Struct.new(:source, :severity, :cwe_id, :cwe_name, :title, :dev_explain, :location, :detail, keyword_init: true)

findings = []

# ---- Brakeman (SAST) ----
brakeman = load_json(options[:brakeman])
if brakeman
  Array(brakeman["warnings"]).each do |w|
    cwe_ids = Array(w["cwe_id"])
    cwe_id = cwe_ids.first
    confidence = (w["confidence"] || "Medium")
    severity =
      if CRITICAL_CWES.include?(cwe_id.to_s) && confidence == "High"
        "Critical"
      elsif confidence == "High"
        "High"
      elsif confidence == "Medium"
        "Medium"
      else
        "Low"
      end
    info = cwe_info(cwe_id)
    findings << Finding.new(
      source: "SAST (Brakeman)",
      severity: severity,
      cwe_id: cwe_id,
      cwe_name: info["name"],
      title: w["warning_type"] || w["check_name"],
      dev_explain: info["dev_explain"],
      location: "#{w['file']}:#{w['line']}",
      detail: w["message"]
    )
  end
end

# ---- ZAP (DAST) ----
zap = load_json(options[:zap])
if zap
  Array(zap["site"]).each do |site|
    Array(site["alerts"]).each do |alert|
      riskcode = alert["riskcode"].to_i
      cwe_id = alert["cweid"]
      base_severity =
        case riskcode
        when 3 then "High"
        when 2 then "Medium"
        else "Low"
        end
      severity = (CRITICAL_CWES.include?(cwe_id.to_s) && base_severity == "High") ? "Critical" : base_severity
      info = cwe_info(cwe_id)
      instances = Array(alert["instances"])
      locations = instances.first(3).map { |i| i["uri"] }.compact.join(", ")
      locations = "#{locations} (+#{instances.size - 3} more)" if instances.size > 3
      findings << Finding.new(
        source: "DAST (ZAP)",
        severity: severity,
        cwe_id: cwe_id,
        cwe_name: info["name"],
        title: alert["name"],
        dev_explain: info["dev_explain"],
        location: locations.empty? ? "(no URI reported)" : locations,
        detail: alert["desc"]&.gsub(/<\/?p>/, "")&.strip
      )
    end
  end
end

severities_order = %w[Critical High Medium Low]
by_severity = findings.group_by(&:severity)
critical_high = findings.select { |f| %w[Critical High].include?(f.severity) }

has_critical_or_high = critical_high.any?
FileUtils.mkdir_p(File.dirname(options[:out]))
FileUtils.mkdir_p("reports")
File.write("reports/has_critical_or_high.txt", has_critical_or_high ? "true" : "false")

md = +""
md << "# Security Pipeline Report\n\n"
md << "*Generated #{Time.now.utc.iso8601} — SAST via Brakeman, DAST via OWASP ZAP baseline scan, SCA via Dependabot.*\n\n"

md << "## Summary\n\n"
md << "| Severity | Count |\n|---|---|\n"
severities_order.each do |sev|
  md << "| #{sev} | #{(by_severity[sev] || []).size} |\n"
end
md << "| **Total** | **#{findings.size}** |\n\n"

if brakeman.nil? && zap.nil?
  md << "> No scanner output was found (both Brakeman and ZAP reports were missing or empty). This report only reflects Dependabot SCA alerts, which are tracked separately as their own PRs.\n\n"
end

md << "SCA (dependency) vulnerabilities are not duplicated here — Dependabot opens its own PR per vulnerable dependency; see the repo's Dependabot alerts tab.\n\n"

if has_critical_or_high
  md << "## Critical / High findings — action required\n\n"
  md << "These need a fix or a documented risk acceptance before merge. Each entry explains the *developer-facing* cause, not just the OWASP/CWE label.\n\n"

  critical_high.sort_by { |f| [severities_order.index(f.severity), f.source] }.each_with_index do |f, idx|
    cwe_label = f.cwe_id ? "CWE-#{f.cwe_id}: #{f.cwe_name}" : f.cwe_name
    md << "### #{idx + 1}. [#{f.severity}] #{f.title} — #{cwe_label}\n\n"
    md << "- **Source:** #{f.source}\n"
    md << "- **Where:** `#{f.location}`\n"
    md << "- **What this means for the code:** #{f.dev_explain}\n"
    md << "- **Scanner detail:** #{f.detail}\n\n" if f.detail && !f.detail.empty?
  end
else
  md << "## Critical / High findings\n\nNone detected in this scan. :white_check_mark:\n\n"
end

%w[Medium Low].each do |sev|
  items = by_severity[sev] || []
  next if items.empty?

  md << "<details>\n<summary>#{sev} findings (#{items.size}) — informational, not blocking</summary>\n\n"
  items.each do |f|
    cwe_label = f.cwe_id ? "CWE-#{f.cwe_id}: #{f.cwe_name}" : f.cwe_name
    md << "- **[#{f.source}]** #{f.title} (#{cwe_label}) — `#{f.location}`\n"
  end
  md << "\n</details>\n\n"
end

File.write(options[:out], md)
puts md
warn "\nhas_critical_or_high=#{has_critical_or_high}"
