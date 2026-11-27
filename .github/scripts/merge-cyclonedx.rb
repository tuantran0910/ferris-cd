#!/usr/bin/env ruby
# frozen_string_literal: true

# Merges the per-crate CycloneDX BOMs emitted by `cargo cyclonedx` into one workspace BOM.
#
# `cargo-cyclonedx` 0.5.x writes one BOM per package next to its `Cargo.toml`; it has no
# workspace-aggregation mode (`--top-level` means "only direct dependencies", which would drop
# ~95% of the graph). Release builds therefore merge all package BOMs here.
#
# Each input BOM only lists its own dependency closure in `components`, and the package itself is
# carried as `metadata.component` (the CLI crate is a leaf, so it appears *only* there). The merge
# therefore seeds the component set from every input's `metadata.component` and drops dependency
# edges whose refs do not resolve, keeping the output valid CycloneDX.

require "json"
require "set"

output = ARGV.shift
abort "usage: merge-cyclonedx.rb <output.json> <input.cdx.json>..." if output.nil? || ARGV.empty?

inputs = ARGV
merged = nil
components = {}
dependencies = {}

inputs.each do |file|
  document = JSON.parse(File.read(file))
  merged ||= document

  root = document.dig("metadata", "component")
  if root.is_a?(Hash)
    key = root["bom-ref"] || root["purl"] || [root["name"], root["version"]].join("@")
    components[key] ||= root
  end

  (document["components"] || []).each do |component|
    key = component["bom-ref"] || component["purl"] || [component["name"], component["version"]].join("@")
    components[key] ||= component
  end

  (document["dependencies"] || []).each do |dependency|
    ref = dependency["ref"] || dependency["bom-ref"]
    next if ref.nil?

    entry = (dependencies[ref] ||= { "ref" => ref, "dependsOn" => [] })
    entry["dependsOn"] |= (dependency["dependsOn"] || [])
  end
end

workspace_root = {
  "type" => "application",
  "bom-ref" => "ferriscd@workspace",
  "name" => "ferriscd",
  "version" => ENV.fetch("VERSION", "0.0.0")
}
components["ferriscd@workspace"] ||= workspace_root
known_refs = components.keys.to_set

merged["metadata"] ||= {}
merged["metadata"]["component"] = workspace_root
merged["components"] = components.values.sort_by { |component| [component["name"].to_s, component["version"].to_s] }
merged["dependencies"] = dependencies
  .select { |ref, _| known_refs.include?(ref) }
  .values
  .each { |dependency| dependency["dependsOn"] = dependency["dependsOn"].select { |ref| known_refs.include?(ref) } }
  .sort_by { |dependency| dependency["ref"] }

File.write(output, "#{JSON.pretty_generate(merged)}\n")
puts "merged #{inputs.length} BOMs into #{output}: #{merged["components"].length} components, " \
     "#{merged["dependencies"].length} dependency entries"
