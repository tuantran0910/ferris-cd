#!/usr/bin/env ruby
# frozen_string_literal: true

# Merges the per-crate CycloneDX BOMs emitted by `cargo cyclonedx` into one workspace BOM.
#
# `cargo-cyclonedx` 0.5.x writes one BOM per package next to its `Cargo.toml`; it has no
# workspace-aggregation mode (`--top-level` means "only direct dependencies", which would drop
# ~95% of the graph). Release builds therefore merge all package BOMs here, deduplicating
# components and dependency edges by `bom-ref`.

require "json"

output = ARGV.shift
abort "usage: merge-cyclonedx.rb <output.json> <input.cdx.json>..." if output.nil? || ARGV.empty?

merged = nil
components = {}
dependencies = {}

ARGV.each do |file|
  document = JSON.parse(File.read(file))
  merged ||= document

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

metadata = merged["metadata"] || {}
metadata["component"] = {
  "type" => "application",
  "bom-ref" => "ferriscd@workspace",
  "name" => "ferriscd",
  "version" => ENV.fetch("VERSION", "0.0.0")
}
merged["metadata"] = metadata
merged["components"] = components.values.sort_by { |component| [component["name"].to_s, component["version"].to_s] }
merged["dependencies"] = dependencies.values.sort_by { |dependency| dependency["ref"] }

File.write(output, "#{JSON.pretty_generate(merged)}\n")
puts "merged #{ARGV.length} BOMs into #{output}: #{merged["components"].length} components"
