#!/usr/bin/env ruby
# frozen_string_literal: true

# Supply-chain policy checks for FerrisCD (`T17.5`).
#
# Shared by `.github/workflows/ci.yml` (every PR) and
# `.github/workflows/security-audit.yml` (weekly cron) so the enforced policy and the
# documented one cannot drift:
#   1. every third-party `uses:` is pinned to a full 40-char commit SHA;
#   2. no workflow signs a mutable tag, and no long-lived cosign key material exists;
#   3. every cargo-deny advisory exception carries a reason and an unexpired date.

require "date"

ROOT = File.expand_path("../..", __dir__)
Dir.chdir(ROOT)

errors = []
workflows = Dir.glob(".github/workflows/*.{yml,yaml}").sort

# 1. Immutable action pins.
workflows.each do |file|
  File.readlines(file).each_with_index do |line, idx|
    next unless line =~ /^\s*-?\s*uses:\s*([^\s#]+)/

    ref = Regexp.last_match(1).gsub(/\A["']|["']\z/, "")
    next if ref.start_with?("./", "docker://")

    unless ref =~ %r{\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}\z}
      errors << "#{file}:#{idx + 1}: unpinned action reference `#{ref}` (must pin 40-char commit SHA)"
    end
  end
end

# 2. The T17.5 Trap Guard: sign by immutable digest only, never a mutable tag or key.
release = ".github/workflows/release.yml"
if File.exist?(release)
  File.readlines(release).each_with_index do |line, idx|
    next unless line =~ /cosign\s+(sign|attest)/

    unless line.include?('${IMAGE_REF}')
      errors << "#{release}:#{idx + 1}: cosign must target ${IMAGE_REF} (immutable digest), got: #{line.strip}"
    end
  end

  if File.readlines(release).grep(/needs\.metadata\.outputs\.(tag|version).*cosign/).any?
    errors << "#{release}: cosign must never interpolate a mutable tag/version output"
  end
end

Dir.glob(".github/**/*").select { |path| File.file?(path) && !path.start_with?(".github/scripts/") }.each do |file|
  source = File.read(file)
  errors << "#{file}: long-lived cosign key material reference" if source =~ /COSIGN_PRIVATE_KEY|COSIGN_PASSWORD|cosign\.key/
end

# 3. Time-bounded advisory exceptions in `deny.toml` must stay live.
deny = File.read("deny.toml")
deny.scan(/\{\s*id\s*=\s*"([^"]+)"(.*?)\}/m).each do |id, body|
  errors << "deny.toml: advisory exception #{id} is missing a reason" unless body.include?("reason =")

  if body =~ /expires:\s*(\d{4}-\d{2}-\d{2})/
    errors << "deny.toml: advisory exception #{id} expired on #{Regexp.last_match(1)}" if Date.today > Date.parse(Regexp.last_match(1))
  else
    errors << "deny.toml: advisory exception #{id} is missing an `expires: YYYY-MM-DD` annotation"
  end
end

if errors.empty?
  puts "OK: #{workflows.length} workflows enforce immutable SHA pins."
  puts "OK: cosign targets only immutable digests; no long-lived cosign keys found."
  puts "OK: every deny.toml advisory exception is documented and unexpired."
else
  abort(errors.join("\n"))
end
