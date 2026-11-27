#!/usr/bin/env ruby
# frozen_string_literal: true

# Supply-chain policy checks for FerrisCD (`T17.5`).
#
# Shared by `.github/workflows/ci.yml` (every PR) and
# `.github/workflows/security-audit.yml` (weekly cron) so the enforced policy and the
# documented one cannot drift:
#   1. every third-party `uses:` is pinned to a full 40-char commit SHA;
#   2. no workflow signs a mutable tag, and no long-lived cosign key material exists;
#   3. every cargo-deny / cargo-audit advisory exception carries a reason and an unexpired date.

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
#    Shell line continuations are joined first so cosmetic reformatting cannot bypass the checks.
release = ".github/workflows/release.yml"
if File.exist?(release)
  joined = File.read(release).gsub(/\\\n\s*/, " ")

  joined.each_line do |line|
    next unless line =~ /^\s*cosign\s+(sign|attest|verify)/

    unless line.include?("${IMAGE_REF}")
      errors << "#{release}: cosign must target ${IMAGE_REF} (immutable digest), got: #{line.strip}"
    end

    if line =~ /needs\.metadata\.outputs\.(tag|version)/
      errors << "#{release}: cosign must never interpolate a mutable tag/version output: #{line.strip}"
    end
  end
end

Dir.glob(".github/**/*").select { |path| File.file?(path) && path != ".github/scripts/check-supply-chain.rb" }.each do |file|
  source = File.read(file)
  errors << "#{file}: long-lived cosign key material reference" if source =~ /COSIGN_PRIVATE_KEY|COSIGN_PASSWORD|cosign\.key/
end

# 3. Time-bounded advisory exceptions must stay live in both policy files.
def check_expiry(errors, label, id, expiry)
  if expiry.nil?
    errors << "#{label}: advisory exception #{id} is missing an `expires: YYYY-MM-DD` annotation"
    return
  end

  errors << "#{label}: advisory exception #{id} expired on #{expiry}" if Date.today > Date.parse(expiry)
rescue ArgumentError
  errors << "#{label}: advisory exception #{id} has a malformed expiry `#{expiry}`"
end

deny = File.read("deny.toml")
deny.scan(/\{\s*id\s*=\s*"([^"]+)"(.*?)\}/m).each do |id, body|
  errors << "deny.toml: advisory exception #{id} is missing a reason" unless body.include?("reason =")
  check_expiry(errors, "deny.toml", id, body[/expires:\s*(\d{4}-\d{2}-\d{2})/, 1])
end

# cargo-deny also accepts bare-string entries, which would bypass the table-form policy.
ignore_body = deny[/ignore\s*=\s*\[(.*?)\n\]/m, 1].to_s
ignore_body.each_line do |line|
  errors << "deny.toml: advisory exception #{Regexp.last_match(1)} must use table form with `reason` and `expires:`" if line =~ /^\s*"([^"]+)"/
end

audit = File.read(".cargo/audit.toml")
audit.scan(/^\s*"([^"]+)"\s*,?/).flatten.each do |id|
  position = audit.index(%("#{id}"))
  window = audit[[position - 500, 0].max...position].to_s
  check_expiry(errors, ".cargo/audit.toml", id, window[/Expires:\s*(\d{4}-\d{2}-\d{2})/, 1])
end

if errors.empty?
  puts "OK: #{workflows.length} workflows enforce immutable SHA pins."
  puts "OK: cosign targets only immutable digests; no long-lived cosign keys found."
  puts "OK: every cargo-deny/cargo-audit advisory exception is documented and unexpired."
else
  abort(errors.join("\n"))
end
