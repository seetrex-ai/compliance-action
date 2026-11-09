# Seetrex Compliance Action -- bin/doccheck.pl: decides whether a document of
# the closed list may be sent to the reader (bin/propose.sh, plan R4 section
# 2.1 step 3). No module is loaded: only the perl core.
#
#   perl "$GITHUB_ACTION_PATH/bin/doccheck.pl" <file>
#
# Prints ONE line and exits 0:
#   ok                  the document is UTF-8 text and no pattern matched
#   not_utf8            not well-formed UTF-8 (RFC 3629), or a NUL byte
#   credential <name>   the first credential pattern that matched, by name
# Exit 2 when the file cannot be read. Never prints a byte of the document.
#
# The credential patterns are a port of CREDENTIAL_PATTERNS of the reader's
# second pass (Seetrex repository, services/reader/filters.py, commit
# 8f4e1ac5), same names, same order, applied as there to the whole text
# (not line by line, so `\s*` may cross a line break as in Python). The text
# is decoded first, so `\s`, `\b` and the classes follow Unicode semantics as
# Python's str patterns do.
use strict;
use warnings;

my $path = shift @ARGV;
if (!defined $path || @ARGV) {
    print STDERR "doccheck.pl: usage: doccheck.pl <file>\n";
    exit 2;
}
open(my $fh, '<:raw', $path) or do { print STDERR "doccheck.pl: cannot read the file\n"; exit 2 };
my $bytes = do { local $/; <$fh> };
close($fh);
$bytes = '' unless defined $bytes;

# Well-formed UTF-8 (RFC 3629 section 4): no overlong form, no surrogate, no
# code point above U+10FFFF. A NUL byte is not text either.
my $utf8 = qr/\A(?:
      [\x01-\x7F]
    | [\xC2-\xDF][\x80-\xBF]
    | \xE0[\xA0-\xBF][\x80-\xBF]
    | [\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}
    | \xED[\x80-\x9F][\x80-\xBF]
    | \xF0[\x90-\xBF][\x80-\xBF]{2}
    | [\xF1-\xF3][\x80-\xBF]{3}
    | \xF4[\x80-\x8F][\x80-\xBF]{2}
)*\z/x;
if ($bytes !~ $utf8) {
    print "not_utf8\n";
    exit 0;
}
my $text = $bytes;
utf8::decode($text);

my $START = qr/(?<![A-Za-z0-9])/;
my $PLACEHOLDER = qr/(?-i:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Z_][A-Z0-9_]*|<[^<>\n]*>)/;
my $VALUE_END = qr/(?=[\s"',;)]|$)/;
my $NOT_PLACEHOLDER = qr/(?!${PLACEHOLDER}${VALUE_END})/;
my $TOKEN_VALUE = qr{(?=[A-Za-z0-9_\-./+=~]*[0-9])(?=[A-Za-z0-9_\-./+=~]*[A-Za-z])[A-Za-z0-9_\-./+=~]{16,}};

my @patterns = (
    [private_key_block => qr/-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY(?: BLOCK)?-----/],
    [aws_access_key_id => qr/${START}(?:AKIA|ASIA)[0-9A-Z]{16}\b/],
    [github_token => qr/${START}(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/],
    [github_fine_grained_pat => qr/${START}github_pat_[A-Za-z0-9_]{60,}\b/],
    [gitlab_token => qr/${START}glpat-[A-Za-z0-9\-_]{20,}\b/],
    [slack_token => qr/${START}xox[baprs]-[A-Za-z0-9\-]{10,}\b/],
    [slack_webhook => qr{(?i)hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9_\-]+/[A-Za-z0-9_\-/]{8,}}],
    [sendgrid_key => qr/${START}SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}/],
    [bearer_token => qr/(?i)${START}Bearer\s+['"]?${TOKEN_VALUE}/],
    [token_or_secret_assignment => qr/(?i)${START}(?:token|secret)['"]?\s*[:=]\s*['"]?${TOKEN_VALUE}/],
    [google_api_key => qr/${START}AIza[0-9A-Za-z_\-]{35}\b/],
    [llm_provider_key => qr/${START}sk-[A-Za-z0-9_\-]{20,}\b/],
    [stripe_key => qr/${START}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/],
    [npm_token => qr/${START}npm_[A-Za-z0-9]{36}\b/],
    [huggingface_token => qr/${START}hf_[A-Za-z0-9]{30,}\b/],
    [jwt => qr/${START}eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/],
    [azure_account_key => qr{(?i)${START}AccountKey\s*=\s*[A-Za-z0-9+/]{20,}={0,2}}],
    [url_with_credentials => qr{(?i)${START}[a-z][a-z0-9+.\-]*://[^\s/:@'"<>]+:[^\s/@'"<>]+@[^\s/@'"<>]}],
    [assignment_of_secret => qr/(?i)${START}(?:api[_-]?key|secret(?:[_-]?access)?[_-]?key|client[_-]?secret|password|passwd|pwd|auth[_-]?token|access[_-]?token|private[_-]?key)['"]?\s*[:=]\s*(?:"${NOT_PLACEHOLDER}[^"\n]{8,}"|'${NOT_PLACEHOLDER}[^'\n]{8,}'|${NOT_PLACEHOLDER}[^\s"'<>]{8,})/],
);

for my $p (@patterns) {
    if ($text =~ $p->[1]) {
        print "credential $p->[0]\n";
        exit 0;
    }
}
print "ok\n";
exit 0;
