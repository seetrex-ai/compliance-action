# tests/fixtures/contract/validate.jq -- a minimal JSON Schema (2020-12)
# validator, for the keywords reader contract 1 uses and nothing more:
# $ref (local "#/$defs/..."; siblings of $ref apply too, as in 2020-12),
# type, const, enum, pattern, minLength, maxLength, minimum, maximum,
# properties, required, additionalProperties: false, minProperties, items,
# minItems, maxItems, uniqueItems, oneOf. Any other keyword is an error, so
# a contract that starts using one fails loudly instead of passing.
#
#   jq -n --slurpfile schema <schema.json> --slurpfile doc <doc.json> \
#     [--arg def <name of a $defs entry, or "">] -f validate.jq
# Output: the list of errors (strings with a JSON path); [] = valid.

def known: ["$schema", "$id", "$defs", "$ref", "title", "description", "type", "const", "enum",
  "pattern", "minLength", "maxLength", "minimum", "maximum", "properties", "required",
  "additionalProperties", "minProperties", "items", "minItems", "maxItems", "uniqueItems", "oneOf"];

def type_ok($t):
  if $t == "integer" then type == "number" and . == floor
  else type == $t end;

def errs($root; $s; $p):
  . as $x
  | ([$s | keys[] | select(IN(known[]) | not)] | if length > 0 then "\($p): unknown keyword \(.)" else empty end),
    (if $s["$ref"] then
       errs($root; ($root | getpath($s["$ref"] | ltrimstr("#/") | split("/"))); $p)
     else empty end),
    (if $s | has("type") then (if ($x | type_ok($s.type)) then empty else "\($p): not \($s.type)" end) else empty end),
    (if $s | has("const") then (if $x == $s.const then empty else "\($p): not the const" end) else empty end),
    (if $s | has("enum") then (if [$s.enum[] | . == $x] | any then empty else "\($p): not in the enum" end) else empty end),
    (if ($s | has("pattern")) and ($x | type) == "string" then
       (if ($x | test($s.pattern)) then empty else "\($p): does not match the pattern" end) else empty end),
    (if ($s | has("minLength")) and ($x | type) == "string" and ($x | length) < $s.minLength then "\($p): too short" else empty end),
    (if ($s | has("maxLength")) and ($x | type) == "string" and ($x | length) > $s.maxLength then "\($p): too long" else empty end),
    (if ($s | has("minimum")) and ($x | type) == "number" and $x < $s.minimum then "\($p): below the minimum" else empty end),
    (if ($s | has("maximum")) and ($x | type) == "number" and $x > $s.maximum then "\($p): above the maximum" else empty end),
    (if ($x | type) == "object" then
       (if $s | has("required") then ($s.required[] | select(. as $k | $x | has($k) | not) | "\($p): missing \(.)") else empty end),
       (if $s.additionalProperties == false then
          ($x | keys[] | select(. as $k | ($s.properties // {}) | has($k) | not) | "\($p): extra key \(.)")
        else empty end),
       (if ($s | has("minProperties")) and ($x | length) < $s.minProperties then "\($p): too few keys" else empty end),
       (if $s | has("properties") then
          ($s.properties | to_entries[] | . as $e | select($x | has($e.key))
           | $x[$e.key] | errs($root; $e.value; "\($p).\($e.key)"))
        else empty end)
     else empty end),
    (if ($x | type) == "array" then
       (if ($s | has("minItems")) and ($x | length) < $s.minItems then "\($p): too few items" else empty end),
       (if ($s | has("maxItems")) and ($x | length) > $s.maxItems then "\($p): too many items" else empty end),
       (if $s.uniqueItems == true and ($x | length) != ($x | unique | length) then "\($p): items not unique" else empty end),
       (if $s | has("items") then
          ($x | to_entries[] | .key as $i | .value | errs($root; $s.items; "\($p)[\($i)]"))
        else empty end)
     else empty end),
    (if $s | has("oneOf") then
       ([$s.oneOf[] as $b | [$x | errs($root; $b; $p)] | length == 0] | map(select(.)) | length) as $n
       | if $n == 1 then empty else "\($p): \($n) branches of oneOf match, not one" end
     else empty end);

$schema[0] as $root
| (if ($def // "") == "" then $root else $root["$defs"][$def] end) as $s
| [$doc[0] | errs($root; $s; "$")]
