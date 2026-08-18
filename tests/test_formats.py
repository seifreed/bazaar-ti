"""Tests for the JSON / SARIF / TOON serializers."""

from __future__ import annotations

import json
from typing import Any

import pytest

from bazaar_ti.formats import (
    FORMATS,
    SARIF_SCHEMA,
    render,
    render_batch,
    to_json,
    to_sarif,
    to_toon,
)


@pytest.mark.parametrize("fmt", FORMATS)
def test_render_serializes_every_format_it_offers(fmt: str) -> None:
    """FORMATS is what --format offers, so render has to handle all of it.

    A name added to the tuple without a branch in render reaches its
    ValueError, and main() catches only BazaarTIError and OSError — so it
    would leave the CLI as a traceback rather than as a usage error.
    """
    assert render({"a": 1}, fmt)


def test_render_dispatch() -> None:
    data = {"a": 1}
    assert render(data, "json") == to_json(data)
    assert render(data, "toon") == to_toon(data)
    assert render(data, "sarif") == to_sarif(data)


@pytest.mark.parametrize("formatter", [to_json, to_sarif, to_toon])
def test_renderers_reject_non_finite_numbers(formatter: Any) -> None:
    with pytest.raises(ValueError, match="non-finite|Out of range float values"):
        formatter({"score": float("nan")})


def test_to_json_matches_stdlib() -> None:
    data = {"b": 2, "a": 1}
    assert to_json(data) == json.dumps(data, indent=2, sort_keys=True)


# --------------------------------------------------------------------------- #
# TOON
# --------------------------------------------------------------------------- #


def test_toon_spec_example() -> None:
    data = {
        "context": {
            "task": "Our favorite hikes together",
            "location": "Boulder",
            "season": "spring_2025",
        },
        "friends": ["ana", "luis", "sam"],
        "hikes": [
            {
                "id": 1,
                "name": "Blue Lake Trail",
                "distanceKm": 7.5,
                "elevationGain": 320,
                "companion": "ana",
                "wasSunny": True,
            }
        ],
    }
    expected = (
        "context:\n"
        "  task: Our favorite hikes together\n"
        "  location: Boulder\n"
        "  season: spring_2025\n"
        "friends[3]: ana,luis,sam\n"
        "hikes[1]{id,name,distanceKm,elevationGain,companion,wasSunny}:\n"
        "  1,Blue Lake Trail,7.5,320,ana,true"
    )
    assert to_toon(data) == expected


def test_toon_scalars_and_numbers() -> None:
    assert to_toon(None) == "null"
    assert to_toon(True) == "true"
    assert to_toon(False) == "false"
    assert to_toon(5) == "5"
    assert to_toon(1.5) == "1.5"
    # Floats round-trip exactly, matching what to_json emits for the same value.
    assert to_toon(0.0) == "0.0"
    assert to_toon(-0.0) == "-0.0"
    assert to_toon(1.0) == "1.0"
    assert to_toon(1e-6) == "1e-06"
    assert to_toon(1e20) == "1e+20"


@pytest.mark.parametrize("value", [1e-30, 1.5e-10, 1e-7, 1e30, 0.1, -2.5e-9])
def test_toon_small_floats_are_not_flattened_to_zero(value: float) -> None:
    # Expanding the exponent away used to round every |x| < 1e-6 down to "0".
    assert float(to_toon(value)) == value


def test_toon_string_quoting() -> None:
    assert to_toon({"a": ""}) == 'a: ""'
    assert to_toon({"a": " x"}) == 'a: " x"'
    assert to_toon({"a": "true"}) == 'a: "true"'
    assert to_toon({"a": "123"}) == 'a: "123"'
    assert to_toon({"a": "-x"}) == 'a: "-x"'
    assert to_toon({"a": "#x"}) == 'a: "#x"'
    assert to_toon({"a": "x,y"}) == 'a: "x,y"'
    assert to_toon({"a": "h:m"}) == 'a: "h:m"'
    assert to_toon({"a": "hello world"}) == "a: hello world"


def test_toon_escaping() -> None:
    assert to_toon('a\\b"c\nd\re\tf\x01g') == '"a\\\\b\\"c\\nd\\re\\tf\\u0001g"'


def test_toon_keys() -> None:
    assert to_toon({"my_key.x": 1}) == "my_key.x: 1"
    assert to_toon({"my-key": 1}) == '"my-key": 1'


def test_toon_nested_object_and_empties() -> None:
    assert to_toon({"a": {"b": 1}}) == "a:\n  b: 1"
    assert to_toon({"a": {}}) == "a:"
    assert to_toon({"a": []}) == "a: []"


def test_toon_root_forms() -> None:
    assert to_toon([1, 2, 3]) == "[3]: 1,2,3"
    assert to_toon([]) == "[]"
    assert to_toon("scalar") == "scalar"


def test_toon_tabular_and_non_tabular_arrays() -> None:
    assert to_toon({"rows": [{"a": 1, "b": 2}, {"a": 3, "b": 4}]}) == (
        "rows[2]{a,b}:\n  1,2\n  3,4"
    )
    # different keys -> not tabular -> list form
    assert to_toon({"x": [{"a": 1}, {"b": 2}]}) == "x[2]:\n  - a: 1\n  - b: 2"
    # nested-object column -> not tabular -> list form; the nested keys stay
    # indented past the "- ", not level with it
    assert to_toon({"x": [{"a": {"z": 1}}, {"a": {"z": 2}}]}) == (
        "x[2]:\n  - a:\n      z: 1\n  - a:\n      z: 2"
    )


def test_toon_list_item_kinds() -> None:
    # empty dict, primitive, nested list, and non-empty dict as list items
    assert to_toon({"x": [{}, {"a": 1}]}) == "x[2]:\n  -\n  - a: 1"
    assert to_toon({"x": [1, {"a": 1}]}) == "x[2]:\n  - 1\n  - a: 1"
    assert to_toon({"x": [[1, 2], {"a": 1}]}) == "x[2]:\n  - [2]: 1,2\n  - a: 1"


def test_toon_list_item_keeps_every_line() -> None:
    # A multi-key dict item: continuation keys align under the first, so they
    # read as members of the item rather than siblings of the list.
    assert to_toon({"x": [{"a": 1, "b": 2}, {"c": 3}]}) == "x[2]:\n  - a: 1\n    b: 2\n  - c: 3"
    # A multi-line nested array item keeps its rows instead of losing all but
    # the header line. A keyless header may not carry a field list outside the
    # document root, so a nested array of records takes the list-item form.
    assert to_toon({"x": [[{"a": 1}, {"a": 2}]]}) == "x[1]:\n  - [2]:\n    - a: 1\n    - a: 2"


def test_toon_nested_array_is_the_list_item_itself() -> None:
    """A keyless header on a hyphen line stands at the item's own depth.

    Encoding the inner array one level deeper left its items indented past
    where the header claimed them, and the reference decoder rejected it.
    """
    assert to_toon({"data": [[[1]]]}) == "data[1]:\n  - [1]:\n    - [1]: 1"
    # The spec forbids "- []"; an empty array in item position is "[0]:".
    # The bare root form and the keyed one are held above, in test_toon_root_forms
    # and test_toon_nested_object_and_empties.
    assert to_toon({"data": [[], [1]]}) == "data[2]:\n  - [0]:\n  - [1]: 1"


# --------------------------------------------------------------------------- #
# SARIF
# --------------------------------------------------------------------------- #


def _sarif(data: Any) -> Any:
    return json.loads(to_sarif(data))


def test_sarif_structure_and_records() -> None:
    records = [
        {"signature": "Emotet", "sha256_hash": "h", "file_name": "a.exe"},
        {"threat_type": "payload", "url": "http://x/"},
        {"md5_hash": "m"},
    ]
    doc = _sarif({"data": records})
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "bazaar-ti"
    results = doc["runs"][0]["results"]
    assert len(results) == len(records)
    assert results[0]["ruleId"] == "Emotet"
    assert results[0]["message"]["text"] == "h — a.exe — Emotet"
    assert "locations" not in results[0]
    assert results[0]["properties"]["sha256_hash"] == "h"
    assert results[1]["ruleId"] == "payload"
    assert results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://x/"
    assert results[2]["ruleId"] == "ioc"
    assert results[2]["message"]["text"] == "m"


def test_sarif_rule_id_prefers_the_most_specific_classification() -> None:
    record = {
        "ioc": "1.1.1.1",
        "signature": "Emotet",
        "malware_printable": "Emotet",
        "threat_type": "botnet_cc",
        "threat": "malware_download",
    }
    assert _sarif(record)["runs"][0]["results"][0]["ruleId"] == "Emotet"
    del record["signature"]
    del record["malware_printable"]
    assert _sarif(record)["runs"][0]["results"][0]["ruleId"] == "botnet_cc"


def test_sarif_rule_id_reads_the_urlhaus_threat_field() -> None:
    # A real URLhaus URL record: "threat" is its classification, and it is what
    # ThreatFox spells "threat_type". Unread, every URLhaus finding fell back
    # to the "ioc" placeholder while carrying a classification of its own.
    record = {
        "url": "http://45.61.49.78/razor/r4z0r.mips",
        "host": "45.61.49.78",
        "threat": "malware_download",
        "tags": ["elf", "mirai"],
    }
    assert _sarif(record)["runs"][0]["results"][0]["ruleId"] == "malware_download"


def test_sarif_rule_id_falls_back_when_nothing_classifies_the_record() -> None:
    # tags is a list on every abuse.ch response, so no rule id can come from it.
    assert _sarif({"ioc": "1.1.1.1", "tags": ["elf"]})["runs"][0]["results"][0]["ruleId"] == "ioc"


def test_sarif_from_a_bare_list_of_records() -> None:
    # A list is already the records. Wrapped in one finding, its message was a
    # Python repr of the whole list and each record lost its own rule and
    # location, which is exactly what SARIF consumers read.
    records = [
        {"ioc": "1.1.1.1", "malware": "qakbot"},
        {"url": "http://x/", "signature": "Emotet"},
    ]
    results = _sarif(records)["runs"][0]["results"]
    assert len(results) == len(records)
    assert results[0]["ruleId"] == "qakbot"
    assert results[0]["message"]["text"] == "1.1.1.1"
    assert results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://x/"


def test_sarif_from_an_empty_list_has_no_results() -> None:
    assert _sarif([])["runs"][0]["results"] == []


def test_sarif_unwraps_every_envelope_in_a_list() -> None:
    # A bulk lookup answers with one envelope per input; the records are a
    # level down inside each of them.
    batch = [
        {"query_status": "ok", "data": [{"sha256_hash": "a"}, {"sha256_hash": "b"}]},
        {"query_status": "ok", "data": [{"sha256_hash": "c"}]},
    ]
    results = _sarif(batch)["runs"][0]["results"]
    assert [r["message"]["text"] for r in results] == ["a", "b", "c"]


def test_render_batch_keys_by_input_except_for_sarif() -> None:
    batch = {
        "a": {"query_status": "ok", "data": [{"sha256_hash": "a", "signature": "Qakbot"}]},
        "b": {"query_status": "ok", "data": [{"sha256_hash": "b", "signature": "Emotet"}]},
    }
    keyed = json.loads(render_batch(batch, "json"))
    assert list(keyed) == ["a", "b"]
    assert "a" in render_batch(batch, "toon")
    # SARIF has nowhere to put the key and is defined per record, so a batch
    # keyed that way used to render as one opaque finding.
    results = json.loads(render_batch(batch, "sarif"))["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["Qakbot", "Emotet"]


def test_sarif_schema_url_is_the_oasis_one() -> None:
    # The old raw.githubusercontent "master/Schemata" path is gone (404), so
    # every emitted document pointed $schema at a dead URL.
    assert SARIF_SCHEMA.startswith("https://docs.oasis-open.org/sarif/")
    assert _sarif({"a": 1})["$schema"] == SARIF_SCHEMA


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        (None, None),  # abuse.ch sends null for untagged records
        ([], None),
        (["exe", "emotet", "exe"], ["exe", "emotet"]),  # must be unique
        ("botnet", ["botnet"]),
        (["ok", 7, None], ["ok"]),  # must be strings
        (7, None),
    ],
)
def test_sarif_tags_match_the_reserved_property_shape(
    tags: Any, expected: list[str] | None
) -> None:
    # SARIF reserves properties.tags for an array of unique strings; anything
    # else makes the whole document fail schema validation.
    properties = _sarif({"data": [{"ioc": "1.2.3.4", "tags": tags}]})["runs"][0]["results"][0][
        "properties"
    ]
    assert properties.get("tags") == expected
    assert properties["ioc"] == "1.2.3.4"


def test_sarif_does_not_mutate_the_caller_record() -> None:
    record = {"ioc": "1.2.3.4", "tags": None}
    _sarif({"data": [record]})
    assert record == {"ioc": "1.2.3.4", "tags": None}


def test_sarif_dict_response_single_result() -> None:
    doc = _sarif({"query_status": "ok"})
    results = doc["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "ioc"
    assert results[0]["message"]["text"] == "abuse.ch record"
    assert results[0]["properties"]["query_status"] == "ok"


def test_sarif_scalar_record() -> None:
    doc = _sarif("scalar")
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "ioc"
    assert result["message"]["text"] == "scalar"
    assert result["properties"] == {"value": "scalar"}
    assert "locations" not in result


def test_sarif_host_location() -> None:
    doc = _sarif({"data": [{"host": "evil.example"}]})
    result = doc["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "evil.example"


def test_render_rejects_an_unknown_format() -> None:
    # A mistyped name used to fall back to JSON and hand back the wrong format.
    with pytest.raises(ValueError, match="Unknown output format 'sarf'"):
        render({"a": 1}, "sarf")


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        # URLhaus keeps its records under urls/payloads, not data.
        ({"query_status": "ok", "urls": [{"url": "http://a/1"}, {"url": "http://a/2"}]}, 2),
        ({"query_status": "ok", "payloads": [{"sha256_hash": "a"}, {"sha256_hash": "b"}]}, 2),
        ({"query_status": "ok", "url_count": "2", "urls": [{"url": "http://a/1"}]}, 1),
        # A URL lookup is one record that happens to carry its own payloads.
        (
            {"query_status": "ok", "url": "http://a/1", "payloads": [{"sha256_hash": "a"}, {}]},
            1,
        ),
        # YARAify's data is one scan result whose fields are the keys.
        ({"query_status": "ok", "data": {"task_id": "t", "static_results": {}}}, 1),
        ({"query_status": "ok", "data": [{"ioc": "1"}, {"ioc": "2"}]}, 2),
        ({"query_status": "ok"}, 1),
        ({"query_status": "ok", "urls": []}, 1),
    ],
)
def test_sarif_finds_one_result_per_record(body: Any, expected: int) -> None:
    assert len(_sarif(body)["runs"][0]["results"]) == expected


@pytest.mark.parametrize(
    "url",
    [
        "http://91.199.45.108/?q={random.randint(1,1000000)}",
        "https://raw.githubusercontent.com/x/projects/[id]/t.zip",
        "http://netvector.wiki/${uuid__}/google.ct",
    ],
)
def test_sarif_location_uri_is_escaped_but_properties_keep_the_original(url: str) -> None:
    # SARIF declares this field uri-reference; live URLhaus entries carry raw
    # {} and [] from templated URLs, and a format-aware consumer rejects the
    # whole file over one of them.
    result = _sarif({"query_status": "ok", "urls": [{"url": url}]})["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not set("{}[]") & set(uri)
    assert result["properties"]["url"] == url


def test_sarif_location_uri_leaves_ordinary_urls_alone() -> None:
    plain = "http://a.test/x.exe?a=1&b=2#frag"
    result = _sarif({"query_status": "ok", "urls": [{"url": plain}]})["runs"][0]["results"][0]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == plain


def test_sarif_location_uri_escapes_invalid_percent_sequences() -> None:
    url = "http://a.test/%20/%ZZ"
    result = _sarif({"ioc": "1.1.1.1", "url": url})["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "http://a.test/%20/%25ZZ"


# --------------------------------------------------------------------------- #
# Guards that keep the output well-formed. Each of these survived a mutation of
# the condition it tests, meaning nothing else in the suite held it in place.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text",
    # a zero in each position the number pattern can hold one: the integer
    # part, the fraction, and the exponent
    ["105214", "100", "2026", "0", "0.5", "1.0", "0.50", "1e0", "1e10", "-2.05e-01"],
)
def test_toon_quotes_numeric_strings_containing_a_zero(text: str) -> None:
    # URLhaus ids arrive as numeric strings ("id": "105214"). Emitted bare they
    # decode back as numbers, silently changing the type.
    assert to_toon({"id": text}) == f'id: "{text}"'


def test_toon_does_not_tabulate_records_that_mix_nested_values() -> None:
    """A MalwareBazaar record is primitives plus nested vendor_intel.

    The tabular form can only hold primitives, so one nested value anywhere in
    the record disqualifies the whole array. Treating "some are primitive" as
    enough would put a Python repr of the nested dict in a row cell.
    """
    records = [
        {"sha256_hash": "a", "file_size": 1, "vendor_intel": {"ANY.RUN": {"verdict": "bad"}}},
        {"sha256_hash": "b", "file_size": 2, "vendor_intel": {"ANY.RUN": {"verdict": "ok"}}},
    ]
    out = to_toon({"data": records})
    assert out.startswith("data[2]:\n  - sha256_hash: a")
    assert "{" not in out and "'" not in out


def test_toon_does_not_tabulate_a_list_of_empty_records() -> None:
    """A table needs field names, and an empty record has none to give.

    Without the check that each record has keys, a list of empty ones is
    "tabular": every keyset matches, so the header goes out with an empty
    field list — which the reference decoder refuses outright ("empty field
    name in field list"), taking the whole document with it.
    """
    assert to_toon({"data": [{}, {}]}) == "data[2]:\n  -\n  -"


def test_toon_keeps_table_rows_in_the_order_the_server_sent_them() -> None:
    # The feeds are ordered — newest first — and a table carries that order in
    # its rows and nowhere else. Sorting them reads as valid TOON with the same
    # count, so the document still parses and the sequence is simply wrong.
    rendered = to_toon({"data": [{"first_seen": "z"}, {"first_seen": "b"}]})
    assert rendered.splitlines()[1:] == ["  z", "  b"]


def test_toon_quotes_a_table_field_name_that_needs_it() -> None:
    """The header names the columns, and a comma in one of them splits it.

    Rows are comma-separated and so is the header, so a field called "a,b"
    written raw declares three columns where the table has two: the row count
    still matches, the document still parses, and every value lands under the
    wrong name.
    """
    rendered = to_toon({"data": [{"a,b": 1, "c": 2}, {"a,b": 3, "c": 4}]})
    assert rendered.splitlines()[0] == 'data[2]{"a,b",c}:'


@pytest.mark.parametrize(
    ("value", "rendered"),
    [(" invoice.pdf", '" invoice.pdf"'), ("invoice.pdf ", '"invoice.pdf "')],
)
def test_toon_quotes_a_string_padded_with_a_space(value: str, rendered: str) -> None:
    """Padding is part of the value, and unquoted the decoder trims it away.

    A file name ending in a space is a trick samples actually use, and the
    reference decoder reads the unquoted form back as the name without it —
    the record renders, nothing errors, and the value is quietly not the one
    the server sent. Both ends are checked because only the leading one was:
    dropping the trailing test left the whole suite green.
    """
    assert to_toon({"file_name": value}) == f"file_name: {rendered}"


def test_toon_quotes_a_string_whose_only_oddity_is_a_control_character() -> None:
    # Nothing else in this string needs quoting, so the control-character check
    # is the only thing standing between it and a raw byte in the output.
    assert to_toon({"file_name": "abc\x01def"}) == 'file_name: "abc\\u0001def"'


@pytest.mark.parametrize(
    ("char", "escape"),
    [
        ("\x7f", "\\u007f"),  # DEL, a control byte past the C0 range
        ("\x85", "\\u0085"),  # NEL, a C1 control that str.splitlines treats as a newline
        (" ", "\\u2028"),  # Unicode line separator
        (" ", "\\u2029"),  # Unicode paragraph separator
    ],
)
def test_toon_escapes_line_breaking_characters_past_the_c0_range(char: str, escape: str) -> None:
    # Left raw, these split the value across a physical line and the decoder
    # rejects the whole document, so the output must stay a single line.
    rendered = to_toon({"file_name": f"abc{char}def"})
    assert rendered == f'file_name: "abc{escape}def"'
    assert len(rendered.splitlines()) == 1


def test_toon_escapes_an_unpaired_surrogate_rather_than_emitting_it() -> None:
    """A surrogate cannot be encoded as UTF-8, so emitting it raised on the way out.

    A JSON body can carry one as a ``"\\udXXX"`` escape, and a sample's file
    name is written by whoever built the sample. Left raw, printing the document
    or writing it to a file raised UnicodeEncodeError, which neither the CLI nor
    the library catches — a traceback where the other two formats print a
    record, since json.dumps escapes it straight back.
    """
    rendered = to_toon({"file_name": "bad\ud800name.exe"})
    # Two backslashes: the escape is written as text, because the reference
    # decoder refuses a "\\uXXXX" escape that names a lone surrogate.
    assert rendered == 'file_name: "bad\\\\ud800name.exe"'
    assert rendered.encode("utf-8")


def test_sarif_prefers_the_url_over_the_host_it_resolves_to() -> None:
    """URLhaus records carry both, and only one of them is the finding.

    The location is what a consumer opens; the bare host is where several
    unrelated payloads live. Reversing the two fields keeps the document valid
    and points every URL finding at an IP address instead.
    """
    record = {"url": "http://42.230.30.16:36416/bin.sh", "host": "42.230.30.16"}
    location = _sarif(record)["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == record["url"]


def test_sarif_identifies_a_payload_by_its_hash_before_its_url() -> None:
    # A record with both is a sample and the URL it came from; the sample is
    # what the finding is about, and the hash is what someone searches for.
    record = {"url": "http://x.test/a.bin", "sha256_hash": "a" * 64}
    assert _sarif(record)["runs"][0]["results"][0]["message"]["text"] == "a" * 64


def test_sarif_results_are_warnings() -> None:
    # The level decides how a consumer files the finding — GitHub shows a
    # warning and a note differently — and nothing else in the document says
    # it, so it is written down here.
    assert _sarif({"ioc": "1.1.1.1"})["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_escapes_an_unpaired_surrogate_in_a_location_url() -> None:
    """The location URI is the one part of the document not built by json.dumps.

    A URL in a malware feed is written by whoever ran the campaign, and a body
    carrying an unpaired surrogate as a ``"\\udXXX"`` escape reached quote() as
    a character UTF-8 cannot represent — so rendering the record raised
    UnicodeEncodeError, which neither the CLI nor the library catches, while
    the same surrogate anywhere else in the record printed fine.
    """
    doc = _sarif({"url": "http://bad\ud800host/x"})
    location = doc["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "http://bad%5Cud800host/x"


def test_sarif_unwraps_a_non_dict_element_inside_a_collection_field() -> None:
    # A stray non-dict element in data/urls/payloads used to reach _result and
    # render as its Python repr ("['nested']"); it is now unwrapped like the
    # top-level list branch, while the real record dict passes through.
    rendered = json.loads(to_sarif({"query_status": "ok", "data": [["nested"], {"ioc": "1"}]}))
    results = rendered["runs"][0]["results"]
    messages = [result["message"]["text"] for result in results]
    assert messages == ["nested", "1"]


@pytest.mark.parametrize("value", [123, ["a"], {"a": 1}, True, None])
def test_sarif_rule_id_ignores_a_classification_that_is_not_a_string(value: Any) -> None:
    # ruleId must be a string, so a field holding anything else has to be
    # passed over rather than written into the document.
    rule_id = _sarif({"ioc": "1.1.1.1", "signature": value})["runs"][0]["results"][0]["ruleId"]
    assert rule_id == "ioc"
    # A later field that *is* a string still wins over the unusable one.
    doc = _sarif({"ioc": "1.1.1.1", "signature": value, "malware": "Qakbot"})
    assert doc["runs"][0]["results"][0]["ruleId"] == "Qakbot"


def test_sarif_message_names_a_record_by_its_first_identifier() -> None:
    """A URLhaus payload carries both an md5 and a sha256.

    Both are identifiers, and both are in the list the message is built from,
    so without stopping at the first the finding would be titled with two
    hashes for the same file.
    """
    record = {
        "md5_hash": "99ad3000abb169e60844a0689dbe9f8c",
        "sha256_hash": "0c415dd718e3b3728707d579cf8214f5",
        "signature": "Gozi",
    }
    message = _sarif(record)["runs"][0]["results"][0]["message"]["text"]
    assert message == "0c415dd718e3b3728707d579cf8214f5 — Gozi"


@pytest.mark.parametrize("value", [0, 1, -5, 2**80, -(2**80), 10**100])
def test_toon_encodes_integers_at_any_width(value: int) -> None:
    assert to_toon(value) == str(value)


@pytest.mark.parametrize("key", ["g\n", "sha256_hash\n", "a_b.c\n", "k\r", "k\t"])
def test_toon_quotes_a_key_that_ends_in_whitespace(key: str) -> None:
    r"""``$`` in Python also matches just before a trailing newline.

    So a key ending in exactly one ``\n`` passed the bare-key pattern and was
    written unquoted, splitting the document across two lines — the decoder
    then rejects the whole thing rather than losing one field.
    """
    encoded = to_toon({key: 1})
    assert encoded == f"{json.dumps(key)}: 1"
    assert "\n" not in encoded.split(":")[0]


def test_sarif_unwraps_a_collection_keyed_by_id() -> None:
    """The Hunting false-positive list answers with entries keyed by entry id.

    Thousands of them, with no ``query_status`` and no list anywhere, so the
    whole thing rendered as one finding carrying every entry in its bag. Every
    other endpoint puts a status string beside its records, which is what tells
    the two shapes apart.
    """
    fplist = {
        "8568": {"platform": "URLhaus", "entry_type": "url", "entry_value": "http://a/"},
        "8567": {"platform": "ThreatFox", "entry_type": "url", "entry_value": "http://b/"},
    }
    results = _sarif(fplist)["runs"][0]["results"]
    assert [r["message"]["text"] for r in results] == ["http://a/", "http://b/"]


def test_sarif_leaves_an_envelope_whose_data_is_one_object_alone() -> None:
    # A YARAify scan result is a single record whose fields are the keys, and
    # a status string beside it keeps it from looking like a keyed collection.
    envelope = {"query_status": "ok", "data": {"metadata": {"file_name": "s.exe"}}}
    assert len(_sarif(envelope)["runs"][0]["results"]) == 1


def test_sarif_names_a_yara_rule_and_a_false_positive_entry() -> None:
    # Neither carries a hash, a URL or an IOC, so both were titled with the
    # placeholder while holding a perfectly good name of their own.
    rule = {"yarahub_uuid": "e490d509", "rule_name": "win_stealc", "author": "Bitsight"}
    entry = {"entry_type": "sha256_hash", "entry_value": "280d5c69", "platform": "MalwareBazaar"}
    assert _sarif(rule)["runs"][0]["results"][0]["message"]["text"] == "win_stealc"
    assert _sarif(entry)["runs"][0]["results"][0]["message"]["text"] == "280d5c69"


@pytest.mark.parametrize("value", [123, ["http://x/"], {"u": 1}, True, None, ""])
def test_sarif_location_ignores_a_url_that_is_not_a_string(value: Any) -> None:
    # The location is percent-escaped on the way into the document, which only
    # a string survives, and a record with no usable one carries no location.
    doc = _sarif({"ioc": "1.1.1.1", "url": value})
    assert "locations" not in doc["runs"][0]["results"][0]
    # A later field that is a string still gives the record its location.
    located = _sarif({"ioc": "1.1.1.1", "url": value, "host": "h.tld"})
    location = located["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "h.tld"
