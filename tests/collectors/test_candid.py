"""Candid service text -> method list with argument/result types and mode."""

import pytest

from icp_threat_intel.collectors.candid import (
    CandidMethod,
    CandidParseError,
    parse_service,
    split_top,
    strip_comments,
)


def test_basic_service_with_annotations() -> None:
    methods = parse_service(
        """
        service : {
          get_link : () -> (text) query;
          update_link : (text) -> ();
          peek : (nat) -> (opt text) composite_query;
          ping : () -> () oneway;
        }
        """
    )
    assert methods == [
        CandidMethod("get_link", (), ("text",), "query"),
        CandidMethod("update_link", ("text",), (), "update"),
        CandidMethod("peek", ("nat",), ("opt text",), "composite_query"),
        CandidMethod("ping", (), (), "oneway"),
    ]


def test_types_comments_quoted_names_and_nested_records() -> None:
    text = """
    // header comment with service : { fake : () -> () } inside
    /* block /* nested */ comment */
    type Rec = record { a : nat; b : vec record { text; blob } };
    type Getter = func () -> (Rec) query;
    service svc : (Init : record { owner : principal }) -> {
      "quoted name" : (record { x : nat; y : text }, Rec) -> (variant { ok; err : text });
      get : Getter;
      put : (text,) -> ();  // trailing comment ; with semicolon
    }
    """
    methods = parse_service(text)
    assert [m.name for m in methods] == ["quoted name", "get", "put"]
    assert methods[0].args == ("record { x : nat; y : text }", "Rec")
    assert methods[0].rets == ("variant { ok; err : text }",)
    assert methods[0].mode == "update"
    assert methods[1] == CandidMethod("get", (), ("Rec",), "query")
    assert methods[2].args == ("text",)


def test_service_given_by_type_reference() -> None:
    text = """
    type Api = service { get_latest_link : () -> (text) query };
    service : Api
    """
    assert parse_service(text) == [CandidMethod("get_latest_link", (), ("text",), "query")]


def test_service_type_reference_after_init_args() -> None:
    text = "type S = service { f : () -> () }; service : (nat) -> S;"
    assert parse_service(text) == [CandidMethod("f", (), (), "update")]


def test_to_dict() -> None:
    assert CandidMethod("f", ("nat",), (), "query").to_dict() == {
        "name": "f",
        "args": ["nat"],
        "rets": [],
        "mode": "query",
    }


def test_strings_are_not_comments() -> None:
    assert strip_comments('"a//b" // gone') == '"a//b" '


def test_split_top_respects_nesting() -> None:
    assert split_top("a; record { b; c }; (d; e)", ";") == ["a", "record { b; c }", "(d; e)"]


@pytest.mark.parametrize(
    "text",
    [
        "type A = nat;",  # no service
        "service : { f : () -> () }; service : { g : () -> () }",  # two services
        "service : { f : () -> () ",  # unbalanced
        "service : { f : (nat) }",  # no arrow
        "service : { f : () -> () frobnicate }",  # unknown annotation
        "service : { f : () -> () query oneway }",  # two annotations
        "service : { f : Missing }",  # unresolved reference
        "service : { f () -> () }",  # missing colon
        "service : { 9f : () -> () }",  # bad identifier
        "service : { f : () -> text }",  # results not parenthesised
        "service : Loop; type Loop = Loop;",  # reference cycle
        "/* never closed",
        "service : { f : (nat) -> () ) }",
    ],
)
def test_malformed_text_raises(text: str) -> None:
    with pytest.raises(CandidParseError):
        parse_service(text)
