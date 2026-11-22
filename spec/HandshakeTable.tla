--------------------------- MODULE HandshakeTable ---------------------------
(***************************************************************************)
(* Prints Step for every state and event, one line each. The output is     *)
(* stored in tests/vectors/handshake_fsm.txt and replayed against          *)
(* src/tls/fsm.rs.                                                         *)
(***************************************************************************)
EXTENDS Handshake, TLC

Word(w)  == IF w = "" THEN "-" ELSE w
State(s) == s.phase \o " " \o (IF s.partial THEN "partial" ELSE "whole")
                \o " " \o (IF s.owed THEN "owed" ELSE "even")
                \o " " \o (IF s.early THEN "skipping" ELSE "strict")

RECURSIVE List(_)
List(as) ==
    IF as = <<>> THEN ""
    ELSE " " \o as[1][1] \o ":" \o Word(as[1][2]) \o List(Tail(as))

ASSUME PrintT("start => " \o State(Start))

ASSUME \A s \in States, e \in Events :
    PrintT("step " \o State(s) \o " " \o e[1] \o ":" \o Word(e[2]) \o " => "
               \o State(Step(s, e).state) \o List(Step(s, e).acts))

\* TLC wants a behaviour to check; this one does nothing.
Nothing == UNCHANGED vars
=============================================================================
