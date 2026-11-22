----------------------------- MODULE HttpTable -----------------------------
(***************************************************************************)
(* Prints the functions of Http.tla for every input, one line each. The    *)
(* output is stored in tests/vectors/http_fsm.txt and replayed against     *)
(* src/http/fsm.rs.                                                        *)
(***************************************************************************)
EXTENDS Http, TLC

Word(w)  == IF w = "" THEN "-" ELSE w
State(s) == s.phase \o " " \o (IF s.keep THEN "keep" ELSE "close")
                \o " " \o (IF s.upgrade THEN "upgrade" ELSE "plain")

RECURSIVE List(_)
List(as) ==
    IF as = <<>> THEN ""
    ELSE " " \o as[1][1] \o ":" \o Word(as[1][2]) \o List(Tail(as))

Result(r) == State(r.state) \o List(r.acts)

ASSUME PrintT("start => " \o Result(Start))

ASSUME \A s \in States, e \in Events :
    PrintT("step " \o State(s) \o " " \o e[1] \o ":" \o Word(e[2]) \o " => "
               \o Result(Step(s, e)))

ASSUME \A v \in Versions, l \in Lengths, c \in Codings :
    PrintT("request_framing " \o v \o " " \o l \o " " \o c \o " => "
               \o RequestFraming(v, l, c))

ASSUME \A v \in Versions, b \in BOOLEAN, l \in Lengths, c \in Codings :
    PrintT("response_framing " \o v \o " " \o (IF b THEN "bodiless" ELSE "body")
               \o " " \o l \o " " \o c \o " => " \o ResponseFraming(v, b, l, c))

ASSUME \A f \in Framings, v \in Versions :
    PrintT("client_framing " \o f \o " " \o v \o " => " \o ClientFraming(f, v))

\* TLC wants a behaviour to check; this one does nothing.
Nothing == UNCHANGED vars
=============================================================================
