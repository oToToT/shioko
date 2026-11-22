-------------------------------- MODULE Http --------------------------------
(***************************************************************************)
(* One client connection of the proxy and its exchanges with the upstream. *)
(*                                                                         *)
(* Part 1 decides how a message body is delimited. Part 2 is the state     *)
(* machine of a connection: a pure function Step from a state and an event *)
(* to a new state and a list of actions. src/http/fsm.rs holds the same    *)
(* functions in Rust, and a test compares them on every input (the table   *)
(* comes from HttpTable.tla).                                              *)
(*                                                                         *)
(* There is no model of the code that drives the state machine. That code *)
(* is one thread working through buffers; what must hold of it (which      *)
(* bytes go where, where a message ends) is checked on the Rust code       *)
(* itself, by the tests and proofs in src/http/.                           *)
(***************************************************************************)
EXTENDS Naturals, Sequences

(***************************************************************************)
(* Part 1: how a body is delimited                                         *)
(***************************************************************************)

Versions == {"1.0", "1.1"}

\* What the head says about Content-Length:
\*   none  no such field
\*   one   exactly one field holding one plain decimal number
\*   bad   anything else: repeated, a list, not a number, too large
Lengths == {"none", "one", "bad"}

\* What the head says about Transfer-Encoding:
\*   none     no such field
\*   chunked  exactly one field holding exactly "chunked"
\*   other    a well-formed list that ends in "chunked" and names other
\*            codings before it
\*   bad      anything else, such as a list that does not end in "chunked"
Codings == {"none", "chunked", "other", "bad"}

\* A request body is empty, has a stated length, or is chunked. A head that
\* leaves any doubt is rejected (400). One that is clear but names a coding
\* we do not implement is unsupported (501).
RequestFraming(version, length, coding) ==
    IF coding = "none" /\ length = "none" THEN "empty"
    ELSE IF coding = "none" /\ length = "one" THEN "length"
    ELSE IF coding = "chunked" /\ length = "none" /\ version = "1.1" THEN "chunked"
    ELSE IF coding = "other" /\ length = "none" /\ version = "1.1" THEN "unsupported"
    ELSE "reject"

\* A response body may also run until the upstream closes the connection.
\* bodiless: the response cannot have a body, because it answers HEAD or
\* its status is 1xx, 204 or 304.
ResponseFraming(version, bodiless, length, coding) ==
    IF RequestFraming(version, length, coding) \in {"reject", "unsupported"} THEN "reject"
    ELSE IF bodiless THEN "empty"
    ELSE IF coding = "chunked" THEN "chunked"
    ELSE IF length = "one" THEN "length"
    ELSE "close"

Framings == {"empty", "length", "chunked", "close"}

\* How we delimit the response towards the client. A body of unknown length
\* is chunked for an HTTP/1.1 client; for an HTTP/1.0 client it ends when we
\* close the connection.
ClientFraming(framing, version) ==
    IF framing \in {"empty", "length"} THEN framing
    ELSE IF version = "1.1" THEN "chunked"
    ELSE "close"

Ambiguous(length, coding) ==
    length = "bad" \/ coding = "bad" \/ (length # "none" /\ coding # "none")

\* A head that could be read in two ways is always rejected.
AmbiguousRejected ==
    \A v \in Versions, l \in Lengths, c \in Codings :
        Ambiguous(l, c) =>
            /\ RequestFraming(v, l, c) = "reject"
            /\ \A b \in BOOLEAN : ResponseFraming(v, b, l, c) = "reject"

\* Chunked encoding is never used with HTTP/1.0, in either direction.
NoChunkedInHttp10 ==
    /\ \A l \in Lengths, c \in Codings :
        /\ RequestFraming("1.0", l, c) # "chunked"
        /\ \A b \in BOOLEAN : ResponseFraming("1.0", b, l, c) # "chunked"
    /\ \A f \in Framings : ClientFraming(f, "1.0") # "chunked"

(***************************************************************************)
(* Part 2: the state machine                                               *)
(***************************************************************************)

\* idle      waiting for a request head from the client
\* connect   request accepted, connecting to the upstream
\* forward   sending the request, head and body, to the upstream
\* response  waiting for the response head from the upstream
\* relay     sending the response, head and body, to the client
\* tunnel    after a 101: bytes pass both ways untouched
\* closed    the connection is finished
Phases == {"idle", "connect", "forward", "response", "relay", "tunnel", "closed"}

\* keep:    the client connection may serve another request afterwards
\* upgrade: the request asks for WebSocket and the site allows it
States == [phase : Phases, keep : BOOLEAN, upgrade : BOOLEAN]
At(phase) == [phase |-> phase, keep |-> FALSE, upgrade |-> FALSE]

\* The statuses of the responses we write ourselves: an ACME token (200),
\* the redirect to HTTPS (301), and the errors.
OwnAnswers     == {"200", "301"}
ClientErrors   == {"400", "403", "404", "413", "414", "421", "431", "501"}
UpstreamErrors == {"502", "504"}
OwnStatuses    == OwnAnswers \cup ClientErrors \cup UpstreamErrors

\* An event is what came of the last action. It is a pair.
\*   <<"request", d>>   a request head we will forward; d is "keep" if the
\*                      client connection may be reused, else "close"
\*   <<"upgrade", d>>   the same, asking for WebSocket on a site that allows it
\*   <<"fail", status>> the exchange ends here; status is what the client
\*                      should be told if it can still be told. Also used
\*                      when we answer a request ourselves without an error
\*                      (200, 301)
\*   <<"gone", "">>     the client connection is lost
\*   <<"connected", "">>
\*   <<"sent", "">>     the whole request, head and body, is forwarded
\*   <<"interim", "">>  the upstream sent a 1xx other than 101
\*   <<"switching", "">> the upstream sent 101
\*   <<"final", d>>     the upstream sent a final response head; d is
\*                      "delimited" if the client will see where our response
\*                      ends, "until_close" if only closing can show it
\*   <<"done", "">>     the response body, or the tunnel, has finished
Events == ({"request", "upgrade"} \X {"keep", "close"})
              \cup ({"fail"} \X OwnStatuses)
              \cup ({"final"} \X {"delimited", "until_close"})
              \cup ({"gone", "connected", "sent", "interim", "switching", "done"} \X {""})

\* Actions, in the order the caller must carry them out. Only the last one
\* of a list is waited for.
ReadHead     == <<"read_head", "">>      \* read and check a request head
Connect      == <<"connect", "">>        \* open a new upstream connection
Forward      == <<"forward", "">>        \* send the request, head and body
ReadResponse == <<"read_response", "">>  \* read a response head
Interim      == <<"interim", "">>        \* pass the 1xx head to the client
Respond(d)   == <<"respond", d>>         \* send the response, head and body;
                                         \* d tells the client "keep" or "close"
Error(s)     == <<"error", s>>           \* write our own response, then close
Tunnel       == <<"tunnel", "">>         \* pass the 101 head, then run the tunnel

Actions == {ReadHead, Connect, Forward, ReadResponse, Interim, Tunnel}
               \cup ({"respond"} \X {"keep", "close"})
               \cup ({"error"} \X OwnStatuses)

\* What the caller does first on a new connection.
Start == [state |-> At("idle"), acts |-> <<ReadHead>>]

Stay(s)    == [state |-> s, acts |-> <<>>]
To(s, phase, as) == [state |-> [s EXCEPT !.phase = phase], acts |-> as]
Close(as)  == [state |-> At("closed"), acts |-> as]

Step(s, e) ==
    IF s.phase = "closed" THEN Stay(s)
    ELSE IF e[1] = "gone" THEN Close(<<>>)
    ELSE IF e[1] = "fail" THEN
        \* Our own response is possible only while none has been started.
        IF s.phase \in {"idle", "connect", "forward", "response"}
        THEN Close(<<Error(e[2])>>) ELSE Close(<<>>)
    ELSE IF s.phase = "idle" /\ e[1] \in {"request", "upgrade"} THEN
        [state |-> [phase |-> "connect", keep |-> e[2] = "keep",
                    upgrade |-> e[1] = "upgrade"],
         acts |-> <<Connect>>]
    ELSE IF s.phase = "connect" /\ e[1] = "connected" THEN
        To(s, "forward", <<Forward>>)
    ELSE IF s.phase = "forward" /\ e[1] = "sent" THEN
        To(s, "response", <<ReadResponse>>)
    ELSE IF s.phase = "response" /\ e[1] = "interim" THEN
        To(s, "response", <<Interim, ReadResponse>>)
    ELSE IF s.phase = "response" /\ e[1] = "switching" THEN
        IF s.upgrade THEN To(s, "tunnel", <<Tunnel>>)
        ELSE Close(<<Error("502")>>)
    ELSE IF s.phase = "response" /\ e[1] = "final" THEN
        IF s.keep /\ e[2] = "delimited"
        THEN To(s, "relay", <<Respond("keep")>>)
        ELSE [state |-> [s EXCEPT !.phase = "relay", !.keep = FALSE],
              acts |-> <<Respond("close")>>]
    ELSE IF s.phase = "relay" /\ e[1] = "done" /\ s.keep THEN
        [state |-> At("idle"), acts |-> <<ReadHead>>]
    ELSE Close(<<>>)

(***************************************************************************)
(* Facts about Step alone. Each is checked for every state and event.      *)
(***************************************************************************)

StepIsTotal ==
    \A s \in States, e \in Events :
        /\ Step(s, e).state \in States
        /\ \A i \in DOMAIN Step(s, e).acts : Step(s, e).acts[i] \in Actions

\* Once closed, nothing happens any more.
ClosedIsFinal ==
    \A s \in States, e \in Events :
        s.phase = "closed" => Step(s, e) = Stay(s)

\* After our own error response the connection is closed.
ErrorCloses ==
    \A s \in States, e \in Events :
        (\E i \in DOMAIN Step(s, e).acts : Step(s, e).acts[i][1] = "error")
            => Step(s, e).state.phase = "closed"

\* A tunnel is opened only on a 101 that answers an upgrade request, and
\* from a tunnel the only way on is to close.
TunnelOnlyOnUpgrade ==
    \A s \in States, e \in Events :
        /\ (\E i \in DOMAIN Step(s, e).acts : Step(s, e).acts[i] = Tunnel)
               => s.upgrade /\ s.phase = "response" /\ e[1] = "switching"
        /\ s.phase = "tunnel" => Step(s, e) = Close(<<>>)

\* The client is told it may reuse the connection only if it allowed that
\* and the response is delimited.
KeepNeedsBoth ==
    \A s \in States, e \in Events :
        (\E i \in DOMAIN Step(s, e).acts : Step(s, e).acts[i] = Respond("keep"))
            => s.keep /\ e = <<"final", "delimited">>

(***************************************************************************)
(* TLC checks the facts above as invariants, and needs a behaviour to check *)
(* them on. This one does nothing.                                         *)
(***************************************************************************)
VARIABLE nothing
vars == <<nothing>>
Init == nothing = 0
Next == UNCHANGED nothing
Spec == Init /\ [][Next]_vars

=============================================================================
