--------------------------- MODULE HandshakeTrace ---------------------------
(***************************************************************************)
(* Recorded runs of the real server, checked against part 2 of             *)
(* Handshake.tla.                                                          *)
(*                                                                         *)
(* tools/tlstrace.py records connections to shioko (tlsfuzzer, OpenSSL,     *)
(* curl), decrypts them with keys it derives itself, and writes each as a  *)
(* trace in the module Recorded: the client's records and how they ended,  *)
(* and our records with the keys and sequence number each was sealed       *)
(* under, in the order they passed.                                        *)
(*                                                                         *)
(* A trace is accepted when some behaviour of the model accounts for all   *)
(* of it: the connection's thread reads the client's records in order, each *)
(* only once it has arrived, as an event that fits what the record was; and *)
(* every record of ours is the next one the model puts on the wire, of the *)
(* right kind, under the same keys and sequence number. The threads' hidden steps (taking the    *)
(* write lock, sealing, switching keys) are the model's to choose; so are  *)
(* the application's writes and closes, but only where the trace shows     *)
(* their effect. A failed write is allowed only once the client has reset  *)
(* the connection.                                                         *)
(*                                                                         *)
(* What a record is, is fixed by the trace, as the rules in               *)
(* src/tls/conn.rs would read it. Whether a ClientHello can be served, and *)
(* with which alert it must be refused if not, tools/tlstrace.py works out *)
(* itself, from the RFCs and shioko's configuration, and the trace must    *)
(* show exactly that.                                                      *)
(***************************************************************************)
EXTENDS Handshake, Recorded, TLC

VARIABLES
    n,       \* the trace being checked
    ii,      \* the client's next record in it, not yet read
    oi,      \* our next record in it, not yet sent
    skipped  \* bytes of early data skipped so far

tvars == <<n, ii, oi, skipped>>

\* A trace is the client's records and ours, each with its place in the
\* order the relay saw them pass.
In  == Traces[n].in
Out == Traces[n].out
InLeft  == ii <= Len(In)
OutLeft == oi <= Len(Out)
NextIn  == In[ii]
NextOut == Out[oi]

\* A record of the client's can be read once it has arrived, that is, if
\* it came before our next record went out.
Arrived(k) == IF OutLeft THEN In[k].pos < NextOut.pos ELSE TRUE
\* The client reset the connection, so writes may fail.
Reset == \E k \in DOMAIN In : In[k].what = "reset" /\ Arrived(k)

\* What the state machine may be told about a record it can read, from what
\* the record held (its classification by tools/tlstrace.py). A ClientHello
\* comes with two verdicts, worked out by tools/tlstrace.py from the RFCs and
\* shioko's configuration rather than from its code: as a first ClientHello,
\* and as a second one, after our HelloRetryRequest; the phase says which
\* applies. Each is that it can be served, and how, or the alert that must
\* refuse it.
Content(p, e) ==
    LET c   == IF fsm.phase = "retry" THEN e.c2 ELSE e.c
        why == IF fsm.phase = "retry" THEN e.why2 ELSE e.why IN
    CASE c \in {"ccs", "close_notify", "alert", "data", "empty_data", "fragment",
               "other"} ->
            {<<p, c>>}
      [] c \in {"hello", "hello_retry", "hello_early", "hello_retry_early"} ->
            IF fsm.phase \in {"start", "retry"} THEN {<<p, c>>} ELSE {<<p, "other">>}
      [] c = "refused" ->
            IF fsm.phase \in {"start", "retry"} THEN {<<"invalid", why>>}
            ELSE {<<p, "other">>}
      [] c \in {"finished", "finished_bad"} ->
            IF fsm.phase = "wait_finished" THEN {<<p, c>>} ELSE {<<p, "other">>}
      [] c = "finished_garbled" ->
            IF fsm.phase = "wait_finished" THEN {<<"invalid", "decode_error">>}
            ELSE {<<p, "other">>}
      [] c \in {"key_update", "key_update_request"} ->
            IF fsm.phase = "open" THEN {<<p, c>>} ELSE {<<p, "other">>}
      [] c = "key_update_garbled_value" ->
            IF fsm.phase = "open" THEN {<<"invalid", "illegal_parameter">>}
            ELSE {<<p, "other">>}
      [] c = "key_update_garbled_length" ->
            IF fsm.phase = "open" THEN {<<"invalid", "decode_error">>}
            ELSE {<<p, "other">>}
      [] c \in {"ccs_bad", "alert_empty", "empty", "trailing", "nocontent",
                "badtype"} -> {<<"invalid", "unexpected_message">>}
      [] c \in {"alert_bad", "toolong"} -> {<<"invalid", "decode_error">>}
      [] c = "overflow" -> {<<"invalid", "record_overflow">>}

\* The events a record of the client's may be, given our read keys.
Explain(e) ==
    IF e.what \in {"end", "reset"} THEN {<<"close", "">>}
    ELSE IF e.what = "refused" THEN {<<"invalid", e.c>>}
    ELSE IF rd.level = "plain" THEN
        IF e.outer = 23 THEN {<<"plain", "data">>} ELSE Content("plain", e)
    ELSE IF e.outer = 23 THEN
        IF e.key = rd.level /\ e.gen = rd.gen THEN Content("protected", e)
        ELSE {<<"undecryptable", "">>}
    \* Only the dummy ChangeCipherSpec and alerts are read unencrypted now.
    ELSE IF e.outer = 22 THEN {<<"plain", "other">>}
    ELSE Content("plain", e)

\* How much early data is skipped before the connection is given up.
EarlyLimit == 16384

\* The connection's thread reads the client's next record.
TraceRecord ==
    /\ InLeft /\ Arrived(ii)
    /\ \E e0 \in Explain(NextIn) :
          LET skip == fsm.phase # "closed" /\ Step(fsm, e0).acts = <<Skip>>
              over == skip /\ skipped + NextIn.size > EarlyLimit
          IN /\ Begin("main", IF over THEN <<"invalid", "unexpected_message">> ELSE e0)
             /\ skipped' = IF skip /\ ~over THEN skipped + NextIn.size ELSE skipped
    /\ ii' = ii + 1
    /\ UNCHANGED <<n, oi>>

\* The application writes or closes, where the trace shows it did; the
\* transport fails, once the client has reset the connection.
Spontaneous(t, e) ==
    /\ \/ e = <<"write", "">> /\ OutLeft /\ NextOut.what = "record"
                              /\ NextOut.kind \in {"data", "key_update"}
       \/ e = <<"close", "">> /\ OutLeft
                              /\ \/ NextOut.what \in {"end", "reset"}
                                 \/ NextOut.kind = "alert" /\ NextOut.alert = "close_notify"
       \/ e = <<"lost", "">> /\ Reset
    /\ t = "second" => ~Handshaking
    /\ Begin(t, e)
    /\ UNCHANGED tvars

\* A record we put on the wire is the next one of the trace.
Fits(e, a, r) ==
    /\ e.what = "record"
    /\ e.key = r.level
    /\ r.level # "plain" => e.gen = r.gen /\ e.seq = r.seq
    /\ e.more = r.more
    /\ IF a[1] = "alert" THEN e.kind = "alert" /\ e.alert = a[2]
       ELSE e.kind = a[2]

TraceWork(t) ==
    \/ (Take(t) \/ Release(t) \/ Drop(t) \/ (Reset /\ Fault(t))) /\ UNCHANGED tvars
    \/ /\ Do(t)
       /\ IF Len(wire') = Len(wire) THEN UNCHANGED tvars
          ELSE /\ OutLeft
               /\ Fits(NextOut, Head(todo[t]), wire'[Len(wire')])
               /\ oi' = oi + 1
               /\ UNCHANGED <<n, ii, skipped>>

\* We close the transport only once the connection is closed and nothing
\* is left to do.
TraceEnd ==
    /\ OutLeft /\ NextOut.what \in {"end", "reset"}
    /\ fsm.phase = "closed" /\ \A t \in Threads : Idle(t)
    /\ oi' = oi + 1
    /\ UNCHANGED <<vars, n, ii, skipped>>

\* Everything we sent is accounted for, and nothing more was to come. What
\* the client sent after we closed was never read.
Accepted ==
    /\ ~OutLeft /\ \A t \in Threads : Idle(t)
    /\ InLeft => fsm.phase = "closed"

TraceInit ==
    /\ Init
    /\ n \in DOMAIN Traces /\ ii = 1 /\ oi = 1 /\ skipped = 0

\* tools/tlstrace.py reads what TLC prints: how far each trace got, and
\* which were accepted.
TraceNext ==
    /\ \/ TraceRecord
       \/ \E t \in Threads, e \in LocalEvents : Spontaneous(t, e)
       \/ \E t \in Threads : TraceWork(t)
       \/ TraceEnd
       \/ Accepted /\ PrintT(<<"accepted", n>>) /\ UNCHANGED <<vars, tvars>>
    /\ (oi' > oi \/ ii' > ii) => PrintT(<<"reached", n, oi', ii'>>)

=============================================================================
