----------------------------- MODULE Handshake -----------------------------
(***************************************************************************)
(* The TLS 1.3 server side of one connection.                              *)
(*                                                                         *)
(* Part 1 is the state machine itself: a pure function Step from a state   *)
(* and an event to a new state and a list of actions. src/tls/fsm.rs is    *)
(* the same function in Rust, and a test compares the two on every state   *)
(* and every event (the table comes from HandshakeTable.tla).              *)
(*                                                                         *)
(* Part 2 is a model of what runs around the state machine: the record     *)
(* keys, a peer that may cause any event at any time, and two threads that *)
(* share the connection. TLC checks the properties at the end against it.  *)
(*                                                                         *)
(* Bytes and cryptography are not modelled. An event already says what a   *)
(* record turned out to be, for example "a Finished that verifies". How    *)
(* records are opened and handshake messages put together from them is     *)
(* one thread's work on buffers; it is checked on the Rust code itself.    *)
(***************************************************************************)
EXTENDS Naturals, Sequences

(***************************************************************************)
(* Part 1: the state machine                                               *)
(***************************************************************************)

\* start          waiting for the first ClientHello
\* retry          HelloRetryRequest sent, waiting for the second ClientHello
\* wait_finished  our whole flight is sent, waiting for the client Finished
\* open           application data flows
\* closed         nothing more is sent or accepted
Phases == {"start", "retry", "wait_finished", "open", "closed"}

\* partial: the start of a handshake message has arrived, the rest has not.
\* owed:    the peer asked for a KeyUpdate and we have not sent ours yet.
\* early:   the client offered early data. We never accept it, so the
\*          records that carry it are skipped (RFC 8446, 4.2.10).
States == [phase : Phases, partial : BOOLEAN, owed : BOOLEAN, early : BOOLEAN]
Start  == [phase |-> "start", partial |-> FALSE, owed |-> FALSE, early |-> FALSE]

Alerts == {"close_notify", "unexpected_message", "bad_record_mac",
           "record_overflow", "handshake_failure", "illegal_parameter",
           "access_denied", "decode_error", "decrypt_error",
           "protocol_version", "internal_error", "missing_extension",
           "unrecognized_name", "no_application_protocol"}

\* What one record from the peer can turn out to be.
\*   ccs                 the dummy ChangeCipherSpec of middlebox compatibility
\*   close_notify        the peer is done sending
\*   alert               any other alert
\*   data                application data
\*   fragment            handshake bytes that do not yet complete a message
\*   hello               a ClientHello we can serve
\*   hello_retry         a ClientHello we can serve once it brings an X25519
\*                       key share
\*   hello_early         like hello, and it offers early data
\*   hello_retry_early   like hello_retry, and it offers early data
\*   finished            a Finished message that verifies
\*   finished_bad        a Finished message that does not
\*   key_update          KeyUpdate, no answer requested
\*   key_update_request  KeyUpdate, answer requested
\*   other               any other handshake message
HandshakeContents == {"fragment", "hello", "hello_retry", "hello_early",
                      "hello_retry_early", "finished", "finished_bad",
                      "key_update", "key_update_request", "other"}
Contents == {"ccs", "close_notify", "alert", "data"} \cup HandshakeContents

\* An event is a pair.
\*   <<"plain", c>>      a record that arrived unencrypted
\*   <<"protected", c>>  a record that decrypted under the current read keys
\*   <<"undecryptable", "">>  a record that does not decrypt under the
\*                       current read keys
\*   <<"invalid", a>>    a record or message we cannot use (does not parse,
\*                       ClientHello we cannot serve, too much skipped early
\*                       data); the caller names the alert
\*   <<"lost", "">>      the transport failed: nothing more can be sent
\*   <<"write", "">>     the application wants to send data
\*   <<"close", "">>     we end the connection: the application is done, a
\*                       deadline passed, or the peer's stream ended
Events == ({"plain", "protected"} \X Contents)
              \cup ({"invalid"} \X (Alerts \ {"close_notify"}))
              \cup {<<"undecryptable", "">>, <<"lost", "">>, <<"write", "">>,
                    <<"close", "">>}

\* Actions, in the order the caller must carry them out.
Send(kind)       == <<"send", kind>>        \* the record or records of this kind
Alert(desc)      == <<"alert", desc>>       \* one alert record
ReadKeys(level)  == <<"read_keys", level>>  \* switch the keys we decrypt with
WriteKeys(level) == <<"write_keys", level>> \* switch the keys we encrypt with
Deliver          == <<"deliver", "">>       \* hand the data to the application
Skip             == <<"skip", "">>          \* drop the record and count its size
                                            \* against the early data allowance

Actions == ({"send"} \X {"server_hello", "retry", "ccs", "flight",
                         "key_update", "data"})
               \cup ({"alert"} \X Alerts)
               \cup ({"read_keys", "write_keys"} \X {"handshake", "data", "next"})
               \cup {Deliver, Skip}

Stay(s)     == [state |-> s, acts |-> <<>>]
Go(s, p, as) == [state |-> [s EXCEPT !.phase = p, !.partial = FALSE], acts |-> as]
Close(as)   == [state |-> [Start EXCEPT !.phase = "closed"], acts |-> as]
Fail(desc)  == Close(<<Alert(desc)>>)

\* Everything after ServerHello: EncryptedExtensions, Certificate,
\* CertificateVerify and Finished go out under the handshake keys, and from
\* then on we write under the application keys.
Flight == <<WriteKeys("handshake"), ReadKeys("handshake"), Send("flight"),
            WriteKeys("data")>>

OnRecord(s, protected, c) ==
    \* The first record that decrypts ends the skipping of early data.
    LET t == IF protected THEN [s EXCEPT !.early = FALSE] ELSE s IN
    IF s.partial /\ c \notin HandshakeContents THEN
        \* Nothing may come between the pieces of a handshake message.
        Fail("unexpected_message")
    ELSE IF c = "ccs" THEN
        \* Dropped, but only unencrypted and only between the first
        \* ClientHello and the client Finished.
        IF ~protected /\ s.phase \in {"retry", "wait_finished"}
        THEN Stay(s) ELSE Fail("unexpected_message")
    ELSE IF s.early /\ s.phase = "retry" /\ ~protected /\ c = "data" THEN
        \* Early data sent before our HelloRetryRequest arrived. Without
        \* read keys it shows as a record of the application data type.
        [state |-> s, acts |-> <<Skip>>]
    ELSE IF protected # (s.phase \in {"wait_finished", "open"}) THEN
        \* Once we have read keys every record must be protected, and
        \* before that none can be.
        Fail("unexpected_message")
    ELSE IF c = "fragment" THEN
        [state |-> [t EXCEPT !.partial = TRUE], acts |-> <<>>]
    ELSE IF c = "close_notify" THEN Close(<<Alert("close_notify")>>)
    ELSE IF c = "alert" THEN Close(<<>>)
    ELSE IF s.phase = "start" /\ c \in {"hello", "hello_early"} THEN
        Go([s EXCEPT !.early = (c = "hello_early")], "wait_finished",
           <<Send("server_hello"), Send("ccs")>> \o Flight)
    ELSE IF s.phase = "start" /\ c \in {"hello_retry", "hello_retry_early"} THEN
        Go([s EXCEPT !.early = (c = "hello_retry_early")], "retry",
           <<Send("retry"), Send("ccs")>>)
    ELSE IF s.phase = "retry" /\ c = "hello" THEN
        Go([s EXCEPT !.early = FALSE], "wait_finished",
           <<Send("server_hello")>> \o Flight)
    ELSE IF s.phase = "retry" /\ c \in {"hello_retry", "hello_early", "hello_retry_early"} THEN
        \* A second ClientHello must bring the key share and must not offer
        \* early data again.
        Fail("illegal_parameter")
    ELSE IF s.phase = "wait_finished" /\ c = "finished" THEN
        Go(t, "open", <<ReadKeys("data")>>)
    ELSE IF s.phase = "wait_finished" /\ c = "finished_bad" THEN
        Fail("decrypt_error")
    ELSE IF s.phase = "open" /\ c = "data" THEN
        Go(t, "open", <<Deliver>>)
    ELSE IF s.phase = "open" /\ c = "key_update" THEN
        Go(t, "open", <<ReadKeys("next")>>)
    ELSE IF s.phase = "open" /\ c = "key_update_request" THEN
        \* Our own KeyUpdate goes out with the next write, not now, so that
        \* reading never has to wait for writing.
        Go([t EXCEPT !.owed = TRUE], "open", <<ReadKeys("next")>>)
    ELSE Fail("unexpected_message")

Step(s, e) ==
    IF s.phase = "closed" THEN Stay(s)
    ELSE IF e[1] = "lost" THEN Close(<<>>)
    ELSE IF e[1] = "close" THEN Close(<<Alert("close_notify")>>)
    ELSE IF e[1] = "invalid" THEN Fail(e[2])
    ELSE IF e[1] = "undecryptable" THEN
        \* Early data we did not accept is encrypted under keys we do not
        \* have. It is skipped until the first record that decrypts.
        IF s.early /\ s.phase = "wait_finished"
        THEN [state |-> s, acts |-> <<Skip>>] ELSE Fail("bad_record_mac")
    ELSE IF e[1] = "write" THEN
        IF s.phase # "open" THEN Stay(s)
        ELSE IF s.owed THEN
            [state |-> [s EXCEPT !.owed = FALSE],
             acts |-> <<Send("key_update"), WriteKeys("next"), Send("data")>>]
        ELSE [state |-> s, acts |-> <<Send("data")>>]
    ELSE OnRecord(s, e[1] = "protected", e[2])

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

\* An alert is the last thing we do, and it closes the connection.
AlertCloses ==
    \A s \in States, e \in Events :
        LET r == Step(s, e) IN
        \A i \in DOMAIN r.acts :
            r.acts[i][1] = "alert" =>
                i = Len(r.acts) /\ r.state.phase = "closed"

\* Application data is released only on an open connection, and only when
\* the application asks.
DataOnlyWhenOpen ==
    \A s \in States, e \in Events :
        (\E i \in DOMAIN Step(s, e).acts : Step(s, e).acts[i] = Send("data"))
            => s.phase = "open" /\ e[1] = "write"

\* Records are skipped only as early data: while the client's offer of it
\* stands, and only records that cannot be read yet. Once a record has
\* decrypted, none is skipped any more.
SkipOnlyEarlyData ==
    \A s \in States, e \in Events :
        /\ (\E i \in DOMAIN Step(s, e).acts : Step(s, e).acts[i] = Skip) =>
            /\ s.early /\ Step(s, e).state = s
            /\ \/ s.phase = "wait_finished" /\ e = <<"undecryptable", "">>
               \/ s.phase = "retry" /\ e = <<"plain", "data">>
        /\ (e[1] = "protected" /\ s.phase # "closed") => ~Step(s, e).state.early

\* Only three things are let pass without any effect. Everything else either
\* moves the connection on or ends it.
NothingElseIgnored ==
    \A s \in States, e \in Events :
        (s.phase # "closed" /\ Step(s, e) = Stay(s)) =>
            \/ /\ e = <<"plain", "ccs">>       \* middlebox compatibility
               /\ s.phase \in {"retry", "wait_finished"}
            \/ e[2] = "fragment" /\ s.partial  \* more of a split message
            \/ e[1] = "write"                  \* refused: not open yet

\* While a handshake message is incomplete, only more handshake bytes may
\* follow.
SplitMessageNotInterleaved ==
    \A s \in States, e \in ({"plain", "protected"} \X (Contents \ HandshakeContents)) :
        (s.partial /\ s.phase # "closed") => Step(s, e) = Fail("unexpected_message")

\* Once we have read keys, an unencrypted record is never used. The only one
\* tolerated is the dummy ChangeCipherSpec before the client Finished.
PlainRefusedAfterKeys ==
    \A s \in States, c \in Contents :
        s.phase \in {"wait_finished", "open"} =>
            \/ Step(s, <<"plain", c>>) = Fail("unexpected_message")
            \/ /\ c = "ccs" /\ s.phase = "wait_finished" /\ ~s.partial
               /\ Step(s, <<"plain", c>>) = Stay(s)

(***************************************************************************)
(* Part 2: the connection around the state machine                         *)
(*                                                                         *)
(* A connection has its own thread. It does the handshake and afterwards   *)
(* reads the peer's records; in plain HTTP it also sends. A tunnel adds a  *)
(* second thread once the connection is open, which only sends.            *)
(*                                                                         *)
(* Step itself is one short critical section. Putting records on the wire  *)
(* is slow and can block, so it has a lock of its own, the write lock:     *)
(*                                                                         *)
(*   - to send for the application, a thread takes the write lock first    *)
(*     and calls Step after;                                               *)
(*   - for a record from the peer, the thread calls Step first and takes   *)
(*     the write lock only if an action needs it. Reading application data *)
(*     never does, so a blocked writer cannot hold up the reader.          *)
(*                                                                         *)
(* Sending a record takes two steps: seal it under the current keys and    *)
(* sequence number, then put it on the wire. A handshake message of ours   *)
(* may need more than one record.                                          *)
(***************************************************************************)
CONSTANTS MaxSeq, MaxGen   \* bounds that keep the model finite

VARIABLES
    fsm,       \* the state machine's state
    rd,        \* keys we decrypt with: [level, gen]
    wr,        \* keys we encrypt with and the next sequence number
    holders,   \* the threads that hold the write lock
    dead,      \* a write failed: nothing more may be put on the wire
    todo,      \* per thread: actions still to carry out
    held,      \* per thread: the keys and sequence number of a sealed record
               \* not yet on the wire, as <<>> or a one-element sequence
    seen,      \* per thread: the value of asked when it last called Step
    wire,      \* every record sent so far, in order
    verified,  \* a valid client Finished arrived under the handshake keys
    delivered, \* application data was handed to the application
    asked      \* how many times the peer asked us for a KeyUpdate

vars == <<fsm, rd, wr, holders, dead, todo, held, seen, wire, verified,
          delivered, asked>>

Threads == {"main", "second"}

\* What the application side of a thread can ask for.
LocalEvents == {<<"write", "">>, <<"close", "">>, <<"lost", "">>}

Init ==
    /\ fsm = Start
    /\ rd = [level |-> "plain", gen |-> 0]
    /\ wr = [level |-> "plain", gen |-> 0, seq |-> 0]
    /\ holders = {}
    /\ dead = FALSE
    /\ todo = [t \in Threads |-> <<>>]
    /\ held = [t \in Threads |-> <<>>]
    /\ seen = [t \in Threads |-> 0]
    /\ wire = <<>>
    /\ verified = FALSE
    /\ delivered = FALSE
    /\ asked = 0

LockIsFree == holders = {}

Idle(t) == todo[t] = <<>> /\ t \notin holders

\* The actions that put something on the wire or change what goes on it.
NeedsLock(a) == a[1] \in {"send", "alert", "write_keys"}

\* A thread lets the state machine decide.
Begin(t, e) ==
    /\ Idle(t)
    /\ IF e[1] \in {"write", "close"}
       THEN LockIsFree /\ holders' = holders \cup {t}
       ELSE UNCHANGED holders
    /\ fsm' = Step(fsm, e).state
    /\ todo' = [todo EXCEPT ![t] = Step(fsm, e).acts]
    /\ verified' = (verified \/ (e = <<"protected", "finished">> /\ rd.level = "handshake"))
    /\ asked' = IF /\ e = <<"protected", "key_update_request">>
                   /\ rd.level = "data" /\ fsm.phase # "closed"
                THEN asked + 1 ELSE asked
    /\ seen' = [seen EXCEPT ![t] = asked']
    /\ UNCHANGED <<rd, wr, dead, held, wire, delivered>>

\* A thread takes the write lock because its next action needs it.
Take(t) ==
    /\ todo[t] # <<>>
    /\ NeedsLock(Head(todo[t]))
    /\ t \notin holders
    /\ LockIsFree
    /\ holders' = holders \cup {t}
    /\ UNCHANGED <<fsm, rd, wr, dead, todo, held, seen, wire, verified, delivered, asked>>

NewKeys(k, level) ==
    IF level = "next" THEN [k EXCEPT !.gen = k.gen + 1]
    ELSE [k EXCEPT !.level = level, !.gen = 0]

Kind(a) == IF a[1] = "alert" THEN "alert" ELSE a[2]

\* The handshake messages of ours that may be too long for one record.
Splittable(a) ==
    a[1] = "send" /\ a[2] \in {"server_hello", "retry", "flight", "key_update"}

\* A thread carries out its next action.
Do(t) ==
    /\ todo[t] # <<>>
    /\ NeedsLock(Head(todo[t])) => t \in holders /\ ~dead
    /\ LET a    == Head(todo[t])
           done == [todo EXCEPT ![t] = Tail(todo[t])]
       IN
       IF a[1] = "read_keys" THEN
           /\ rd' = NewKeys(rd, a[2])
           /\ todo' = done
           /\ UNCHANGED <<wr, held, wire, delivered>>
       ELSE IF a[1] = "write_keys" THEN
           /\ wr' = [NewKeys(wr, a[2]) EXCEPT !.seq = 0]
           /\ todo' = done
           /\ UNCHANGED <<rd, held, wire, delivered>>
       ELSE IF a[1] = "deliver" THEN
           /\ delivered' = TRUE
           /\ todo' = done
           /\ UNCHANGED <<rd, wr, held, wire>>
       ELSE IF a[1] = "skip" THEN
           /\ todo' = done
           /\ UNCHANGED <<rd, wr, held, wire, delivered>>
       ELSE IF held[t] = <<>> THEN
           \* seal: fix the keys and the sequence number of the record
           /\ held' = [held EXCEPT ![t] = <<wr>>]
           /\ UNCHANGED <<rd, wr, todo, wire, delivered>>
       ELSE
           \* write the sealed record and move the sequence number on;
           \* "more" says that the message continues in a second record
           \E more \in BOOLEAN :
               /\ more => /\ Splittable(a)
                           /\ IF wire = <<>> THEN TRUE ELSE ~wire[Len(wire)].more
               /\ wire' = Append(wire, [kind  |-> Kind(a),
                                        level |-> held[t][1].level,
                                        gen   |-> held[t][1].gen,
                                        seq   |-> held[t][1].seq,
                                        more  |-> more,
                                        asked |-> seen[t]])
               /\ wr' = IF held[t][1].level = "plain" THEN wr
                        ELSE [wr EXCEPT !.seq = held[t][1].seq + 1]
               /\ held' = [held EXCEPT ![t] = <<>>]
               /\ todo' = IF more THEN todo ELSE done
               /\ UNCHANGED <<rd, delivered>>
    /\ UNCHANGED <<fsm, holders, dead, seen, verified, asked>>

\* A thread has nothing left to do and releases the write lock.
Release(t) ==
    /\ t \in holders
    /\ todo[t] = <<>>
    /\ holders' = holders \ {t}
    /\ UNCHANGED <<fsm, rd, wr, dead, todo, held, seen, wire, verified, delivered, asked>>

\* Sending fails (I/O error, deadline). The record may be half written and
\* the keys half switched, so the write side is dead from here on. The rest
\* of the actions is dropped and the connection is closed.
Fault(t) ==
    /\ t \in holders
    /\ todo[t] # <<>>
    /\ dead' = TRUE
    /\ fsm' = Step(fsm, <<"lost", "">>).state
    /\ todo' = [todo EXCEPT ![t] = <<>>]
    /\ held' = [held EXCEPT ![t] = <<>>]
    /\ UNCHANGED <<rd, wr, holders, seen, wire, verified, delivered, asked>>

\* A thread gets the write lock and finds the write side dead: what it
\* still had to send is dropped.
Drop(t) ==
    /\ t \in holders
    /\ dead
    /\ todo[t] # <<>>
    /\ todo' = [todo EXCEPT ![t] = <<>>]
    /\ UNCHANGED <<fsm, rd, wr, holders, dead, held, seen, wire, verified, delivered, asked>>

Handshaking == fsm.phase \in {"start", "retry", "wait_finished"}

\* The handshake deadline: the connection's thread gives up on a handshake.
Deadline == Handshaking /\ Begin("main", <<"close", "">>)

\* A thread gets on with what it has to do.
Work(t) == Take(t) \/ Do(t) \/ Release(t) \/ Drop(t)

Next ==
    \/ \E e \in Events : Begin("main", e)
    \/ \E e \in LocalEvents : ~Handshaking /\ Begin("second", e)
    \/ \E t \in Threads : Work(t) \/ Fault(t)

\* Threads keep going, and the deadline is not starved.
Fairness ==
    /\ \A t \in Threads : WF_vars(Work(t))
    /\ SF_vars(Deadline)

Spec == Init /\ [][Next]_vars /\ Fairness

\* Explore only this much of the unbounded behaviour.
Bound == wr.seq <= MaxSeq /\ wr.gen <= MaxGen /\ rd.gen <= MaxGen

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

Levels  == {"plain", "handshake", "data"}
Rank(k) == CASE k.level = "plain"     -> 0
             [] k.level = "handshake" -> 1
             [] k.level = "data"      -> 2 + k.gen

TypeOK ==
    /\ fsm \in States
    /\ rd \in [level : Levels, gen : Nat]
    /\ wr \in [level : Levels, gen : Nat, seq : Nat]
    /\ holders \subseteq Threads /\ dead \in BOOLEAN
    /\ verified \in BOOLEAN /\ delivered \in BOOLEAN /\ asked \in Nat

\* What the state machine believes about the keys is true. The next record
\* from the peer is judged under the keys its phase calls for, and a thread
\* that starts to send writes under the keys its phase calls for.
KeysMatchPhase ==
    /\ Idle("main") =>
        /\ fsm.phase \in {"start", "retry"} => rd.level = "plain"
        /\ fsm.phase = "wait_finished" => rd.level = "handshake"
        /\ fsm.phase = "open" => rd.level = "data"
    /\ (\A t \in Threads : Idle(t)) =>
        /\ fsm.phase \in {"start", "retry"} => wr.level = "plain"
        /\ fsm.phase \in {"wait_finished", "open"} => wr.level = "data"

\* Application data is neither sent nor delivered before the client
\* Finished has been verified.
DataOnlyAfterFinished ==
    (delivered \/ \E i \in DOMAIN wire : wire[i].kind = "data") => verified

\* Every kind of record goes out under the keys it belongs to.
RightKeys ==
    \A i \in DOMAIN wire :
        /\ wire[i].kind \in {"server_hello", "retry", "ccs"} => wire[i].level = "plain"
        /\ wire[i].kind = "flight" => wire[i].level = "handshake"
        /\ wire[i].kind \in {"data", "key_update"} => wire[i].level = "data"

\* How many complete messages or records of this kind went out.
Count(kind) == Len(SelectSeq(wire, LAMBDA r : r.kind = kind /\ ~r.more))

\* One HelloRetryRequest at most, and likewise one of each other handshake
\* record and one alert.
AtMostOnce ==
    \A kind \in {"retry", "server_hello", "ccs", "flight", "alert"} :
        Count(kind) <= 1

\* Our records leave in handshake order. The dummy ChangeCipherSpec is left
\* out of the comparison: it follows whichever of HelloRetryRequest and
\* ServerHello comes first.
Stage(kind) == CASE kind = "retry"        -> 1
                 [] kind = "server_hello" -> 2
                 [] kind = "flight"       -> 3
                 [] OTHER                 -> 4
InOrder ==
    \A i, j \in DOMAIN wire :
        (i < j /\ wire[i].kind # "ccs" /\ wire[j].kind # "ccs") =>
            Stage(wire[i].kind) <= Stage(wire[j].kind)

\* Nothing is sent after an alert.
AlertIsLast ==
    \A i \in DOMAIN wire : wire[i].kind = "alert" => i = Len(wire)

Sealed   == SelectSeq(wire, LAMBDA r : r.level # "plain")
Nonce(r) == <<r.level, r.gen, r.seq>>

\* No two records are sealed under the same keys and sequence number.
NoNonceReuse ==
    \A i, j \in DOMAIN Sealed : i # j => Nonce(Sealed[i]) # Nonce(Sealed[j])

\* The peer can decrypt our records in the order it receives them: each
\* sealed record carries exactly the keys and sequence number the peer
\* expects next.
Following(r) ==
    IF r.more THEN <<r.level, r.gen, r.seq + 1>>
    ELSE IF r.kind = "flight" THEN <<"data", 0, 0>>
    ELSE IF r.kind = "key_update" THEN <<"data", r.gen + 1, 0>>
    ELSE <<r.level, r.gen, r.seq + 1>>
PeerCanDecrypt ==
    \A i \in DOMAIN Sealed :
        Nonce(Sealed[i]) = IF i = 1 THEN <<"handshake", 0, 0>>
                           ELSE Following(Sealed[i - 1])

\* The records of one handshake message of ours follow each other directly,
\* under the same keys: nothing comes between them.
MessagesNotInterleaved ==
    \A i \in 1..(Len(wire) - 1) :
        wire[i].more =>
            /\ wire[i + 1].kind = wire[i].kind
            /\ wire[i + 1].level = wire[i].level /\ wire[i + 1].gen = wire[i].gen

\* Keys only move forward: plain, handshake, data, next data generation.
KeysMoveForward ==
    [][Rank(rd') >= Rank(rd) /\ Rank(wr') >= Rank(wr)]_vars

\* A requested KeyUpdate is answered before our next application data.
\* Each record carries how many requests had arrived when the state machine
\* released it. A data record released after some request must follow a
\* KeyUpdate of ours released after that same request.
KeyUpdateAnswered ==
    \A j \in DOMAIN wire :
        (wire[j].kind = "data" /\ wire[j].asked > 0) =>
            \E i \in 1..(j - 1) :
                wire[i].kind = "key_update" /\ wire[i].asked = wire[j].asked

\* Every handshake ends: the connection opens or closes.
HandshakeEnds == <>(fsm.phase \in {"open", "closed"})

\* Not a property. tools/spec.sh confirms the model gets this far: a retry,
\* a full handshake, data both ways, a KeyUpdate answered, a clean close.
FullRun ==
    /\ delivered /\ asked = 2
    /\ \A kind \in {"retry", "server_hello", "ccs", "flight", "alert"} : Count(kind) = 1
    /\ Count("key_update") = 1 /\ Count("data") >= 2
    /\ wire[Len(wire)].kind = "alert" /\ wire[Len(wire)].gen = 1

=============================================================================
