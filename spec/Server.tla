------------------------------- MODULE Server -------------------------------
(***************************************************************************)
(* The threads of the server: the accept loops, the cap on connections,    *)
(* and the two threads of a tunnel.                                        *)
(*                                                                         *)
(* Each listener has an accept loop. It takes a slot, waits for a          *)
(* connection and hands both to a new thread. That thread serves the       *)
(* connection and gives the slot back when it ends, however it ends.       *)
(*                                                                         *)
(* A connection that becomes a tunnel (WebSocket) needs two threads, one   *)
(* per direction, called pumps here. The "up" pump is the connection's own *)
(* thread and copies client to upstream. The "down" pump is a second       *)
(* thread and copies upstream to client.                                   *)
(*                                                                         *)
(* Writing to the client goes through TLS, which has one write lock. The   *)
(* "down" pump takes it for every piece of data. The "up" pump does not    *)
(* need it to copy data, so a client that is slow to read cannot stop us   *)
(* reading from it. Either pump takes the lock once more at its end, to    *)
(* say goodbye to the client with a TLS alert.                             *)
(*                                                                         *)
(* A pump stops when its read ends (end of stream, error, idle timeout),   *)
(* when a write fails, or when it panics. In every case it then shuts down *)
(* both sockets, which is what makes the other pump stop.                  *)
(*                                                                         *)
(* Unlike the other two specs this one has no state machine in the code    *)
(* to compare with; it records the design that src/main.rs and             *)
(* src/http/proxy.rs follow.                                               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Cap,        \* most connections served at once
    Listeners,  \* the accept loops
    Conns       \* names for connections, reused once one has ended

ASSUME Cap \in Nat /\ Cardinality(Conns) >= Cap

VARIABLES
    used,     \* slots taken
    accept,   \* per listener: "wait" for a slot, or "ready" with a slot,
              \* blocked in accept()
    conn,     \* per connection: "free", "serve" (TLS handshake and HTTP),
              \* or "tunnel"
    pump,     \* per connection and direction, where the pump is:
              \*   off        no tunnel
              \*   read       blocked reading its source
              \*   lock       waiting for the write lock, to write data
              \*   write      holding the write lock, blocked writing data
              \*   bye_lock   waiting for the write lock, to write its alert
              \*   bye_write  holding the write lock, blocked writing its alert
              \*   stop       about to shut the sockets down
              \*   done       finished
    lock,     \* per connection: who holds the write lock, or "free"
    shut      \* per connection: the sockets have been shut down

vars == <<used, accept, conn, pump, lock, shut>>

Sides == {"up", "down"}

Init ==
    /\ used = 0
    /\ accept = [l \in Listeners |-> "wait"]
    /\ conn = [c \in Conns |-> "free"]
    /\ pump = [c \in Conns |-> [p \in Sides |-> "off"]]
    /\ lock = [c \in Conns |-> "free"]
    /\ shut = [c \in Conns |-> FALSE]

(***************************************************************************)
(* Accepting and serving                                                   *)
(***************************************************************************)

\* An accept loop takes a slot before it accepts, so that when the server
\* is full new connections wait in the kernel's queue.
Reserve(l) ==
    /\ accept[l] = "wait"
    /\ used < Cap
    /\ used' = used + 1
    /\ accept' = [accept EXCEPT ![l] = "ready"]
    /\ UNCHANGED <<conn, pump, lock, shut>>

\* A connection arrives; the slot goes to the thread that serves it.
Accept(l, c) ==
    /\ accept[l] = "ready"
    /\ conn[c] = "free"
    /\ accept' = [accept EXCEPT ![l] = "wait"]
    /\ conn' = [conn EXCEPT ![c] = "serve"]
    /\ UNCHANGED <<used, pump, lock, shut>>

\* accept() fails, or the thread cannot be started: the slot is given back.
AcceptFails(l) ==
    /\ accept[l] = "ready"
    /\ accept' = [accept EXCEPT ![l] = "wait"]
    /\ used' = used - 1
    /\ UNCHANGED <<conn, pump, lock, shut>>

\* A connection that is not a tunnel ends: normally, on an error, or by a
\* panic. The slot is given back in every case.
Finish(c) ==
    /\ conn[c] = "serve"
    /\ conn' = [conn EXCEPT ![c] = "free"]
    /\ used' = used - 1
    /\ UNCHANGED <<accept, pump, lock, shut>>

(***************************************************************************)
(* Tunnels                                                                 *)
(***************************************************************************)

\* The upstream answered 101: the second thread starts and both pump.
StartTunnel(c) ==
    /\ conn[c] = "serve"
    /\ conn' = [conn EXCEPT ![c] = "tunnel"]
    /\ pump' = [pump EXCEPT ![c] = [p \in Sides |-> "read"]]
    /\ UNCHANGED <<used, accept, lock, shut>>

At(c, p, where) == pump[c][p] = where
Move(c, p, where) == pump' = [pump EXCEPT ![c][p] = where]
Waiting(c, p) == pump[c][p] \in {"lock", "bye_lock"}
Writing(c, p) == pump[c][p] \in {"write", "bye_write"}

\* Data arrives for the client and "down" has to write it through TLS.
\* Data from the client goes to the upstream without the write lock, so
\* for "up" there is nothing to model.
Data(c, p) ==
    /\ p = "down"
    /\ At(c, p, "read")
    /\ ~shut[c]
    /\ Move(c, p, "lock")
    /\ UNCHANGED <<used, accept, conn, lock, shut>>

\* A read ends: end of stream, error, idle timeout, sockets shut down, or
\* the pump panics. The pump may have an alert to send before it stops.
ReadEnds(c, p) ==
    /\ At(c, p, "read")
    /\ Move(c, p, "bye_lock") \/ Move(c, p, "stop")
    /\ UNCHANGED <<used, accept, conn, lock, shut>>

TakeLock(c, p) ==
    /\ Waiting(c, p)
    /\ lock[c] = "free"
    /\ lock' = [lock EXCEPT ![c] = p]
    /\ Move(c, p, IF At(c, p, "lock") THEN "write" ELSE "bye_write")
    /\ UNCHANGED <<used, accept, conn, shut>>

\* The client took the bytes.
Written(c, p) ==
    /\ Writing(c, p)
    /\ ~shut[c]
    /\ lock' = [lock EXCEPT ![c] = "free"]
    /\ Move(c, p, IF At(c, p, "write") THEN "read" ELSE "stop")
    /\ UNCHANGED <<used, accept, conn, shut>>

\* A write fails: error, write timeout, sockets shut down, or the pump
\* panics. The lock is released in every case.
WriteFails(c, p) ==
    /\ Writing(c, p)
    /\ lock' = [lock EXCEPT ![c] = "free"]
    /\ Move(c, p, "stop")
    /\ UNCHANGED <<used, accept, conn, shut>>

\* A stopping pump shuts down both sockets, also when it is unwinding from
\* a panic.
Stop(c, p) ==
    /\ At(c, p, "stop")
    /\ shut' = [shut EXCEPT ![c] = TRUE]
    /\ Move(c, p, "done")
    /\ UNCHANGED <<used, accept, conn, lock>>

\* The connection's thread waits for the second thread, then ends and
\* gives the slot back.
EndTunnel(c) ==
    /\ conn[c] = "tunnel"
    /\ \A p \in Sides : At(c, p, "done")
    /\ conn' = [conn EXCEPT ![c] = "free"]
    /\ pump' = [pump EXCEPT ![c] = [p \in Sides |-> "off"]]
    /\ shut' = [shut EXCEPT ![c] = FALSE]
    /\ used' = used - 1
    /\ UNCHANGED <<accept, lock>>

Next ==
    \/ \E l \in Listeners : Reserve(l) \/ AcceptFails(l) \/ \E c \in Conns : Accept(l, c)
    \/ \E c \in Conns : Finish(c) \/ StartTunnel(c) \/ EndTunnel(c)
    \/ \E c \in Conns, p \in Sides :
        \/ Data(c, p) \/ ReadEnds(c, p) \/ TakeLock(c, p)
        \/ Written(c, p) \/ WriteFails(c, p) \/ Stop(c, p)

\* What the liveness properties rely on.
Fairness ==
    \A c \in Conns :
        /\ WF_vars(EndTunnel(c))
        /\ \A p \in Sides :
            /\ WF_vars(Stop(c, p))
            \* a read or write on a socket that is shut down returns at once
            /\ WF_vars(shut[c] /\ (ReadEnds(c, p) \/ WriteFails(c, p)))
            \* a write has a timeout: it does not block for ever
            /\ WF_vars(Written(c, p) \/ WriteFails(c, p))
            \* a thread waiting for the lock gets it once it is free
            /\ SF_vars(TakeLock(c, p))

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

PumpStates == {"off", "read", "lock", "write", "bye_lock", "bye_write", "stop", "done"}

TypeOK ==
    /\ used \in Nat
    /\ accept \in [Listeners -> {"wait", "ready"}]
    /\ conn \in [Conns -> {"free", "serve", "tunnel"}]
    /\ pump \in [Conns -> [Sides -> PumpStates]]
    /\ lock \in [Conns -> Sides \cup {"free"}]
    /\ shut \in [Conns -> BOOLEAN]

Live == {c \in Conns : conn[c] # "free"}

\* Never more connections than the cap.
CapRespected == Cardinality(Live) <= Cap

\* Every slot taken belongs to exactly one accept loop or connection, so
\* none is lost and none is given back twice.
SlotsAccounted ==
    used = Cardinality({l \in Listeners : accept[l] = "ready"}) + Cardinality(Live)

\* No pump thread outlives its connection.
NoStrayThread ==
    \A c \in Conns : conn[c] # "tunnel" => \A p \in Sides : At(c, p, "off")

\* The write lock is held by exactly the pump that is writing, so two
\* pumps never write to the client at once.
OneWriter ==
    \A c \in Conns, p \in Sides : Writing(c, p) <=> lock[c] = p

\* Copying from the client never waits for the write lock, so a client
\* that does not read what we send cannot stop us reading what it sends.
ReadingNeverWaits ==
    \A c \in Conns : pump[c]["up"] \notin {"lock", "write"}

\* Once one pump's read has ended, the whole tunnel ends and its slot is
\* free again. This covers half-close, idle timeout and a panic in either
\* thread.
TunnelEnds ==
    \A c \in Conns :
        (\E p \in Sides : pump[c][p] \in {"bye_lock", "bye_write", "stop"})
            ~> (conn[c] = "free")

\* A pump waiting for the write lock does not wait for ever.
LockGranted ==
    \A c \in Conns, p \in Sides : Waiting(c, p) ~> ~Waiting(c, p)

\* Not a property. tools/spec.sh confirms the model gets this far: the
\* server is full of tunnels and an accept loop is waiting for a slot.
Full ==
    /\ used = Cap
    /\ Cardinality({c \in Conns : conn[c] = "tunnel"}) = Cap
    /\ \E l \in Listeners : accept[l] = "wait"

\* Not a property. One pump waits for the lock while the other holds it.
Contended ==
    \E c \in Conns : At(c, "up", "bye_lock") /\ At(c, "down", "write")

=============================================================================
