------------------------------- MODULE Server -------------------------------
(***************************************************************************)
(* The threads of the server: the accept loops, the cap on connections,    *)
(* and the two threads of a tunnel.                                        *)
(*                                                                         *)
(* Each listener has an accept loop. It takes a slot, waits for a          *)
(* connection and hands both to a new thread. That thread serves the       *)
(* connection and gives the slot back when it ends, however it ends.       *)
(*                                                                         *)
(* Connections come out of two pools of Cap slots each: one for peers      *)
(* inside some site's allowlist, one for everyone else, so that no flood   *)
(* from outside the allowlists can take the slots of the sites behind      *)
(* them. In the public pool one address may hold at most PerAddress        *)
(* connections. A connection whose pool, or address, has no room is       *)
(* turned away at once: closed, and its slot given back.                   *)
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
(* SIGTERM stops the server: from then on nobody is let in, the           *)
(* connections that wait for a request and the tunnels are cut, the       *)
(* requests being served end, and the process exits, once no connection   *)
(* is left or at a deadline.                                               *)
(*                                                                         *)
(* A pump stops when its read ends (end of stream, error, idle timeout),   *)
(* when a write fails, or when it panics. In every case it then shuts down *)
(* both sockets (unless the other pump has already), which is what makes   *)
(* the other pump stop. The pump reading the client writes too, through    *)
(* the same lock: its alert when its read ends, and in the middle of a     *)
(* tunnel the KeyUpdate the client asks for.                               *)
(*                                                                         *)
(* Unlike the other two specs this one has no state machine in the code    *)
(* to compare with; it records the design that src/main.rs and             *)
(* src/http/proxy.rs follow.                                               *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
    Cap,        \* most connections served at once from each pool
    PerAddress, \* most connections at once from one address, public pool
    Listeners,  \* the accept loops
    Secure,     \* the listeners that speak TLS
    PublicTls,  \* some TLS site serves peers outside every allowlist
    Conns,      \* names for connections, reused once one has ended
    Addresses   \* where connections come from

ASSUME /\ Cap \in Nat /\ PerAddress \in Nat /\ Secure \subseteq Listeners
       /\ PublicTls \in BOOLEAN /\ Cardinality(Conns) >= Cap

\* allowed  the peer is inside some site's allowlist
\* public   everyone else
Pools == {"allowed", "public"}

VARIABLES
    used,     \* slots taken
    accept,   \* per listener: "wait" for a slot, or "ready" with a slot,
              \* blocked in accept()
    conn,     \* per connection: "free", "serve" (TLS handshake and HTTP),
              \* or "tunnel"
    pool,     \* per connection: the pool its slot is from, or "none"
    from,     \* per connection in the public pool: the address it came
              \* from, which the pool counts; "none" otherwise
    pump,     \* per connection and direction, where the pump is:
              \*   off        no tunnel
              \*   read       blocked reading its source
              \*   lock       waiting for the write lock, to write data
              \*   write      holding the write lock, blocked writing data
              \*   answer_lock   waiting for the write lock, to answer the
              \*                 client's KeyUpdate
              \*   answer_write  holding the write lock, blocked writing it
              \*   bye_lock   waiting for the write lock, to write its alert
              \*   bye_write  holding the write lock, blocked writing its alert
              \*   stop       about to shut the sockets down
              \*   done       finished
    lock,     \* per connection: who holds the write lock, or "free"
    shut,     \* per connection: the sockets have been shut down
    stopping, \* SIGTERM has come
    deadline, \* the time a stop waits for the requests being served is up
    ended,    \* the process has exited
    late      \* a connection was let in after the stop (never, if right)

vars == <<used, accept, conn, pool, from, pump, lock, shut, stopping, deadline, ended, late>>
\* What the stop leaves alone.
stop == <<stopping, deadline, ended, late>>

Sides == {"up", "down"}

Init ==
    /\ used = 0
    /\ accept = [l \in Listeners |-> "wait"]
    /\ conn = [c \in Conns |-> "free"]
    /\ pool = [c \in Conns |-> "none"]
    /\ from = [c \in Conns |-> "none"]
    /\ pump = [c \in Conns |-> [p \in Sides |-> "off"]]
    /\ lock = [c \in Conns |-> "free"]
    /\ shut = [c \in Conns |-> FALSE]
    /\ stopping = FALSE /\ deadline = FALSE /\ ended = FALSE /\ late = FALSE

(***************************************************************************)
(* Accepting and serving                                                   *)
(***************************************************************************)

\* An accept loop takes a slot before it accepts, so that when the server
\* is full new connections wait in the kernel's queue. Which pool the slot
\* is from is known only once the connection has come.
Reserve(l) ==
    /\ accept[l] = "wait"
    /\ used < 2 * Cap
    /\ used' = used + 1
    /\ accept' = [accept EXCEPT ![l] = "ready"]
    /\ UNCHANGED <<conn, pool, from, pump, lock, shut, stop>>

Live == {c \in Conns : conn[c] # "free"}
InPool(k) == {c \in Live : pool[c] = k}
FromAddress(a) == {c \in InPool("public") : from[c] = a}

\* Pool k has a slot free for a connection from a.
Room(k, a) ==
    /\ Cardinality(InPool(k)) < Cap
    /\ k = "public" => Cardinality(FromAddress(a)) < PerAddress

\* A connection arrives from a, which puts it in pool k; the slot goes to
\* the thread that serves it.
Accept(l, c, k, a) ==
    /\ accept[l] = "ready"
    /\ conn[c] = "free"
    /\ ~stopping
    /\ Room(k, a)
    /\ accept' = [accept EXCEPT ![l] = "wait"]
    /\ conn' = [conn EXCEPT ![c] = "serve"]
    /\ pool' = [pool EXCEPT ![c] = k]
    /\ from' = [from EXCEPT ![c] = IF k = "public" THEN a ELSE "none"]
    /\ late' = (late \/ stopping)
    /\ UNCHANGED <<used, pump, lock, shut, stopping, deadline, ended>>

\* A connection arrives that is turned away: its pool or address has no
\* room, it comes over TLS from outside every allowlist when every TLS
\* site has one, or the server is stopping. It is closed at once and the
\* slot is given back.
TurnAway(l, k, a) ==
    /\ accept[l] = "ready"
    /\ ~Room(k, a) \/ (k = "public" /\ l \in Secure /\ ~PublicTls) \/ stopping
    /\ accept' = [accept EXCEPT ![l] = "wait"]
    /\ used' = used - 1
    /\ UNCHANGED <<conn, pool, from, pump, lock, shut, stop>>

\* accept() fails, or the thread cannot be started: the slot is given back.
AcceptFails(l) ==
    /\ accept[l] = "ready"
    /\ accept' = [accept EXCEPT ![l] = "wait"]
    /\ used' = used - 1
    /\ UNCHANGED <<conn, pool, from, pump, lock, shut, stop>>

\* The connection's slot goes back to its pool.
Leave(c) ==
    /\ conn' = [conn EXCEPT ![c] = "free"]
    /\ pool' = [pool EXCEPT ![c] = "none"]
    /\ from' = [from EXCEPT ![c] = "none"]
    /\ used' = used - 1

\* A connection that is not a tunnel ends: normally, on an error, or by a
\* panic. The slot is given back in every case.
Finish(c) ==
    /\ conn[c] = "serve"
    /\ Leave(c)
    /\ UNCHANGED <<accept, pump, lock, shut, stop>>

(***************************************************************************)
(* Tunnels                                                                 *)
(***************************************************************************)

\* The upstream answered 101: the second thread starts and both pump.
StartTunnel(c) ==
    /\ conn[c] = "serve"
    /\ conn' = [conn EXCEPT ![c] = "tunnel"]
    /\ pump' = [pump EXCEPT ![c] = [p \in Sides |-> "read"]]
    /\ UNCHANGED <<used, accept, pool, from, lock, shut, stop>>

At(c, p, where) == pump[c][p] = where
Move(c, p, where) == pump' = [pump EXCEPT ![c][p] = where]
Waiting(c, p) == pump[c][p] \in {"lock", "answer_lock", "bye_lock"}
Writing(c, p) == pump[c][p] \in {"write", "answer_write", "bye_write"}

\* Data arrives for the client and "down" has to write it through TLS.
\* Data from the client goes to the upstream without the write lock, so
\* for "up" there is nothing to model.
Data(c, p) ==
    /\ p = "down"
    /\ At(c, p, "read")
    /\ ~shut[c]
    /\ Move(c, p, "lock")
    /\ UNCHANGED <<used, accept, conn, pool, from, lock, shut, stop>>

\* The client asks for a KeyUpdate: "up" has to send ours through TLS, and
\* then reads on. This waits for the write lock, as data from the client
\* never does; but only because the client asked us to send.
Answer(c, p) ==
    /\ p = "up"
    /\ At(c, p, "read")
    /\ ~shut[c]
    /\ Move(c, p, "answer_lock")
    /\ UNCHANGED <<used, accept, conn, pool, from, lock, shut, stop>>

\* A read ends: end of stream, error, idle timeout, sockets shut down, or
\* the pump panics. The pump may have an alert to send before it stops.
ReadEnds(c, p) ==
    /\ At(c, p, "read")
    /\ Move(c, p, "bye_lock") \/ Move(c, p, "stop")
    /\ UNCHANGED <<used, accept, conn, pool, from, lock, shut, stop>>

TakeLock(c, p) ==
    /\ Waiting(c, p)
    /\ lock[c] = "free"
    /\ lock' = [lock EXCEPT ![c] = p]
    /\ Move(c, p, CASE At(c, p, "lock") -> "write"
                    [] At(c, p, "answer_lock") -> "answer_write"
                    [] OTHER -> "bye_write")
    /\ UNCHANGED <<used, accept, conn, pool, from, shut, stop>>

\* The client took the bytes.
Written(c, p) ==
    /\ Writing(c, p)
    /\ ~shut[c]
    /\ lock' = [lock EXCEPT ![c] = "free"]
    /\ Move(c, p, IF At(c, p, "bye_write") THEN "stop" ELSE "read")
    /\ UNCHANGED <<used, accept, conn, pool, from, shut, stop>>

\* A write fails: error, write timeout, sockets shut down, or the pump
\* panics. The lock is released in every case.
WriteFails(c, p) ==
    /\ Writing(c, p)
    /\ lock' = [lock EXCEPT ![c] = "free"]
    /\ Move(c, p, "stop")
    /\ UNCHANGED <<used, accept, conn, pool, from, shut, stop>>

\* A stopping pump shuts down both sockets, also when it is unwinding from
\* a panic.
Stop(c, p) ==
    /\ At(c, p, "stop")
    /\ shut' = [shut EXCEPT ![c] = TRUE]
    /\ Move(c, p, "done")
    /\ UNCHANGED <<used, accept, conn, pool, from, lock, stop>>

\* The connection's thread waits for the second thread, then ends and
\* gives the slot back.
EndTunnel(c) ==
    /\ conn[c] = "tunnel"
    /\ \A p \in Sides : At(c, p, "done")
    /\ Leave(c)
    /\ pump' = [pump EXCEPT ![c] = [p \in Sides |-> "off"]]
    /\ shut' = [shut EXCEPT ![c] = FALSE]
    /\ UNCHANGED <<accept, lock, stop>>

(***************************************************************************)
(* Stopping                                                                *)
(***************************************************************************)

\* SIGTERM (or SIGINT) comes.
Terminate ==
    /\ ~stopping
    /\ stopping' = TRUE
    /\ UNCHANGED <<used, accept, conn, pool, from, pump, lock, shut, deadline, ended, late>>

\* A stopping server cuts a tunnel: it shuts the sockets down, which ends
\* both pumps. (Connections waiting for a request are cut too; they end
\* with Finish, below.)
Cut(c) ==
    /\ stopping
    /\ conn[c] = "tunnel"
    /\ ~shut[c]
    /\ shut' = [shut EXCEPT ![c] = TRUE]
    /\ UNCHANGED <<used, accept, conn, pool, from, pump, lock, stop>>

\* The time a stop waits for the requests being served is up.
Deadline ==
    /\ stopping /\ ~deadline
    /\ deadline' = TRUE
    /\ UNCHANGED <<used, accept, conn, pool, from, pump, lock, shut, stopping, ended, late>>

\* The process exits: no connection is left, or the deadline has come.
Exit ==
    /\ stopping
    /\ Live = {} \/ deadline
    /\ ended' = TRUE
    /\ UNCHANGED <<used, accept, conn, pool, from, pump, lock, shut, stopping, deadline, late>>

Running ==
    \/ Terminate \/ Deadline \/ Exit \/ \E c \in Conns : Cut(c)
    \/ \E l \in Listeners :
        \/ Reserve(l) \/ AcceptFails(l)
        \/ \E k \in Pools, a \in Addresses :
            TurnAway(l, k, a) \/ \E c \in Conns : Accept(l, c, k, a)
    \/ \E c \in Conns : Finish(c) \/ StartTunnel(c) \/ EndTunnel(c)
    \/ \E c \in Conns, p \in Sides :
        \/ Data(c, p) \/ Answer(c, p) \/ ReadEnds(c, p) \/ TakeLock(c, p)
        \/ Written(c, p) \/ WriteFails(c, p) \/ Stop(c, p)

\* Once the process has exited, nothing happens any more.
Next == (~ended /\ Running) \/ (ended /\ UNCHANGED vars)

\* What the liveness properties rely on, while the process runs.
Fairness ==
    /\ WF_vars(~ended /\ Exit)
    /\ \A c \in Conns :
        /\ WF_vars(~ended /\ EndTunnel(c))
        \* a stopping server cuts the tunnels, and the requests it is
        \* serving end (by their timeouts, if not before)
        /\ WF_vars(~ended /\ Cut(c))
        /\ WF_vars(~ended /\ stopping /\ Finish(c))
        /\ \A p \in Sides :
            /\ WF_vars(~ended /\ Stop(c, p))
            \* a read or write on a socket that is shut down returns at once
            /\ WF_vars(~ended /\ shut[c] /\ (ReadEnds(c, p) \/ WriteFails(c, p)))
            \* a write has a timeout: it does not block for ever
            /\ WF_vars(~ended /\ (Written(c, p) \/ WriteFails(c, p)))
            \* a thread waiting for the lock gets it once it is free
            /\ SF_vars(~ended /\ TakeLock(c, p))

Spec == Init /\ [][Next]_vars /\ Fairness

(***************************************************************************)
(* Properties                                                              *)
(***************************************************************************)

PumpStates == {"off", "read", "lock", "write", "answer_lock", "answer_write", "bye_lock", "bye_write", "stop", "done"}

TypeOK ==
    /\ used \in Nat
    /\ accept \in [Listeners -> {"wait", "ready"}]
    /\ conn \in [Conns -> {"free", "serve", "tunnel"}]
    /\ pool \in [Conns -> Pools \cup {"none"}]
    /\ from \in [Conns -> Addresses \cup {"none"}]
    /\ pump \in [Conns -> [Sides -> PumpStates]]
    /\ lock \in [Conns -> Sides \cup {"free"}]
    /\ shut \in [Conns -> BOOLEAN]
    /\ {stopping, deadline, ended, late} \subseteq BOOLEAN

\* Never more connections in a pool than its cap, nor from one address in
\* the public pool than PerAddress; never more slots taken than the two
\* pools hold.
CapRespected == \A k \in Pools : Cardinality(InPool(k)) <= Cap
PerAddressRespected == \A a \in Addresses : Cardinality(FromAddress(a)) <= PerAddress
ReservationsBounded == used <= 2 * Cap

\* Every slot taken belongs to exactly one accept loop or connection, so
\* none is lost and none is given back twice; a connection's slot is from
\* a pool exactly while it lives.
SlotsAccounted ==
    used = Cardinality({l \in Listeners : accept[l] = "ready"}) + Cardinality(Live)
PoolsAccounted ==
    \A c \in Conns :
        /\ (conn[c] # "free") = (pool[c] # "none")
        /\ (conn[c] # "free" /\ pool[c] = "public") = (from[c] # "none")

\* No pump thread outlives its connection.
NoStrayThread ==
    \A c \in Conns : conn[c] # "tunnel" => \A p \in Sides : At(c, p, "off")

\* The write lock is held by exactly the pump that is writing, so two
\* pumps never write to the client at once.
OneWriter ==
    \A c \in Conns, p \in Sides : Writing(c, p) <=> lock[c] = p

\* Copying from the client never waits for the write lock, so a client
\* that does not read what we send cannot stop us reading what it sends;
\* unless it asks for a KeyUpdate, whose answer does wait (answer_lock),
\* which stalls only the client that asked.
ReadingNeverWaits ==
    \A c \in Conns : pump[c]["up"] \notin {"lock", "write"}

\* Once one pump's read has ended, the whole tunnel ends and its slot is
\* free again. This covers half-close, idle timeout and a panic in either
\* thread.
TunnelEnds ==
    \A c \in Conns :
        (\E p \in Sides : pump[c][p] \in {"bye_lock", "bye_write", "stop"})
            ~> (conn[c] = "free" \/ ended)

\* A pump waiting for the write lock does not wait for ever, while the
\* process runs.
LockGranted ==
    \A c \in Conns, p \in Sides : Waiting(c, p) ~> (~Waiting(c, p) \/ ended)

\* Nobody is let in once the server is stopping.
NoneLetInWhileStopping == ~late

\* A stop always ends with the process exiting, and need not wait for its
\* deadline: without it, the connections left all end (the tunnels cut,
\* the requests finished) and the process exits then.
StopEnds == stopping ~> ended

\* Keeps the model small: one tunnel at a time. A tunnel's threads, lock
\* and sockets are its own, and which pool a slot is from does not depend
\* on how many connections are tunnels.
OneTunnel == Cardinality({c \in Conns : conn[c] = "tunnel"}) <= 1

\* Not a property. tools/spec.sh confirms the model gets this far: every
\* slot is taken, by every connection there can be (one of them a tunnel,
\* a pool full) and an accept loop, and the other accept loop waits.
Full ==
    /\ used = 2 * Cap
    /\ Live = Conns
    /\ \E k \in Pools : Cardinality(InPool(k)) = Cap
    /\ \E c \in Conns : conn[c] = "tunnel"
    /\ \E l \in Listeners : accept[l] = "wait"

\* Not a property. A connection is turned away while the other pool has
\* room: one pool is full and the other is not.
OnePoolFull ==
    /\ Cardinality(InPool("public")) = Cap
    /\ Cardinality(InPool("allowed")) < Cap
    /\ \E l \in Listeners : accept[l] = "ready"

\* Not a property. A stop that ended without its deadline, the server
\* drained.
Drained == ended /\ ~deadline

\* Not a property. One pump waits for the lock while the other holds it.
Contended ==
    \E c \in Conns : At(c, "up", "bye_lock") /\ At(c, "down", "write")

=============================================================================
