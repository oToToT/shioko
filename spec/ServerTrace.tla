---------------------------- MODULE ServerTrace ----------------------------
(***************************************************************************)
(* A recorded run of the real server, checked against Server.tla.          *)
(*                                                                         *)
(* A build with --features record logs each step of Server.tla as its      *)
(* thread takes it (src/record.rs); tools/servertrace.py turns the log     *)
(* into Steps, in module ServerRecorded. TLC takes the steps one after the *)
(* other, each with the action of Server.tla it names, and checks the      *)
(* spec's invariants in every state on the way: the cap, the slots, no     *)
(* stray thread, one writer, reading never waiting for the write lock. A   *)
(* step the spec does not allow where it comes stops the run there.        *)
(*                                                                         *)
(* One allowance: in the spec a pump cannot read data, or finish a write,  *)
(* once the other pump has shut the sockets down. A read or write that     *)
(* returned just before the other thread's shutdown may still be recorded  *)
(* just after it, since the two threads write their lines without a lock   *)
(* in common. So here those two steps do not look at `shut`. No invariant  *)
(* depends on it.                                                          *)
(***************************************************************************)
EXTENDS Server, ServerRecorded, Sequences, TLC

VARIABLE i  \* the next step

TraceData(c, p) ==
    /\ p = "down" /\ At(c, p, "read")
    /\ Move(c, p, "lock")
    /\ UNCHANGED <<used, accept, conn, pool, from, lock, shut>>

TraceWritten(c, p) ==
    /\ Writing(c, p)
    /\ lock' = [lock EXCEPT ![c] = "free"]
    /\ Move(c, p, IF At(c, p, "write") THEN "read" ELSE "stop")
    /\ UNCHANGED <<used, accept, conn, pool, from, shut>>

Take(s) ==
    CASE s.what = "reserve"     -> Reserve(s.l)
      [] s.what = "accept"      -> Accept(s.l, s.c, s.k, s.a)
      [] s.what = "turn_away"   -> TurnAway(s.l, s.k, s.a)
      [] s.what = "fail"        -> AcceptFails(s.l)
      [] s.what = "release"     -> Finish(s.c) \/ EndTunnel(s.c)
      [] s.what = "tunnel"      -> StartTunnel(s.c)
      [] s.what = "data"        -> TraceData(s.c, s.p)
      [] s.what = "read_ends"   -> ReadEnds(s.c, s.p)
      [] s.what = "lock"        -> TakeLock(s.c, s.p)
      [] s.what = "unlock_ok"   -> TraceWritten(s.c, s.p)
      [] s.what = "unlock_fail" -> WriteFails(s.c, s.p)
      [] s.what = "stop"        -> Stop(s.c, s.p)

TraceInit == Init /\ i = 1

\* tools/servertrace.py reads what TLC prints.
TraceNext ==
    \/ /\ i <= Len(Steps)
       /\ Take(Steps[i])
       /\ i' = i + 1
       /\ PrintT(<<"reached", i'>>)
    \/ /\ i > Len(Steps)
       /\ PrintT(<<"accepted">>)
       /\ UNCHANGED <<vars, i>>

=============================================================================
