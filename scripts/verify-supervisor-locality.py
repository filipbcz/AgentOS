"""Strict foreground CPU-locality transcript; no scheduler control or simulated evidence."""
import re


def verify(data, shell, shell_cr3, prior_pids, apics, supervisor, require, pipe=None):
    """Consume the bounded candidate protocol and every real child event."""
    require(len(apics) in (1,2), "Missing independently observed CPU roster")
    offset=0
    seen=set(prior_pids)
    covered=set()
    intervals=[]
    rejected=[]
    all_roots=[]

    def line():
        nonlocal offset
        end=data.find(b"\r\n",offset)
        require(end>=offset and data[offset:end].isascii(),"Truncated locality evidence")
        result=data[offset:end].decode("ascii")
        offset=end+2
        return result

    def fields(kind,names,record=None):
        pattern="AGENTOS TEST "+kind+"".join(" "+name+"=("+supervisor.HEX16+")" for name in names)
        match=re.fullmatch(pattern,line() if record is None else record)
        require(match is not None,"Missing or malformed locality "+kind)
        return tuple(int(v,16) for v in match.groups())

    def snap(kind,record=None):
        names=("PID","PARENT","APIC","CPUS","MOVES","TOTAL","MS")
        is_peer=kind in ("PEER_BEGIN","PEER_END")
        values=fields(kind,names+(("WORK",) if is_peer else ()),record)
        pid,parent,cpu,count,moves,total,ms=values[:7]
        require(cpu in apics and count==len(apics) and 0<=moves<=total<2**63 and ms<2**63 and
                (count!=1 or total==0),"Invalid scheduler snapshot")
        result={"pid":pid,"parent":parent,"apic":cpu,"moves":moves,"total":total,"ms":ms}
        if is_peer:
            result["work"]=values[7]
        return result

    def progresses(a,b):
        return (a["pid"],a["parent"])==(b["pid"],b["parent"]) and a["ms"]<=b["ms"] and \
            0<=b["moves"]-a["moves"]<=b["total"]-a["total"] and \
            (a["apic"]==b["apic"] or b["moves"]>a["moves"])

    def actual_exit(pid,status):
        m=supervisor.EXIT.fullmatch(line())
        require(m is not None,"Missing actual candidate/runner exit")
        actual,root,code=(int(v,16) for v in m.groups())
        require(actual==pid and code==status and root>0 and root%4096==0 and root!=shell_cr3,
                "Wrong actual candidate/runner exit or address space")
        return root

    start=snap("RUNNER")
    runner=start["pid"]
    require(start["parent"]==shell and runner>max(seen | {shell}),"Reused/foreign foreground runner")
    seen.add(runner)
    floor_ms,floor_total=start["ms"],start["total"]
    deadline=floor_ms+15000
    require(deadline<2**63,"Invalid locality deadline")
    pool=1 if len(apics)==1 else 2*len(apics)
    rounds=0
    for rnd in range(1,5):
        if covered==apics:
            break
        rounds=rnd
        require(fields("WAVE",("ROOT","ROUND","COUNT"))==(runner,rnd,pool),"Wrong bounded candidate wave")
        candidates=[]
        for slot in range(pool):
            root,number,index,pid=fields("CANDIDATE",("ROOT","ROUND","SLOT","PID"))
            require((root,number,index)==(runner,rnd,slot) and pid>max(seen),"Foreign, duplicate or replayed candidate PID")
            seen.add(pid)
            candidates.append(pid)
        ready=[]
        for pid in candidates:
            s=snap("READY")
            require((s["pid"],s["parent"])==(pid,runner) and floor_ms<=s["ms"]<=deadline and
                    s["total"]>=floor_total,"Foreign/replayed candidate placement report")
            ready.append(s)
        floor_ms=max(s["ms"] for s in ready)
        floor_total=max(s["total"] for s in ready)
        wave_roots=[]
        earlier_child_roots=[]
        remaining=list(candidates)
        placements=dict(zip(candidates,ready))

        def collect(pid,status,roots):
            root=actual_exit(pid,status)
            require(root not in wave_roots and root not in earlier_child_roots and
                    all(r!=root and r!=shell_cr3 for r in roots),"Aliased live candidate/child address space")
            wave_roots.append(root)
            earlier_child_roots.extend(roots)
            all_roots.extend([root,*roots])
            require(fields("REAP",("ROOT","PID","STATUS"))==(runner,pid,status),"Missing actual candidate collection")
            remaining.remove(pid)
            return root

        def attempt(pid,run):
            nonlocal floor_ms,floor_total
            placement=placements[pid]
            cpu=placement["apic"]
            require(fields("SELECT",("ROOT","PID","APIC","RUN"))==(runner,pid,cpu,int(run)),
                    "Duplicate CPU selection or incorrect candidate command")
            status=0
            roots=[]
            outcome=None
            if run:
                first=line()
                skipped=first.startswith("AGENTOS TEST SKIP ")
                before=snap("SKIP" if skipped else "BEGIN",first)
                require(progresses(placement,before) and floor_ms<=before["ms"]<=deadline-3000 and
                        before["total"]>=floor_total,"Stale or regressed candidate snapshot")
                if skipped:
                    require(before["apic"]!=cpu,"False placement miss")
                    status=75
                    outcome={"pid":pid,"reason":"placement","ready":placement,"before":before}
                    floor_ms,floor_total=before["ms"],before["total"]
                else:
                    require(before["apic"]==cpu,"Workload started on wrong CPU")
                    if pipe is not None:
                        outcome,roots=pipe.verify_interval(line,pid,before,seen,supervisor,require)
                    else:
                        begin=supervisor.BEGIN.fullmatch(line())
                        require(begin is not None and int(begin[1],16)==pid,"Supervisor parent mismatch")
                        previous=max(seen)
                        records=[]
                        try:
                            for _ in supervisor.EXPECTED_ORDER:
                                text=line()
                                item=supervisor.event(text)
                                require(item is not None,"Unexpected supervisor event")
                                records.append(item)
                                m=supervisor.EXIT.fullmatch(text)
                                if m:
                                    roots.append(int(m[2],16))
                            end=supervisor.END.fullmatch(line())
                            require(end is not None and int(end[1],16)==pid,"Supervisor end mismatch")
                            outcome=supervisor.verify_interval(pid,records,seen)
                        except supervisor.VerificationError as error:
                            require(False,"Foreground supervisor: "+str(error))
                        children=[outcome["healthy_pid"],*outcome["failed_pids"],outcome["killed_pid"]]
                        require(children==sorted(children) and min(children)>previous,"Replayed supervisor child PID")
                    after=snap("ENDED")
                    require(progresses(before,after) and after["ms"]<=deadline and
                            after["ms"]-before["ms"]>=outcome["duration_ms"],"Incomplete or regressed supervisor bracket")
                    local=all(before[k]==after[k] for k in ("apic","moves","total"))
                    status=0 if local else 76
                    if pipe is not None:
                        pipe.verify_bracket(outcome,before,after,apics,local,require)
                    else:
                        outcome["child_statuses"]=[records[i][3] for i in (0,2,4,6,9)]
                    outcome.update({"pid":pid,"apic":cpu,"before":before,"after":after})
                    if not local:
                        outcome["reason"]="migration"
                    floor_ms,floor_total=after["ms"],after["total"]
            root=collect(pid,status,roots)
            return status,outcome,root

        def accept(cpu,outcome):
            require(cpu not in covered,"Duplicate local CPU interval")
            covered.add(cpu)
            intervals.append(outcome)

        if len(apics)==2:
            # The same deterministic pairing policy as the guest controller.
            # Never accept an idle or absent peer, even for an otherwise local
            # supervisor interval. Both candidate lifetimes must be consumed.
            while True:
                pair=next(((pid,peer) for pid in remaining if placements[pid]["apic"] not in covered
                           for peer in remaining if placements[peer]["apic"]!=placements[pid]["apic"]),None)
                if pair is None:
                    break
                pid,peer=pair
                cpu,peer_cpu=placements[pid]["apic"],placements[peer]["apic"]
                require(fields("PAIR",("ROOT","PID","PEER"))==(runner,pid,peer),"Wrong or replayed peer selection")
                before=snap("PEER_BEGIN")
                require(progresses(placements[peer],before) and before["work"]==0 and
                        floor_ms<=before["ms"]<=deadline and before["total"]>=floor_total,
                        "Invalid peer start identity, counters or time")
                floor_ms,floor_total=before["ms"],before["total"]
                run=before["apic"]==peer_cpu
                status,outcome,root=attempt(pid,run)
                after=snap("PEER_END")
                require(progresses(before,after) and 0<after["work"]<=2000000 and
                        floor_ms<=after["ms"]<=deadline and after["total"]>=floor_total,
                        "Invalid peer work, stop identity, counters or time")
                floor_ms,floor_total=after["ms"],after["total"]
                peer_root=collect(peer,0,[])
                require(peer_root!=root,"Peer aliases live supervisor candidate")
                peer_proof={"pid":peer,"apic":peer_cpu,"before":before,"after":after,"cr3":peer_root}
                if not run:
                    rejected.append({"pid":pid,"reason":"peer-placement","peer":peer_proof})
                    continue
                outcome["peer"]=peer_proof
                if status!=75:
                    require(before["ms"]<=outcome["before"]["ms"]<=outcome["after"]["ms"]<=after["ms"] and
                            before["total"]<=outcome["before"]["total"]<=outcome["after"]["total"]<=after["total"],
                            "Peer does not bracket the full supervisor interval")
                stationary=after["apic"]==peer_cpu and after["moves"]==before["moves"]
                if status==0 and stationary:
                    accept(cpu,outcome)
                else:
                    if status==0:
                        outcome["reason"]="peer-migration"
                    rejected.append(outcome)
            for pid in remaining.copy():
                attempt(pid,False)
        else:
            for pid in remaining.copy():
                cpu=placements[pid]["apic"]
                run=cpu not in covered
                status,outcome,_=attempt(pid,run)
                if run and status==0:
                    accept(cpu,outcome)
                elif run:
                    rejected.append(outcome)
        require(not remaining,"Uncollected wave candidate or peer")
    require(covered==apics and len(intervals)==len(apics),"Incomplete per-CPU supervisor coverage")
    end=snap("COMPLETE")
    require(progresses(start,end) and floor_ms<=end["ms"]<=deadline and end["total"]>=floor_total,
            "Incomplete controller cleanup or regressed counters")
    root=actual_exit(runner,0)
    require(root not in all_roots,"Candidate reused the live controller address space")
    reply=b"exit status 0\r\nagentos> "
    require(data.startswith(reply,offset),"Shell did not collect real runner exit")
    return offset+len(reply),{"absent":False,"runner_pid":runner,"shell_pid":shell,"runner_cr3":root,
        "runner_status":0,"cpus":len(apics),"covered_apics":sorted(covered),"rounds":rounds,
        "intervals":intervals,"rejected":rejected,"elapsed_ms":end["ms"]-start["ms"]},seen-set(prior_pids)
