"""Strict IPC workload evidence, inside the independently authenticated CPU bracket."""
import re

MASK64=(1<<64)-1


def fnv(length):
    result=2166136261
    for i in range(length):
        result=((result^((i*73+i//251)&255))*16777619)&0xffffffff
    return result


def neg(value):
    return value&MASK64


def first_free(mask):
    return next((i for i in range(32) if not mask&(1<<i)),-1)


def verify_interval(line,pid,before,seen,supervisor,require):
    def fields(kind,names):
        pattern="AGENTOS IPC TEST "+kind+"".join(" "+n+"=("+supervisor.HEX16+")" for n in names)
        match=re.fullmatch(pattern,line())
        require(match is not None,"Missing or malformed IPC "+kind)
        return tuple(int(v,16) for v in match.groups())

    timer_before=fields("TIMER_BEFORE",("PID","VERSION","MS","TIMERS","IDLE"))
    errors=fields("TIMER_ERRORS",("PID","NULL","WRAP","RO","SIZE","FLAGS"))
    timer_after=fields("TIMER_AFTER",("PID","VERSION","MS","TIMERS","IDLE"))
    require(timer_before[:2]==timer_after[:2]==(pid,2) and
            before["ms"]<=timer_before[2]<=timer_after[2] and
            timer_before[4]<=timer_before[3] and timer_after[4]<=timer_after[3] and
            all(a<=b for a,b in zip(timer_before[3:],timer_after[3:])) and
            errors==(pid,neg(-14),neg(-14),neg(-14),neg(-22),neg(-22)),
            "Invalid exact timer statistics or boundary syscall results")
    channel_errors=fields("CHANNEL_ERRORS",("PID","FULL","SHORT","NULL","RO","WRAP"))
    require(channel_errors==(pid,neg(-11),neg(-90),neg(-14),neg(-14),neg(-14)),
            "IPC full mailbox or non-consuming failures differ")
    messages=[]
    for seq,length in enumerate((1024,1,7,1024),1):
        actual,number,peer,uid,gid,fd,n,digest=fields(
            "MESSAGE",("PID","SEQ","PEER","UID","GID","FD","BYTES","FNV"))
        require((actual,number,peer,uid,gid,n,digest)==
                (pid,seq,pid,1000,1000,length,fnv(length)),
                "Incorrect complete message, boundary, direction or authenticated self identity")
        messages.append({"seq":seq,"fd":fd,"bytes":n,"fnv32":digest,"peer":peer,"uid":uid,"gid":gid})
    channel_end=fields("CHANNEL_END",("PID","EMPTY","EOF","TRYPIPE","PIPE"))
    require(channel_end==(pid,neg(-11),0,neg(-32),neg(-32)),
            "IPC drain, EOF or EPIPE differs")
    owner,initial,occupied,held,first,second,duplicate,restored=fields(
        "FDS",("PID","INITIAL","OCCUPIED","HELD","FIRST","SECOND","DUP","RESTORED"))
    require(owner==pid and initial==restored==7 and held==first_free(initial)+1 and
            occupied==initial|(1<<held) and
            first==first_free(occupied) and second==first_free(occupied|(1<<first)) and
            duplicate==first_free(occupied|(1<<first)|(1<<second)) and
            [m["fd"] for m in messages]==[second,first,second,duplicate],
            "Descriptor allocation, message direction, duplicate or stdio restoration differs")

    child,parent,cpu,cpus,moves,total,ms=fields(
        "SERVICE_CPU",("PID","PARENT","APIC","CPUS","MOVES","TOTAL","MS"))
    require(child>max(seen|{pid}) and parent==pid and timer_after[2]<=ms and
            0<=moves<=total<2**63 and total>=before["total"],
            "Foreign, reused or invalid IPC counterpart scheduling identity")
    child_fds=fields("SERVICE_FDS",("PID","INHERITED","REMAINING","SHORT","NULL"))
    endpoint=31
    inherited=initial|(1<<first_free(initial))|(1<<endpoint)
    require(child_fds==(child,inherited,initial|(1<<endpoint),neg(-90),neg(-14)),
            "Counterpart inherited wrong descriptors or consumed request on a failed operation")
    challenge=(pid*0x9e3779b97f4a7c15+child)&MASK64
    answer=(((challenge<<9)|(challenge>>55))&MASK64)^0x6d97341b
    service=fields("SERVICE",("PID","PEER","UID","GID","CHALLENGE","ANSWER","DENIED"))
    require(service==(child,pid,1000,1000,challenge,answer,neg(-1)),
            "Counterpart peer credentials, challenge response or isolation differs")
    match=supervisor.EXIT.fullmatch(line())
    require(match is not None,"Missing real IPC counterpart exit")
    exited,cr3,status=(int(v,16) for v in match.groups())
    require((exited,status)==(child,0) and cr3>0 and cr3%4096==0,
            "IPC counterpart did not exit normally from a private space")
    reply=fields("REPLY",("PID","PEER","UID","GID","OBSERVED","CHALLENGE","ANSWER"))
    require(reply==(pid,child,1000,1000,pid,challenge,answer),
            "Reply does not authenticate both actual participants and their response")
    reaped=fields("REAP",("PID","CHILD","STATUS","AGAIN","EOF","PIPE","INHERITED","RESTORED"))
    require(reaped==(pid,child,0,neg(-10),0,neg(-32),inherited,initial),
            "Missing actual single child collection, endpoint drain or descriptor cleanup")
    seen.add(child)
    return {"duration_ms":ms-before["ms"],"child_pid":child,"child_cr3":cr3,"child_statuses":[status],
            "child":{"pid":child,"parent":parent,"apic":cpu,"cpus":cpus,"moves":moves,"total":total,"ms":ms},
            "timer_before":list(timer_before[1:]),"timer_after":list(timer_after[1:]),
            "timer_errors":[-14,-14,-14,-22,-22],
            "messages":messages,"fd_initial":initial,"fd_occupied":occupied,
            "fd_pair":[first,second],"fd_duplicate":duplicate,"fd_restored":restored,
            "peer_uid":service[2],"peer_gid":service[3],"reply_uid":reply[2],"reply_gid":reply[3],
            "challenge":challenge,"answer":answer,"inherited":inherited,"child_remaining":child_fds[2],
            "collected_status":status,"second_wait":-10},[cr3]


def verify_bracket(outcome,before,after,apics,local,require):
    child=outcome["child"]
    require(child["apic"] in apics and child["cpus"]==len(apics) and
            before["ms"]<=child["ms"]<=after["ms"] and
            before["total"]<=child["total"]<=after["total"] and
            (len(apics)!=1 or child["total"]==child["moves"]==0),
            "Counterpart actual APIC, count, time or migration counters outside bracket")
    if local:
        require(child["apic"]==before["apic"]==after["apic"] and child["moves"]==0 and
                child["total"]==before["total"]==after["total"],
                "Counterpart was not local to its complete stationary IPC interval")
