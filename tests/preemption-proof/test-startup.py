"""Deterministic isolated startup regression, real socket and UartCapture, no VM."""
import argparse
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback

sys.dont_write_bytecode=True
import run

SMOKE=run.load("qemu-smoke.py")
PAYLOAD=b"local socket bytes, not guest evidence\r\n"


def require(ok,message):
    if not ok:
        raise AssertionError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reject(action,kind,contains):
    try:
        action()
    except kind as error:
        require(contains in str(error),f"Wrong error: {error!r}")
        return repr(error)
    raise AssertionError(f"Expected {kind.__name__}: {contains}")


class OpenGate:
    """Delay the actual shared UartCapture._read open, not its implementation."""
    def __init__(self,path,fail=False):
        self.path=path
        self.entered=threading.Event()
        self.release=threading.Event()
        self.fail=fail

    def open(self,*args,**kwargs):
        self.entered.set()
        require(self.release.wait(5),"Host test did not release open gate")
        if self.fail:
            raise OSError("controlled reader open failure")
        return self.path.open(*args,**kwargs)

    def is_file(self):
        exists=self.path.is_file()
        if not exists:
            self.release.set()
        return exists

    def stat(self):
        return self.path.stat()

    def read_bytes(self):
        return self.path.read_bytes()


@contextmanager
def alive_process():
    # Actual host subprocess, deliberately not QEMU or GDB.
    process=subprocess.Popen([sys.executable,"-c","import sys; sys.stdin.buffer.read()"],stdin=subprocess.PIPE)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
        process.stdin.close()


@contextmanager
def capture_fixture(path,fail=False):
    with alive_process() as process:
        reader,writer=socket.socketpair()
        reader.settimeout(.05)
        gate=OpenGate(path,fail)
        uart=SMOKE.UartCapture(reader,gate)
        try:
            require(gate.entered.wait(3) and not path.exists(),"Reader did not reach delayed open")
            yield process,uart,writer,gate
        finally:
            uart.stop.set()
            gate.release.set()
            try:
                uart.close()
            finally:
                writer.close()


def tests(root,results):
    serial=root/"late-com1.log"
    with capture_fixture(serial) as (process,uart,writer,gate):
        # This is the exact original call before the fix, while open is gated.
        results["old_uart_failure"]=reject(lambda:SMOKE.wait_session(process,uart,serial,
            lambda data:bool(data),"old startup",1),FileNotFoundError,str(serial))
        require(not serial.exists() and not gate.release.is_set(),"Old failure changed file")
        observed=[]
        def on_reader(record):
            require(record["reader_ready"] and record["bytes_at_readiness"]==0 and
                    not record["shell_ready_verified"] and serial.is_file(),"Reader confused with guest READY")
            observed.append(record)
            writer.sendall(PAYLOAD)
        log=run.wait_initial_session(SMOKE,process,uart,gate,lambda data:data==PAYLOAD,
                                    time.monotonic()+3,on_reader)
        require(len(observed)==1 and log==serial.read_bytes()==PAYLOAD,"Not actual socket data")
        results["delayed_uart_and_read"]={"startup":observed[0],"first_match_hex":log.hex(),
                                        "bytes":len(log),"guest_ready":False}
    serial=root/"dead-com1.log"
    with capture_fixture(serial) as (process,uart,writer,gate):
        process.terminate(); process.wait(timeout=5)
        results["dead_process"]=reject(lambda:run.wait_uart_reader(process,uart,serial,time.monotonic()+2),
                                       RuntimeError,"QEMU exited during COM1 startup")
        require(not serial.exists(),"Dead process created evidence")
    serial=root/"error-com1.log"
    with capture_fixture(serial,fail=True) as (process,uart,writer,gate):
        gate.release.set(); uart.worker.join(timeout=3)
        require(isinstance(uart.error,OSError),"Missing actual reader exception")
        results["reader_exception"]=reject(lambda:run.wait_uart_reader(process,uart,serial,time.monotonic()+2),
                                           RuntimeError,"controlled reader open failure")
        require(not serial.exists(),"Reader failure created evidence")
    serial=root/"timeout-com1.log"
    with capture_fixture(serial) as (process,uart,writer,gate):
        deadline=time.monotonic()+.10
        results["missing_file_timeout"]=reject(lambda:run.wait_uart_reader(process,uart,serial,deadline),
                                               TimeoutError,"COM1 reader startup deadline expired")
        require(time.monotonic()>=deadline and not serial.exists(),"Missing file timeout not real")
    serial=root/"empty-com1.log"
    with capture_fixture(serial) as (process,uart,writer,gate):
        observed=[]
        deadline=time.monotonic()+.20
        results["empty_file_not_ready"]=reject(lambda:run.wait_initial_session(SMOKE,process,uart,gate,
            lambda data:bool(data),deadline,observed.append),TimeoutError,"ordinary shell")
        require(len(observed)==1 and observed[0]["bytes_at_readiness"]==0 and not observed[0]["shell_ready_verified"] and
                time.monotonic()>=deadline and serial.stat().st_size==0,"File existence accepted as READY")
        results["empty_file_reader"]=observed[0]
    # The old debugger startup read accepted file existence as a complete
    # record. Control a partial write to reproduce that separate race.
    path=root/"trace-ready.json"
    with alive_process() as debugger, path.open("w",buffering=1) as stream:
        stream.write('{"hardware":'); stream.flush()
        results["old_debugger_failure"]=reject(lambda:json.loads(path.read_text()),json.JSONDecodeError,"Expecting value")
        released=threading.Event()
        class PartialPath:
            def read_text(self):
                data=path.read_text()
                released.set()
                return data
        def finish():
            require(released.wait(3),"Debugger wait did not read partial JSON")
            stream.write('true,"threads":1,"fixture":true}'); stream.flush()
        worker=threading.Thread(target=finish)
        worker.start()
        try:
            ready=run.wait_debugger_ready(debugger,PartialPath(),time.monotonic()+3)
            require(ready=={"hardware":True,"threads":1,"fixture":True},"Invalid completed fixture")
            results["delayed_debugger_record"]=ready
        finally:
            released.set(); worker.join(timeout=4)
            require(not worker.is_alive(),"Debugger fixture thread did not finish")
    path=root/"partial-timeout.json"
    with alive_process() as debugger:
        path.write_text('{"hardware":')
        results["debugger_timeout"]=reject(lambda:run.wait_debugger_ready(debugger,path,time.monotonic()+.10),
                                            TimeoutError,"Debugger did not arm")
        debugger.terminate(); debugger.wait(timeout=5)
        results["debugger_death"]=reject(lambda:run.wait_debugger_ready(debugger,path,time.monotonic()+2),
                                          RuntimeError,"Debugger exited before arming")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt",type=Path,required=True)
    args=parser.parse_args()
    result=dict(result="fail",guest_runs=0,scope="host socket fixtures only",cases={},sources={
        "runner":digest(Path(run.__file__)),"smoke":digest(Path(SMOKE.__file__)),"test":digest(Path(__file__))})
    try:
        with tempfile.TemporaryDirectory(prefix="agentos-startup-") as tmp:
            tests(Path(tmp),result["cases"])
        result["result"]="pass"
    except Exception as exc:
        result.update(error=repr(exc),traceback=traceback.format_exc())
    finally:
        raw=json.dumps(result,sort_keys=True,indent=2)+"\n"
        args.receipt.write_text(raw)
        print(raw,end="",flush=True)
    return int(result["result"]!="pass")


if __name__=="__main__":
    raise SystemExit(main())
