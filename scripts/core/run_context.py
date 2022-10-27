from contextlib import contextmanager
import typing
import subprocess
import sys
import io

@contextmanager
def run(
    *args, check=False, return_stdout=False, env=None
) -> typing.Union[typing.NoReturn, io.TextIOBase]:
    kwargs = {"stdout": sys.stderr, "stderr": subprocess.STDOUT}
    if env is not None:
        kwargs["env"] = env
    if return_stdout:
        kwargs["stderr"] = sys.stderr
        kwargs["stdout"] = subprocess.PIPE
    args = [str(a) for a in args]
    print(
        "** Running",
        " ".join(map(lambda a: repr(a) if " " in a else a, args)),
        kwargs,
        file=sys.stderr,
        flush=True,
    )
    proc = None
    try:
        proc = subprocess.Popen(args, **kwargs)
        yield proc
    finally:
        if proc is not None:
            proc.terminate()
            proc.kill()

    if return_stdout:
        return proc.stdout
