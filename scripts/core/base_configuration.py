import requests
import json
import os
import sys
import subprocess
from termcolor import colored
from kubernetes import client, utils
from kubernetes.client import Configuration, ApiClient


class BaseConfiguration:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        kubeconfig = Configuration()
        kubeconfig.host = "http://127.0.0.1:8080"
        self.api_client = ApiClient(configuration=kubeconfig)
        self.v1 = client.CoreV1Api(api_client=self.api_client)

        self.steps = []

    def log(self, log_prefix: str, *message):
        print(log_prefix, *message)

    def log_k8s_api_error(self, log_prefix: str, err: utils.FailToCreateError):
        self.log(log_prefix, colored(
            "Failed to create following resources:", "red", attrs=["bold"]))
        for err in err.api_exceptions:
            error = json.loads(err.body)
            reason = error["reason"]
            message = error["message"]
            print(colored(f"{log_prefix} {reason}: {message}",
                  "yellow" if reason == "AlreadyExists" else "red", attrs=["bold"]))
            if reason != "AlreadyExists":
                print(colored(f"{log_prefix} {err}", "red", attrs=["bold"]))

    def run(self):
        total_steps = len(self.steps)
        print(colored(f"Running {self.__class__.__name__} with {total_steps} steps",
              "green", "on_yellow", attrs=["bold"]))
        for idx, step in enumerate(self.steps):
            log_prefix = "[{}/{}]: {} : ".format(idx + 1,
                                                 total_steps, step.__name__)
            print(colored(log_prefix + "Starting", "magenta", attrs=["bold"]))
            step(log_prefix, **self.kwargs)

    def run_process(self, *cmd, log_prefix: str, handle_error=True):
        completed_process = None
        print(colored(f"{log_prefix} {' '.join(cmd[0])}", "yellow"))
        try:
            completed_process = subprocess.run(
                *cmd, env=os.environ.copy(), capture_output=True)
        except subprocess.CalledProcessError as e:
            print(colored(log_prefix, "Error running command: {}".format(
                e), "red", attrs=["bold"]))
            sys.exit(1)
        return_code, out, err = completed_process.returncode, completed_process.stdout, completed_process.stderr
        out, err = out.decode(), err.decode()
        print(colored(
            f"{log_prefix} Command completed with exit code {return_code}", "blue", attrs=["bold"]))
        print(f"{log_prefix} ", out)
        print(colored(f"{log_prefix} {err}",
              "green" if return_code == 0 else "red"))
        if handle_error and return_code != 0:
            sys.exit(1)
        return return_code, out, err

    def is_gh_repo_private(self, gh_user, gh_repo: str) -> bool:
        r = requests.get(f"https://api.github.com/repos/{gh_user}/{gh_repo}")
        return r.status_code == 404

