import argparse
import typing
import subprocess
import sys
import io
import os
import json
import base64
import pathlib
import requests
import time
from contextlib import contextmanager

from kubernetes import client, utils
from kubernetes.client import Configuration, ApiClient
from pyrage import x25519
from termcolor import colored


AGE_PUBLIC_KEY_FILE = (pathlib.Path(
    __file__).parent.parent / "age.pubkey").resolve()


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


class ClusterConfiguration(BaseConfiguration):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.steps = [
            self.create_flux_system_namespace,
            self.setup_age_secret,
            self.setup_github_secret,

        ]

    def create_flux_system_namespace(self, log_prefix: str | None = None, **kwargs):
        all_namespaces = self.v1.list_namespace()
        if "flux-system" in [ns.metadata.name for ns in all_namespaces.items]:
            self.log(log_prefix, colored(
                "flux-system namespace already exists", "yellow"))
            return
        self.log(log_prefix, "Creating flux-system namespace")
        self.v1.create_namespace(body={"metadata": {"name": "flux-system"}})

    def setup_age_secret(self, log_prefix: str | None = None, **kwargs):
        # get the current secrets
        current_secrets = self.v1.list_namespaced_secret(
            namespace="flux-system")
        # check if the secret already exists
        if "sops-age" in [secret.metadata.name for secret in current_secrets.items]:
            if not kwargs.get("force_age_secret", False):
                self.log(log_prefix, colored(
                    "Age secret already exists, skipping", "blue"))
                return
            self.log(
                log_prefix,
                colored(
                    "Age secret already exists, but force_age_secret is set to True, recreating", "yellow"),
            )
            self.log(log_prefix, colored(
                "Deleting existing age secret", "red"))
            self.v1.delete_namespaced_secret(
                name="sops-age", namespace="flux-system")
        # create the secret
        self.age_id = x25519.Identity.generate()
        self.age_pubkey = str(self.age_id.to_public())
        self.age_privkey = str(self.age_id)
        secret = {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": "sops-age",
                "namespace": "flux-system",
            },
            "data": {
                "age.agekey": base64.b64encode(self.age_privkey.encode()).decode()
            },
        }
        self.log(log_prefix, "Creating secret", json.dumps(secret, indent=4))
        self.v1.create_namespaced_secret(namespace="flux-system", body=secret)
        with open(AGE_PUBLIC_KEY_FILE, "w") as f:
            self.log(log_prefix, f"Writing age public key to", colored(
                AGE_PUBLIC_KEY_FILE, "green", attrs=["bold"]))
            f.write(self.age_pubkey)

    def setup_github_secret(self, log_prefix: str | None = None, **kwargs):
        # get the current secrets
        current_secrets = self.v1.list_namespaced_secret(
            namespace="flux-system")
        # check if the secret already exists
        if "github-flux-auth" in [secret.metadata.name for secret in current_secrets.items]:
            if not kwargs.get("force_github_secret", False):
                self.log(log_prefix, colored(
                    "Github secret already exists, skipping", "blue"))
                return
            self.log(
                log_prefix,
                colored(
                    "Github secret already exists, but force_github_secret is set to True, recreating", "yellow"),
            )
            self.log(log_prefix, colored(
                "Deleting existing github secret", "red"))
            self.v1.delete_namespaced_secret(
                name="github-flux-auth", namespace="flux-system")
        # create the secret
        gh_user = kwargs.get("gh_user")
        if not gh_user:
            self.log(log_prefix, colored(
                "No github user provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No github user provided. Please provide a github user using the --gh-user flag")
        gh_password = kwargs.get("gh_password")
        if not gh_password:
            self.log(log_prefix, colored(
                "No github password provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No github password provided. Please provide a github password using the --gh-password flag")

        secret = {
            "kind": "Secret",
            "apiVersion": "v1",
            "metadata": {
                "name": "github-flux-auth",
                "namespace": "flux-system",
            },
            "data": {
                "username": base64.b64encode(f"{gh_user}\n".encode()).decode(),
                "password": base64.b64encode(f"{gh_password}\n".encode()).decode(),
            }
        }
        self.log(log_prefix, "Creating secret", json.dumps(secret, indent=4))
        self.v1.create_namespaced_secret(namespace="flux-system", body=secret)


class FluxConfiguration(BaseConfiguration):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.kubeconfig = kwargs.get("kube_config")
        self.cluster_name = kwargs.get("cluster_name")
        self.gh_repo = kwargs.get("gh_repo")
        self.gh_user = kwargs.get("gh_user")
        self.cluster_path = pathlib.Path(
            __file__).parent.parent / "clusters" / self.cluster_name
        self.infra_path = self.cluster_path / "infrastructure.yaml"
        self.apps_path = self.cluster_path / "apps.yaml"
        self.source_path = self.cluster_path / "source.yaml"
        self.flux_path = self.cluster_path / "flux.yaml"

        self.steps = [
            self.check_config,
            self.restart_coredns_pods,
            self.restart_metrics_server,
            self.flux_preflight_check,
            self.generate_flux_source,
            self.install_flux,
            self.install_apps,
        ]

    def check_config(self, log_prefix: str | None = None, **kwargs):

        if self.kubeconfig is None:
            self.log(self.__class__.__name__, colored(
                "No kubeconfig provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No kubeconfig provided. Please provide a kubeconfig using the --kube-config flag")
        self.env = {"KUBECONFIG": self.kubeconfig, "PATH": os.environ["PATH"]}

        if self.gh_repo is None:
            self.log(log_prefix, colored(
                "No github repo provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No github repo provided. Please provide a github repo using the --gh-repo flag")

        if self.gh_user is None:
            self.log(log_prefix, colored(
                "No github user provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No github user provided. Please provide a github user using the --gh-user flag")

        if self.cluster_name is None:
            self.log(log_prefix, colored(
                "No cluster name provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No cluster name provided. Please provide a cluster name using the --cluster-name flag")

        if not self.cluster_path.exists():
            self.log(log_prefix, colored(
                f"Cluster path {self.cluster_path} does not exist", "red", attrs=["bold", "blink"]))
            raise ValueError(
                f"Please ensure you have created a directory for cluster {self.cluster_name} as described in the README and provide a valid cluster name using the --cluster-name flag")

        if not self.infra_path.exists():
            self.log(log_prefix, colored(
                f"Infrastructure file {self.infra_path} does not exist", "red", attrs=["bold", "blink"]))
            raise ValueError(
                f"Please ensure you have created an {self.infra_path} file for cluster {self.cluster_name} as described in the README")

        if not self.apps_path.exists():
            self.log(log_prefix, colored(
                f"Applications file {self.apps_path} does not exist", "red", attrs=["bold", "blink"]))
            raise ValueError(
                f"Please ensure you have created an {self.apps_path} file for cluster {self.cluster_name} as described in the README")

    def restart_coredns_pods(self, log_prefix: str | None = None, **kwargs):
        self.log(log_prefix, colored("Restarting coredns pods", "green"))
        self.run_process([
            "kubectl", "rollout", "restart", "deployment/coredns", "-n", "kube-system"
        ], log_prefix=log_prefix)
        self.log(log_prefix, colored("Sleeping for 10s", "yellow"))
        time.sleep(10)

    def restart_metrics_server(self, log_prefix: str | None = None, **kwargs):
        self.log(log_prefix, colored("Restarting metrics server", "green"))
        self.run_process([
            "kubectl", "rollout", "restart", "deployment/metrics-server", "-n", "kube-system"
        ], log_prefix=log_prefix)
        self.log(log_prefix, colored("Sleeping for 10s", "yellow"))
        time.sleep(10)

    def flux_preflight_check(self, log_prefix: str | None = None, **kwargs):
        self.run_process(["flux", "check", "--pre"], log_prefix=log_prefix)

    def generate_flux_source(self, log_prefix: str | None = None, **kwargs):
        cmd = [
            "flux", "create", "source", "git", "flux-system",
            "--url", self.gh_repo,
            "--branch", "main",
            "--interval", "1m",
            "--export"
        ]
        repo_name = self.gh_repo.split("/")[-1]
        if self.is_gh_repo_private(self.gh_user, repo_name):
            self.log(log_prefix, colored(
                "Github repo is private. Will use github-flux-auth secret", "yellow"))
            cmd.extend(
                [
                    "--secret-ref", "github-flux-auth",
                ]
            )
        else:
            self.log(log_prefix, colored(
                "Github repo is public. Will not use github-flux-auth secret or username/password", "yellow"))

        code, out, err = self.run_process(cmd, log_prefix=log_prefix)

        self.log(log_prefix, colored(
            f"Writting flux source to {self.source_path}", "yellow", attrs=["bold"]))
        with open(str(self.source_path), "w") as f:
            f.write(out)

    def install_flux(self, log_prefix: str | None = None, **kwargs):
        code, out, err = self.run_process(["flux", "install", "--export",
                                           f"{self.flux_path}"], log_prefix=log_prefix)
        self.log(log_prefix, f"Writing Flux CRDs to {self.flux_path}")
        with open(str(self.flux_path), "w") as f:
            f.write(out)
        self.log(log_prefix, colored(
            f"Flux installed, please check {self.flux_path} for any errors", "green", attrs=["bold"]))
        self.log(log_prefix, colored(
            f"Executing `kubectl apply -f {self.flux_path} to install flux", "green", attrs=["bold"]))
        try:
            utils.create_from_yaml(self.api_client, str(
                self.flux_path), namespace="flux-system")
        except utils.FailToCreateError as e:
            self.log_k8s_api_error(log_prefix, e)

    def install_apps(self, log_prefix: str | None = None, **kwargs):
        self.log(log_prefix, colored(
            f"Setting up GitReposority/flux-system from {self.source_path}", "green", attrs=["bold"]))
        self.run_process(
            ["kubectl", "apply", "-f", str(self.source_path)], log_prefix=log_prefix)

        self.log(log_prefix, colored(
            f"Setting up Infrastructure from {self.infra_path}", "green", attrs=["bold"]))
        self.run_process(
            ["kubectl", "apply", "-f", str(self.infra_path)], log_prefix=log_prefix)

        self.log(log_prefix,
                 colored(f"Setting up Apps from {self.apps_path}", "green", attrs=["bold"]))
        self.run_process(
            ["kubectl", "apply", "-f", str(self.apps_path)], log_prefix=log_prefix)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cluster configuration")
    parser.add_argument("--kube-config", type=str,
                        help="Path to kubeconfig file")
    parser.add_argument(
        "--force-age-secret",
        action="store_true",
        help="Force the creation of the age secret",
    )
    parser.add_argument(
        "--gh-user", type=str, help="Github user with acccess to this repo"
    )
    parser.add_argument(
        "--gh-password",
        type=str,
        help="Github password for the user with acccess to this repo",
    )
    parser.add_argument(
        '--force-github-secret', action='store_true', help='Force the creation of the github secret'
    )
    parser.add_argument(
        '--cluster-name', type=str, help='Name of the cluster. {dev, staging, production}'
    )
    parser.add_argument(
        '--gh-repo', type=str, default="https://github.com/maany/flux-play", help='URL of the github repo containing flux values'
    )
    args = parser.parse_args()
    print(args)
    with run(
        "kubectl",
        "proxy",
        "--port=8080",
        env={"KUBECONFIG": args.kube_config, "PATH": os.environ["PATH"]},
    ) as proc:
        print("Kubectl proxy started")
        print("Waiting for kubectl proxy to start")
        while True:
            try:
                kubeconfig = Configuration()
                kubeconfig.host = "http://127.0.0.1:8080"
                api_client = ApiClient(configuration=kubeconfig)
                kubectl = client.CoreV1Api(api_client=api_client)
                kubectl.list_node()
                print("Kubectl proxy is ready")
                break
            except Exception as e:
                print("Kubectl proxy is not ready yet")
                pass

        cluster_config = ClusterConfiguration(
            force_age_secret=args.force_age_secret,
            gh_user=args.gh_user,
            gh_password=args.gh_password,
            force_github_secret=args.force_github_secret,
        )
        cluster_config.run()

        flux_config = FluxConfiguration(
            force_age_secret=args.force_age_secret,
            gh_user=args.gh_user,
            gh_password=args.gh_password,
            force_github_secret=args.force_github_secret,
            kube_config=args.kube_config,
            gh_repo=args.gh_repo,
            cluster_name=args.cluster_name
        )
        flux_config.run()

        proc.terminate()
        proc.kill()
