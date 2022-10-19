import argparse
import typing
import subprocess
import sys
import io
import os
import json
import base64
import pathlib
from enum import Enum
from contextlib import contextmanager

from kubernetes import client, config, watch
from kubernetes.client import Configuration, ApiClient
from pyrage import x25519
from termcolor import colored


AGE_PUBLIC_KEY_FILE = (pathlib.Path(__file__).parent.parent / "age.pubkey").resolve()

class ClusterType(Enum):
    """_summary_ The cluster type

    Args:
        Enum (_type_): _description_
    """

    DEV = "dev"
    PROD = "production"
    STAGING = "staging"


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
    try:
        proc = subprocess.Popen(args, **kwargs)
        yield proc
    finally:
        proc.terminate()
        proc.kill()

    if return_stdout:
        return proc.stdout


class ClusterConfiguration:
    def __init__(self, **kwargs) -> None:
        self.kwargs = kwargs
        kubeconfig = Configuration()
        kubeconfig.host = "http://127.0.0.1:8080"
        self.api_client = ApiClient(configuration=kubeconfig)
        self.v1 = client.CoreV1Api(api_client=api_client)

        self.steps = [
            self.create_flux_system_namespace,
            self.setup_age_secret,
            # self.generate_flux_config,
            # self.install_flux
        ]

    def run(self):
        total_steps = len(self.steps)
        for idx, step in enumerate(self.steps):
            log_prefix = "[{}/{}]: {} : ".format(idx + 1, total_steps, step.__name__)
            print(colored(log_prefix + "Starting", "magenta", attrs=["bold"]))
            step(log_prefix, **self.kwargs)

    def log(self, log_prefix: str, *message):
        print(log_prefix, *message)

    def create_flux_system_namespace(self, log_prefix: str | None = None, **kwargs):
        all_namespaces = self.v1.list_namespace()
        if "flux-system" in [ns.metadata.name for ns in all_namespaces.items]:
            self.log(log_prefix, colored("flux-system namespace already exists", "yellow"))
            return
        self.log(log_prefix, "Creating flux-system namespace")
        self.v1.create_namespace(body={"metadata": {"name": "flux-system"}})

    def setup_age_secret(self, log_prefix: str | None = None, **kwargs):
        # get the current secrets
        current_secrets = self.v1.list_namespaced_secret(namespace="flux-system")
        # check if the secret already exists
        if "sops-age" in [secret.metadata.name for secret in current_secrets.items]:
            if not kwargs.get("force_age_secret", False):
                self.log(log_prefix, colored("Age secret already exists, skipping", "blue"))
                return
            self.log(
                log_prefix,
                colored("Age secret already exists, but force_age_secret is set to True, recreating", "yellow"),
            )
            self.log(log_prefix, colored("Deleting existing age secret", "red"))
            self.v1.delete_namespaced_secret(name="sops-age", namespace="flux-system")
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
            self.log(log_prefix, f"Writing age public key to", colored(AGE_PUBLIC_KEY_FILE, "green", attrs=["bold"]))
            f.write(self.age_pubkey)

    def generate_flux_config(self, log_prefix: str | None = None, **kwargs):
        pass

    def install_flux(self, log_prefix: str | None = None, **kwargs):
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cluster configuration")
    parser.add_argument("--kube-config", type=str, help="Path to kubeconfig file")
    parser.add_argument(
        "--force-age-secret",
        action="store_true",
        help="Force the creation of the age secret",
    )
    parser.add_argument(
        "--gh_user", type=str, help="Github user with acccess to this repo"
    )
    parser.add_argument(
        "--gh_password",
        type=str,
        help="Github password for the user with acccess to this repo",
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
        )
        cluster_config.run()

        # proc.wait()
