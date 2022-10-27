import argparse
import os
import time

from kubernetes import client
from kubernetes.client import Configuration, ApiClient
from termcolor import colored

from core.run_context import run
from core.base_configuration import BaseConfiguration


class DevClusterConfiguration(BaseConfiguration):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.kubeconfig = kwargs.get("kube_config")

        self.steps = [
            self.check_config,
            self.restart_coredns_pods,
            self.restart_metrics_server,
        ]

    def check_config(self, log_prefix: str | None = None, **kwargs):
        if self.kubeconfig is None:
            self.log(self.__class__.__name__, colored(
                "No kubeconfig provided", "red", attrs=["bold", "blink"]))
            raise ValueError(
                "No kubeconfig provided. Please provide a kubeconfig using the --kube-config flag")
        self.env = {"KUBECONFIG": self.kubeconfig, "PATH": os.environ["PATH"]}


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
        self.log(log_prefix, colored("Sleeping for 20s", "yellow"))
        time.sleep(20)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Vagrant Cluster post boot configuration")
    parser.add_argument("--kube-config", type=str,
                        help="Path to kubeconfig file")

    args = parser.parse_args()

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
            

        dev_cluster_config = DevClusterConfiguration(
            kube_config = args.kube_config,
        )
        dev_cluster_config.run()

        proc.terminate()
        proc.kill()