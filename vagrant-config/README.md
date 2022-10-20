## Setup a k8s cluster on Oracle VirtualBox

Install [Oracle Virtualbox](https://linuxhint.com/install-setup-virtualbox-ubuntu-22-04/)

Install [vagrant](https://www.vagrantup.com/downloads)

Then, verify the resource requests ( CPU, Memory ) for the kubernetes master and workers in Vagrantfile

If you add a new worker, then add its IP address in the `/etc/hosts` config section of `bootstrap.sh`

Once ready execute

```
vagrant up
```

If you get errors related to host-only network for VirtualBox, add a `/etc/vbox/networks.conf` file

```
maany@beast:~/Projects/pqer/flux-play/vagrant-config$ cat /etc/vbox/networks.conf 
* 10.0.0.0/8 172.16.16.0/24 192.168.0.0/16
* 2001::/64
```

After the nodes are up, copy the kubeconfig
```
scp root@172.16.16.100:/etc/kubernetes/admin.conf ./config
```
