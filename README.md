# Configuring a kubernetes cluster
Assuming you have access to the kubernetes cluster, perform the following steps to configure it to run the app
This guide assumes you are setting up the dev cluster (./cluster/dev)
## Automatic Configuration
Please ensure you have installed the following CLI tools:
1. kubectl

```
cd scripts
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```


## Manual Coniguration

## Generating an AGE Keypair

**NOTE**: One shall generate a new key for every cluster

```
$ brew install age
$ age-keygen -o age.agekey
Public key: age18pt75u7vsm57d4hw3hkjk020fp2la09vh59mjjtdczw5tes7s3ls44vqlj
```
Create a secret with the age private key, the key name must end with .agekey to be detected as an age key:

```
cat age.agekey |
kubectl create secret generic sops-age \
--namespace=flux-system \
--from-file=age.agekey=/dev/stdin
```

## Configuring Flux to use SOPS decry
## Adding Secrets

Create the unencrypted kubernetes secret by starting with a new empty file, and put the following boilerplate:
```
apiVersion: v1
kind: Secret
metadata:
    name: my-secret
    namespace: rucio
type: Opaque
stringData:
    my-secret: |
       this is the secret
       mult-line data
       that will be encrypted
```

From the example above it should be obvious where the secret content goes. Make sure that you indent it correctly!
Then encrypt it with the following command:

```
sops --encrypt \
  --in-place\
  --age=age18pt75u7vsm57d4hw3hkjk020fp2la09vh59mjjtdczw5tes7s3ls44vqlj \
  --encrypted-regex '^(data|stringData)$' \
  secret.yaml

```