# Step 2

## Changelogs 

- `route/route.go`: go code to implement and test `ip rule add` for multi-homed network 
- :exclamation: Motify an existing module `vendor/github.com/containernetworking/plugins/pkg/ipam/ipam_linux.go` to add routing rule. 
- Add table and priority to `conf/10-multi-bridge-cni.conf.j2` for routing rule 
  ```
  {
    "bridge": "cni0", 
      "isManagementNetwork": true,
      "isDefaultGateway": true,
      "forceAddress": false,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
  {% for node in nodeinfo %}
  {% if node.name == ansible_hostname %}
        "subnet": "{{ node.podcidr[0] }}"
  {% endif %}
  {% endfor %}
      }, 
      "table": 0, 
      "priority": 100
  },
  ```
  Table 0 stands for `local` table and the CLI is designed to create rules for tables other than this one.

## Demo

  For example: 
  ```
  ➜ kubectl exec -it netshoot1 -- ip route 
  default via 10.240.0.1 dev eth0 
  10.240.0.0/24 dev eth0 proto kernel scope link src 10.240.0.4 
  10.240.10.0/24 dev net1 proto kernel scope link src 10.240.10.2 
  10.240.20.0/24 dev net2 proto kernel scope link src 10.240.20.2

  ➜ kubectl exec -it netshoot1 -- ip route show table 1
  default via 10.240.10.1 dev net1 

  ➜ kubectl exec -it netshoot1 -- ip route show table 2
  default via 10.240.20.1 dev net2 
  ```

  ```
  ➜ kubectl exec -it netshoot1 -- ip rule  
  0:  from all lookup local
  101:  from 10.240.10.2 lookup 1
  102:  from 10.240.20.2 lookup 2
  32766:  from all lookup main
  32767:  from all lookup default
  ```

  Every interfaces are connected to other nodes in a cluster.
  ```
  root@cni-worker01:~# ping -c 1 10.240.0.4
  PING 10.240.0.4 (10.240.0.4) 56(84) bytes of data.
  64 bytes from 10.240.0.4: icmp_seq=1 ttl=63 time=0.267 ms

  --- 10.240.0.4 ping statistics ---
  1 packets transmitted, 1 received, 0% packet loss, time 0ms
  rtt min/avg/max/mdev = 0.267/0.267/0.267/0.000 ms


  root@cni-worker01:~# ping -c 1 10.240.10.2
  PING 10.240.10.2 (10.240.10.2) 56(84) bytes of data.
  64 bytes from 10.240.10.2: icmp_seq=1 ttl=63 time=0.292 ms

  --- 10.240.10.2 ping statistics ---
  1 packets transmitted, 1 received, 0% packet loss, time 0ms
  rtt min/avg/max/mdev = 0.292/0.292/0.292/0.000 ms


  root@cni-worker01:~# ping -c 1 10.240.20.2
  PING 10.240.20.2 (10.240.20.2) 56(84) bytes of data.
  64 bytes from 10.240.20.2: icmp_seq=1 ttl=63 time=0.634 ms

  --- 10.240.20.2 ping statistics ---
  1 packets transmitted, 1 received, 0% packet loss, time 0ms
  rtt min/avg/max/mdev = 0.634/0.634/0.634/0.000 ms
  ```

  Pods are connected to outside world :earth_asia:
  ```
  ➜ kubectl exec -it netshoot1 -- ping -c 1 8.8.8.8        
  PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
  64 bytes from 8.8.8.8: icmp_seq=1 ttl=127 time=39.2 ms

  --- 8.8.8.8 ping statistics ---
  1 packets transmitted, 1 received, 0% packet loss, time 0ms
  rtt min/avg/max/mdev = 39.174/39.174/39.174/0.000 ms
  ```

## Deployment 

### Build CNI binary 

```
go build -o bin/multi-bridge 
```

### Deploy CNI using ansible 

```
ansible-playbook deploy.yaml 
```


## Working Progress 

- Multiple `bridge` plugins can be worked together 
- Static routed pod network defined `ansible` 

For example, if you want to add additional veth `net1` connected to bridge `cni1`, set annotations as follows:
```  
  annotations: 
    multi-bridge.cni.kubernetes.io/dev: "net1"
```

## Limitations 

- This CNI relies strongly on `ansible`, especially because of routing. But officially (in my opinion), we use `DaemonSet` to deploy CNI in `Pod` type.

## Next Step 

- Let's deploy multi-bridge CNI using `DaemonSet`!
