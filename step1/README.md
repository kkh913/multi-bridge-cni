# Step 1

## Deployment 

### Build CNI binary 

go build -o bin/multi-bridge 

### Deploy CNI using ansible 

ansible-playbook deploy.yaml 

## Working Progress 

- Multiple `bridge` plugins can be worked together 
- Static routed pod network defined `ansible` 

For example, if you want to add additional veth `net1` connected to bridge `cni1`, set annotations as follows:
```  
  annotations: 
    multi-bridge.cni.kubernetes.io/dev: "net1"
```

## Limitations 

- Only veth `eth0` connected to `cni0` can be routed to outside world. Due to routing problems - multi-homed which means multiple gateways, others can receive packets, but cannot send packets to appropriate gateway. 

## Next Step 

- Modify `host-local` IPAM source code to support 'multi-homed' pods! 
