# Setting up enclave-enabled EC2 host

1. Go to `Launch an Instance` in the EC2 console
2. Select `Amazon Linux 2 AMI (HVM) - Kernel 5.10, SSD Volume Type` under AMI (Most recent Linux distros are supported but installing the tools is easier on Amazon Linux 2023 and Amazon Linux 2)
3. Select `m5a.xlarge` under Instance Type. Complete list of instances which have Nitro Support can be found [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html#ec2-nitro-instances)
4. Select Key pair, Network Settings and Storage as usual
5. Under `Advanced Details`, for Nitro Enclave option select `Enable`
6. Start the instance

## Notes

1. A Nitro Enclave requires a minimum of 2 vCPUs and a host can have at most 4 Enclaves, more information [here](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
2. The host must always have at least 2 vCPUs, so the host machine must have at least 4 vCPUs to support 1 Enclave.


# Installing dependencies 

1. Install Docker
```bash
sudo yum -y install docker
sudo usermod -a -G docker ec2-user
sudo systemctl enable docker.service
sudo systemctl start docker.service
```

2. Install Nitro CLI
```bash
sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
sudo yum install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne ec2-user
nitro-cli --version
sudo systemctl start nitro-enclaves-allocator.service
sudo systemctl enable nitro-enclaves-allocator.service

```

3. Install Go
```bash
sudo yum -y install golang
```

For next steps go [here](/usage.md)
