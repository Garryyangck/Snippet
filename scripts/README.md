> 这是虚拟机一些常见环境配置的脚本

# Ubuntu

## 创建新虚拟机后的基础环境配置

### init_vm.sh

```bash
#!/bin/sh

echo 'Step 1: 安装常用软件包'
sudo apt-get update
sudo apt-get install -y vim git curl wget zsh ufw net-tools openssh-server build-essential tree openvpn htop iotop iftop nethogs

echo 'Step 2: 启动ssh服务，以便远程连接'
sudo systemctl start ssh
sudo systemctl enable ssh

echo 'Step 3: 启动防火墙，并开放22端口以供远程连接'
sudo ufw enable
sudo ufw allow ssh
sudo ufw reload

echo 'Step 4: 安装oh-my-zsh'
sh -c "$(wget https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
```

### init_oh_my_zsh.sh

> 注意：这里用到了 source 命令，这是 bash 的特有命令，shell 没有，因此启动需要使用 `bash ./init_oh_my_zsh.sh`。
>
> 如果安装了 oh-my-zsh，则使用 `zsh ./init_oh_my_zsh.sh`。
>
> 最后可能还是没有成功执行 `source ~/.zshrc`，那就手动执行一下吧！

```bash
#!/bin/bash

echo 'Step 1: 使用agnoster主题'
# 使用sed命令替换.zshrc文件中的ZSH_THEME配置
sed -i "s/^ZSH_THEME=.*/ZSH_THEME='agnoster'/" ~/.zshrc
source ~/.zshrc

echo 'Step 2: 安装语法高亮和提示插件'
git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions || git clone https://gitee.com/hailin_cool/zsh-autosuggestions.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting ||git clone https://gitee.com/Annihilater/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
sed -i "s/^plugins=.*/plugins=(git zsh-autosuggestions z zsh-syntax-highlighting)/" ~/.zshrc
source ~/.zshrc
```

### docker_install.sh

```bash
#!/bin/sh

echo 'Step 1: 移除之前docker版本并更新更新 apt 包索引'
sudo apt-get remove docker docker-engine docker.io
sudo apt-get update

echo 'Step 2: 安装 apt 依赖包，用于通过HTTPS来获取仓库'
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common

ehoc 'Step 3: 添加 Docker 的官方 GPG 密钥'
curl -fsSL https://mirrors.aliyun.com/docker-ce/linux/ubuntu/gpg | sudo apt-key add -

echo 'Step 4: 设置docker稳定版仓库，这里使用了阿里云仓库'
sudo add-apt-repository "deb [arch=amd64] https://mirrors.aliyun.com/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update

echo 'Step 5: 安装免费的docker Community版本docker-ce'
sudo apt-get install -y docker-ce
# sudo apt-get install -y docker-ce=<VERSION> #该命令可以选择docker-ce版本

echo 'Step 6: 将用户添加到docker组'
sudo usermod -aG docker $USER

echo 'Step 7: 查看docker版本及运行状态'
sudo docker -v
sudo systemctl status docker

echo 'Step 8: 本步非必需。使用阿里云设置Docker镜像加速，注意下面链接请使用阿里云给自己的URL'
sudo mkdir -p /etc/docker
sudo tee /etc/docker/daemon.json <<-'EOF'
{  "registry-mirrors": ["https://ua3456xxx.mirror.aliyuncs.com"] }
EOF
sudo systemctl daemon-reload
sudo systemctl restart docker
```

### docker_compose_install

```bash
#!/bin/sh

echo 'Step 1: 安装最新稳定的 Docker Compose 文件'
sudo curl -L "https://github.com/docker/compose/releases/download/v2.6.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

echo 'Step 2: 赋予二进制文件docker-compose可执行权限'
sudo chmod +x /usr/local/bin/docker-compose
docker-compose version
```

