#!/bin/bash

# Script de configuração automática para servidor Ubuntu com OpenVPN
# Criado em: $(date)

# Verificar se está sendo executado como root
if [ "$EUID" -ne 0 ]; then
  echo "Este script precisa ser executado como root."
  echo "Por favor, execute-o novamente com 'sudo'."
  exit 1
fi

# Definir variáveis 
USERNAME="enzo.ceravolo"
PASSWORD="SenhaSegura123"  # Altere para uma senha forte
SERVER_IP="192.168.1.100"  # IP fixo para o servidor
GATEWAY="192.168.1.1"      # Gateway da rede
INTERFACE=$(ip -o -4 route show to default | awk '{print $5}' | head -1)
SSH_PORT="22"              # Porta SSH
VPN_PORT="1194"            # Porta OpenVPN
VPN_PROTO="udp"            # Protocolo OpenVPN
VPN_NETWORK="10.8.0.0"     # Rede VPN
VPN_NETMASK="255.255.255.0"  # Máscara de rede VPN
CLIENT_NAME="cliente1"     # Nome do primeiro cliente VPN

# Cores para melhor visualização
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Função para exibir progresso
progress() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Função para exibir sucesso
success() {
    echo -e "${GREEN}[SUCESSO]${NC} $1"
}

# Função para exibir erro
error() {
    echo -e "${RED}[ERRO]${NC} $1"
    exit 1
}

# Função para verificar se um pacote está instalado
is_package_installed() {
    dpkg -s "$1" &> /dev/null
    return $?
}

# Atualizar o sistema
update_system() {
    progress "Atualizando sistema..."
    apt update && apt upgrade -y || error "Falha ao atualizar o sistema!"
    success "Sistema atualizado com sucesso!"
}

# Criar usuário
create_user() {
    progress "Criando usuário $USERNAME..."
    if id "$USERNAME" &>/dev/null; then
        progress "Usuário $USERNAME já existe."
    else
        useradd -m -s /bin/bash "$USERNAME" || error "Falha ao criar usuário!"
        echo "$USERNAME:$PASSWORD" | chpasswd || error "Falha ao definir senha!"
        usermod -aG sudo "$USERNAME" || error "Falha ao adicionar ao grupo sudo!"
        success "Usuário $USERNAME criado com sucesso!"
    fi
}

# Configurar IP fixo
configure_static_ip() {
    progress "Configurando IP fixo ($SERVER_IP)..."
    
    # Criar arquivo de configuração Netplan
    cat > /etc/netplan/01-netcfg.yaml <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $INTERFACE:
      dhcp4: no
      addresses: [$SERVER_IP/24]
      gateway4: $GATEWAY
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
EOF
    
    # Aplicar configurações
    netplan apply || error "Falha ao aplicar configuração de rede!"
    success "IP fixo configurado com sucesso!"
}

# Configurar SSH
configure_ssh() {
    progress "Configurando SSH..."
    apt install -y openssh-server || error "Falha ao instalar SSH!"
    
    # Backup do arquivo original
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    
    # Configurar SSH com segurança
    sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
    sed -i "s/#PermitRootLogin prohibit-password/PermitRootLogin no/" /etc/ssh/sshd_config
    sed -i "s/#PasswordAuthentication yes/PasswordAuthentication yes/" /etc/ssh/sshd_config
    sed -i "s/X11Forwarding yes/X11Forwarding no/" /etc/ssh/sshd_config
    
    # Adicionar configurações de segurança adicionais
    echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
    
    # Habilitar e reiniciar serviço SSH
    systemctl enable ssh
    systemctl restart ssh || error "Falha ao reiniciar serviço SSH!"
    
    success "SSH configurado com sucesso na porta $SSH_PORT!"
}

# Configurar Firewall
configure_firewall() {
    progress "Configurando Firewall (UFW)..."
    apt install -y ufw || error "Falha ao instalar UFW!"
    
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow $SSH_PORT/tcp
    ufw allow $VPN_PORT/$VPN_PROTO
    
    # Habilitar UFW sem prompt
    echo "y" | ufw enable
    
    success "Firewall configurado com sucesso!"
}

# Configurar sistema para ficar sempre ligado
configure_always_on() {
    progress "Configurando sistema para ficar sempre ligado..."
    
    # Desativar suspensão e hibernação
    systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
    
    # Configurar comportamento após queda de energia
    apt install -y sysfsutils || error "Falha ao instalar sysfsutils!"
    echo "devices/system/cpu/cpufreq/policy*/energy_performance_preference = performance" >> /etc/sysfs.conf
    
    # Configurar reinicialização automática após kernel panic
    echo "kernel.panic = 10" >> /etc/sysctl.conf
    echo "kernel.panic_on_oops = 1" >> /etc/sysctl.conf
    sysctl -p
    
    success "Configuração para ficar sempre ligado concluída!"
}

# Instalar OpenVPN
install_openvpn() {
    progress "Instalando OpenVPN e Easy-RSA..."
    apt install -y openvpn easy-rsa || error "Falha ao instalar OpenVPN!"
    success "OpenVPN instalado com sucesso!"
}

# Configurar Autoridade Certificadora (CA)
configure_ca() {
    progress "Configurando Autoridade Certificadora..."
    
    # Criar diretório e copiar arquivos Easy-RSA
    mkdir -p /home/$USERNAME/openvpn-ca
    cp -r /usr/share/easy-rsa/* /home/$USERNAME/openvpn-ca/
    
    # Editar o arquivo vars
    cd /home/$USERNAME/openvpn-ca
    cat > vars <<EOF
export EASY_RSA="\$(pwd)"
export OPENSSL="openssl"
export PKCS11TOOL="pkcs11-tool"
export GREP="grep"
export KEY_CONFIG="\$(pwd)/openssl-1.0.0.cnf"
export KEY_DIR="\$(pwd)/keys"
export PKCS11_MODULE_PATH="dummy"
export PKCS11_PIN="dummy"
export KEY_SIZE=2048
export CA_EXPIRE=3650
export KEY_EXPIRE=3650
export KEY_COUNTRY="BR"
export KEY_PROVINCE="SP"
export KEY_CITY="SaoPaulo"
export KEY_ORG="Servidor-VPN"
export KEY_EMAIL="admin@example.com"
export KEY_OU="VPN"
export KEY_NAME="servidor_vpn"
EOF
    
    # Ajustar permissões
    chown -R $USERNAME:$USERNAME /home/$USERNAME/openvpn-ca
    
    success "Autoridade Certificadora configurada com sucesso!"
}

# Gerar certificados e chaves
generate_keys() {
    progress "Gerando certificados e chaves..."
    
    cd /home/$USERNAME/openvpn-ca
    
    # Inicializar a PKI
    source vars
    ./clean-all
    
    # Gerar CA (responder automaticamente às perguntas)
    echo -e "\n\n\n\n\n\n\n" | ./build-ca
    
    # Gerar certificado e chave do servidor (responder automaticamente às perguntas)
    echo -e "\n\n\n\n\n\n\n\n\n\n" | ./build-key-server servidor_vpn
    
    # Gerar parâmetros Diffie-Hellman
    ./build-dh
    
    # Gerar chave TLS Auth
    openvpn --genkey --secret keys/ta.key
    
    # Gerar certificado e chave do cliente (responder automaticamente às perguntas)
    echo -e "\n\n\n\n\n\n\n\n\n\n" | ./build-key $CLIENT_NAME
    
    success "Certificados e chaves gerados com sucesso!"
}

# Configurar servidor OpenVPN
configure_openvpn_server() {
    progress "Configurando servidor OpenVPN..."
    
    # Copiar arquivos para o diretório do OpenVPN
    cd /home/$USERNAME/openvpn-ca
    cp keys/{servidor_vpn.crt,servidor_vpn.key,ca.crt,dh*.pem,ta.key} /etc/openvpn/
    
    # Criar arquivo de configuração do servidor
    cat > /etc/openvpn/server.conf <<EOF
port $VPN_PORT
proto $VPN_PROTO
dev tun
ca ca.crt
cert servidor_vpn.crt
key servidor_vpn.key
dh dh2048.pem
server $VPN_NETWORK $VPN_NETMASK
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF
    
    # Habilitar encaminhamento de IP
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    
    # Configurar NAT
    iptables -t nat -A POSTROUTING -s $VPN_NETWORK/$VPN_NETMASK -o $INTERFACE -j MASQUERADE
    
    # Salvar regras do iptables
    apt install -y iptables-persistent || error "Falha ao instalar iptables-persistent!"
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    netfilter-persistent save
    
    # Habilitar e iniciar o serviço OpenVPN
    systemctl enable openvpn@server
    systemctl start openvpn@server || error "Falha ao iniciar o serviço OpenVPN!"
    
    success "Servidor OpenVPN configurado com sucesso!"
}

# Criar arquivo de configuração do cliente
create_client_config() {
    progress "Criando configuração do cliente..."
    
    # Criar diretório para armazenar arquivos de cliente
    mkdir -p /home/$USERNAME/client-configs/files
    chmod 700 /home/$USERNAME/client-configs/files
    
    # Diretório base para os certificados
    KEY_DIR=/home/$USERNAME/openvpn-ca/keys
    OUTPUT_DIR=/home/$USERNAME/client-configs/files
    BASE_CONFIG=/home/$USERNAME/client-configs/base.conf
    
    # Criar arquivo de configuração base
    mkdir -p /home/$USERNAME/client-configs
    cat > "$BASE_CONFIG" <<EOF
client
dev tun
proto $VPN_PROTO
remote $SERVER_IP $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
auth SHA256
key-direction 1
verb 3
EOF
    
    # Criar arquivo de configuração completo do cliente
    cat > "$OUTPUT_DIR/$CLIENT_NAME.ovpn" <<EOF
$(cat "$BASE_CONFIG")
<ca>
$(cat "$KEY_DIR/ca.crt")
</ca>
<cert>
$(cat "$KEY_DIR/$CLIENT_NAME.crt")
</cert>
<key>
$(cat "$KEY_DIR/$CLIENT_NAME.key")
</key>
<tls-auth>
$(cat "$KEY_DIR/ta.key")
</tls-auth>
EOF
    
    # Ajustar permissões
    chown -R $USERNAME:$USERNAME /home/$USERNAME/client-configs
    
    success "Configuração do cliente criada com sucesso: $OUTPUT_DIR/$CLIENT_NAME.ovpn"
    echo "Salve este arquivo para conectar-se à VPN a partir do seu PC pessoal."
}

# Configurar atualizações automáticas
configure_auto_updates() {
    progress "Configurando atualizações automáticas..."
    
    apt install -y unattended-upgrades || error "Falha ao instalar unattended-upgrades!"
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades
    
    # Configurar atualizações automáticas
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    success "Atualizações automáticas configuradas com sucesso!"
}

# Configurar monitoramento de disponibilidade
configure_monitoring() {
    progress "Configurando monitoramento de disponibilidade..."
    
    apt install -y monit || error "Falha ao instalar monit!"
    
    # Criar configuração para monitorar OpenVPN
    cat > /etc/monit/conf.d/openvpn <<EOF
check process openvpn with pidfile /var/run/openvpn/server.pid
    start program = "/usr/bin/systemctl start openvpn@server"
    stop program = "/usr/bin/systemctl stop openvpn@server"
    if failed host 127.0.0.1 port $VPN_PORT type $VPN_PROTO then restart
    if 5 restarts within 5 cycles then timeout
EOF
    
    # Configuração principal
    cat > /etc/monit/monitrc <<EOF
set daemon 60
set logfile /var/log/monit.log
set idfile /var/lib/monit/id
set statefile /var/lib/monit/state
set eventqueue
    basedir /var/lib/monit/events
    slots 100
set httpd port 2812 and
    use address localhost
    allow localhost

include /etc/monit/conf.d/*
include /etc/monit/conf-enabled/*
EOF
    
    chmod 700 /etc/monit/monitrc
    
    # Habilitar e iniciar monit
    systemctl enable monit
    systemctl restart monit || error "Falha ao reiniciar o serviço monit!"
    
    success "Monitoramento de disponibilidade configurado com sucesso!"
}

# Executar todas as funções
main() {
    clear
    echo "=============================================="
    echo "     CONFIGURAÇÃO AUTOMÁTICA DO SERVIDOR     "
    echo "=============================================="
    echo ""
    echo "Este script irá configurar:"
    echo "- Atualização do sistema"
    echo "- Criação do usuário: $USERNAME"
    echo "- IP fixo: $SERVER_IP"
    echo "- SSH na porta: $SSH_PORT"
    echo "- OpenVPN na porta: $VPN_PORT/$VPN_PROTO"
    echo "- Configurações para o servidor ficar sempre ligado"
    echo "- Atualizações automáticas de segurança"
    echo "- Monitoramento de disponibilidade"
    echo ""
    echo "=============================================="
    
    # Confirmar execução
    read -p "Deseja continuar? (s/n): " confirm
    if [[ $confirm != "s" && $confirm != "S" ]]; then
        echo "Operação cancelada pelo usuário."
        exit 0
    fi
    
    # Executar etapas
    update_system
    create_user
    configure_static_ip
    configure_ssh
    configure_firewall
    configure_always_on
    install_openvpn
    configure_ca
    generate_keys
    configure_openvpn_server
    create_client_config
    configure_auto_updates
    configure_monitoring
    
    echo ""
    echo "=============================================="
    echo "     CONFIGURAÇÃO CONCLUÍDA COM SUCESSO!     "
    echo "=============================================="
    echo ""
    echo "Informações importantes:"
    echo "- Usuário criado: $USERNAME"
    echo "- IP do servidor: $SERVER_IP"
    echo "- Porta SSH: $SSH_PORT"
    echo "- Arquivo de configuração do cliente VPN:"
    echo "  /home/$USERNAME/client-configs/files/$CLIENT_NAME.ovpn"
    echo ""
    echo "Você deve copiar o arquivo de configuração do cliente"
    echo "para o seu PC pessoal para se conectar à VPN."
    echo ""
    echo "É recomendado reiniciar o servidor para aplicar todas as configurações."
    read -p "Deseja reiniciar agora? (s/n): " reboot_confirm
    if [[ $reboot_confirm == "s" || $reboot_confirm == "S" ]]; then
        reboot
    fi
}

# Iniciar script
main
