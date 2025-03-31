#!/bin/bash

# Detectar a interface de rede ativa (ignora loopback)
iface=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -n 1)

# Verifica se encontrou uma interface
if [[ -z "$iface" ]]; then
  echo "❌ Nenhuma interface de rede encontrada. Abortando."
  exit 1
fi

echo "🔍 Interface detectada: $iface"

# Backup dos arquivos Netplan existentes
sudo mkdir -p ~/netplan-backup
sudo cp /etc/netplan/*.yaml ~/netplan-backup/

# Criar novo arquivo temporário com DHCP
tmpfile=$(mktemp)
cat <<EOF > "$tmpfile"
network:
  version: 2
  ethernets:
    $iface:
      dhcp4: true
EOF

echo "🧪 Testando nova configuração..."
# Testa a configuração antes de aplicar
if sudo netplan try --config-file="$tmpfile"; then
  echo "✅ Teste OK! Aplicando nova configuração..."
  sudo cp "$tmpfile" /etc/netplan/01-default-config.yaml
  sudo netplan apply
  echo "🎉 Netplan resetado com sucesso. IP atual:"
  ip a show "$iface"
else
  echo "❌ Erro no teste. A configuração não foi aplicada. Nada foi alterado."
fi

# Limpa o temporário
rm -f "$tmpfile"
