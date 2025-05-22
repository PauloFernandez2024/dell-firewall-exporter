# magalucloud-firewall-exporter
Firewall Exporter é uma ferramenta que permite extrair importantes métricas de redes e sistemas, utilizando ferramentas nativas do Linux, e converte-las para um formato reconhecido pelo Prometheus. A opção de criação de um exporter específico, ao invés da utilização de scripts e do promtool (Prometheus) como validador, se deve ao fato de um exporter customizado permitir a coleta e a exposição destas métricas en tempo real, seguindo modelo **pull** usado pelo Prometheus.

Na construção do exporter foram criados módulos específicos, para o tratamento de áreas ou de subsystems com características e métricas próprias.

a. Métricas de Rede
Módulo responsável pela captura de dados das interfaces de rede físicas e lógicas, através de ferramentas nativas como o **ethtool** ou através de acesso aos diretórios, como **/sys/class/net**, pertencentes à interface de sysfs.

Particularmente neste módulo, as métricas de rede estão sendo agrupadas em categorias como load, fails, buffers, security e cpu, levando em conta as características das interfaces presentes. Este agrupamento é importante para escalabilidade, diagnóstico eficiente e organização lógica das métricas. Seguem abaixo, alguns exemplos práticos:
```
     - Facilidade de navegação e análise por tipo de comportamento
            Categoria	Representa
            load	Carga de tráfego (bytes, pacotes) recebida ou transmitida
            fails	Erros e descartes que indicam falhas
            buffers	Estados e falhas de alocação/uso de buffers
            security	Métricas associadas a criptografia, TLS, offloads
            cpu	        Uso da CPU por offloads, checagem de somas (checksums), etc.
```

```
        Exemplo prático:
            Se o tráfego (load) está normal, mas os erros (fails) estão altos, possivelmente há problemaa de interface.
            Se buffers estão se esgotando com sintomas de ring full, serão encontrado valores significativos como queda de pacotes.
```

```
      - Escalabilidade com Prometheus e Grafana
            . Dashboards modulares por categoria (ex: painel só de fails)
            . Alertas por área (ex: alerta de buffer overflow, alerta de TLS drop)
            . Queries agrupadas, utilizando promql, como: "sum by (interface) (net_fails_rx_errors)"
```

```
      - Manutenção e extensão mais fáceis
            . Quando adicionada uma nova métrica como: "tls_drop_bypass_req", saberemos que petence "net_security_tx" ou "pp_alloc_slow" em "net_buffers_rx"
```

```
      - Uso de prefixos mais semânticos e evita confusão com nomes genéricos como "rx_errors" ou "tx_dropped".
            Nome	                Significado claro
            net_load_rx_bytes	        Tráfego recebido
            net_fails_tx_err	        Erros de transmissão
            net_buffers_rx_alloc_fail	Falha ao alocar buffer de recepção
            net_security_rx_tls_err	Erros de descriptografia TLS na recepção
```

```
      - Compatibilidade com múltiplos drivers/dispositivos
            Em ambientes com drivers diferentes (Intel, Mellanox, etc), nem todas as métricas estarão presentes em todos os devices, mas agrupando por categoria, 
            é possível lidar melhor com esta ausência de métricas (missing but expected), gerar "help/type" dinâmicos por grupo e utilizar fallback em dashboards 
            por grupo
```

Vale ressaltar que o módulo de rede, para cada interface presente, proverá classificações baseadas em características de hardware, função e representação.

```
     Tipo	Detectável por	
     PF	        Interface física com suporte a SR-IOV
     VF	        Interfaces virtuais criadas a partir de uma PF com suporte a SR-IOV
     PCI	Interfaces de rede não SR-IOV conectadas diretamente ao PCIe bus
     Virtual	Interfaces criadas por software, não correspondem a hardware real
```

```
      
```
b. Módulo NUMA
Módulo que tem como objetivo principal oferecer visibilidade sobre o uso de memória em sistemas com arquitetura NUMA (Non-Uniform Memory Access), auxiliando no  diagnóstico em problemas de desempenho relacionados ao acesso de memória entre diferentes nós NUMA, em sistemas multicore/multisocket.
A captura de dados é realizada através da ferramenta nativa **numastat**


c. Módulo Protocol
Módulo que define o volume na utilização de socket e realizando categorizações quanto aos protocolo utilizado (tcp e udp), além de prover os **estados** das conexões,
através de classificações que permitem saber a carga de solicitações, possíveis vazamentos de conexões ou oroblemas na finalização de conexões e ataques ou escaneamentos de portas. Para obter tais informações, o módulo acessa diretórios, como **/proc/net**, pertencentes à interface de sysfs.


d. Módulo Procs
Define o volume de utilização de **file descriptors**, incluindo sockets, sendo utilizados correntemente, assim como será de grande auxílio em diagnosticar e garantir que processos não excedam os limites de file descriptors, o que causaria falhas, travamentos ou comportamento inesperado. Para obter tais informações, o módulo acessa diretórios, como **/proc**, pertencentes à interface de sysfs.


e. Módulo MonCPU e IPMI
Responsável por prover visibilidade em tempo real sobre uso da CPU, políticas de frequência e limites de energia aplicados no sistema. Para obter tais informações, o módulo acessa diretórios, como **//sys/devices/system/cpu/** e **/sys/class/powercap/**, pertencentes à interface de sysfs.
Neste módulo também foram inseridas informações provenientes da interface **IPMI**, utilizando o comando nativo **ipmitool**. Caso a infraestrutura possa prover suporte a este modo de gestão de hardware (BMC), de forma independente do sistema operacional, informações relacionadas aos sendores de temperatura, energia e fan serão exibidas pelo Prometheus. 
 

## 1. Requirements
Garanta que a versão do python seja igual ou superior à 3.9. Instale o módulo cliente do prometheus:  
```
	# sudo pip3 install prometheus_client  
	
```

## 2. Criação de Serviço no Agente

copie prometheus-dell-firewall-exporter.py para /usr/local/bin:  
```
	# sudo cp prometheus-dell-firewall-exporter.py  /usr/local/bin  
```
   
copie o arquivo de configuração para /etc/default:  
```
	# sudo cp prometheus-dell-firewall-exporter.yaml  /etc/default  
```
  
copie prometheus-dell-firewall-exporter.service para  /etc/systemd/system:  
```
	# sudo cp prometheus-dell-firewall-exporter.service  /etc/systemd/system  
```
   
realize a recarga da nova configuração:  
  	# sudo systemctl  daemon-reload  
  
inicie o  novo serviço:  
```
	# sudo systemctl start  prometheus-dell-prometheus-exporter 
```
   
verifique seu status:  
```
	# sudo systemctl status prometheus-dell-firewall-exporter  
```
  
habilite o serviço para ser inicializado durante o reboot:  
```
	# sudo systemctl enable prometheus-dell-firewall-exporter  
```



## 3. Alterações do arquivo de configuração no Agente
O arquivo de configuração do agente (**/etc/default/prometheus-dell-firewall-exporter.yaml**) precisa ser alterado para se ajustar ao prometheus rodando em ambiente de produção. O atual conteúdo possui as seguintes linhas:

exporter:  
&nbsp;&nbsp;port: 8081  
&nbsp;&nbsp;timeout: 120  

port: defina uma porta tcp onde o agente deverá ficar em **listenning**, esperando por consultas vindas do prometheus server  
timeout: intervalo que o agente utiliza para gerar informações atualizadas das métricas do firewall
  
  

## 4. Testes adicionais
Para testes, o programa curl http://127.0.0.1:8081 poderá ser executado e a saída capturada para análises e ajustes
