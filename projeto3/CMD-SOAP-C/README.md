# CMD-SOAP - Teste das operações do serviço SCMD (Signature CMD)

Na diretoria CMD_1.6_spec encontra os ficheiros que lhe permitem testar as
operações do serviço SCMD (Signature
CMD), de acordo com a versão 1.6 da "CMD - Especificação dos serviços de
Assinatura", utilizando a linguagem de programação python (versão 3).

Nessa diretoria encontram-se três ficheiros:

+ cmd_soap_msg.py - contém as funções que preparam e executam os comandos
SOAP do SCMD, nomeadamente:
  + GetCertificate
  + CCMovelSign
  + CCMovelMultipleSign
  + ValidateOtp
+ \_cmd_config.py - Ficheiro que deve ser renomeado para cmd_config.py e onde
deve colocar o ApplicationId fornecido pela AMA.
+ test_cmd_wsdl.py - Permite-lhe testar os vários comandos SOAP do SCMD.


### 1. Utilização da aplicação de testes

As várias opções da _command line interface_ (CLI) da aplicação de testes podem
ser visualizadas  através da execução de `python3 test_cmd_wsdl.py -h`.

As opções de cada operação podem ser visualizadas  através da execução de
`python3 test_cmd_wsdl.py <oper> -h`, em que <oper> é uma das seguintes
operações:

+ "GetCertificate" ou "gc"
  + testa o comando SOAP GetCertificate do SCMD
+ "CCMovelSign" ou "ms"
  - testa o comando SOAP CCMovelSign do SCMD
+ "CCMovelMultipleSign" ou "mms"
  - testa o comando SOAP CCMovelMultipleSign do SCMD
+ "ValidateOtp" ou "otp"
  - testa o comando SOAP ValidateOtp do SCMD
+ "TestAll" ou "test"
  - testa automaticamente a sequência de comandos GetCertificate, CCMovelSign e
ValidateOtp, verificando no final a assinatura,  baseado na assinatura
recebida, na hash gerada e na chave pública do certificado recebido.

Por defeito é feita a ligação ao serviço SCMD de pré-produção - no caso de
pretender utilizar o serviço SCMD de produção tem que incluir o argumento
opcional `-prod` na linha de comando.

#### 1.1 Exemplo do "TestAll"

Para efetuar o teste à sequência de comandos GetCertificate, CCMovelSign e
ValidateOtp, deve utilizar a seguinte linha de comando:

        python3 test_cmd_wsdl.py test ../LICENSE '+351 000000000' 12345678

sendo a resposta esperada a seguinte:


        test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)
        version: 1.0

        +++ Test All inicializado +++

         0% ... Leitura de argumentos da linha de comando - file: ../LICENSE user: +351 000000000 pin: 12345678
        10% ... A contactar servidor SOAP CMD para operação GetCertificate
        20% ... Certificado emitido para "JOSÉ EDUARDO PINA DE MIRANDA" pela Entidade de Certificação "(TESTE) EC de Chave Móvel Digital de Assinatura Digital Qualificada do Cartão de Cidadão 0007" na hierarquia do "(Teste) Cartão de Cidadão 005"
        30% ... Leitura do ficheiro ../LICENSE
        40% ... Geração de hash do ficheiro ../LICENSE
        50% ... Hash gerada (em base64): OXLcl0T2SZ8Pmy2/dmlvKuetivmyPd5m1q+Gyd+zaYY=
        60% ... A contactar servidor SOAP CMD para operação CCMovelSign
        70% ... ProcessID devolvido pela operação CCMovelSign: 8c3123b0-fc15-41e1-872c-c508249c0210
        80% ... A iniciar operação ValidateOtp
        Introduza o OTP recebido no seu dispositivo: 305816

        90% ... A contactar servidor SOAP CMD para operação ValidateOtp
        100% ... Assinatura (em base 64) devolvida pela operação ValidateOtp: p3KlsLSg+csXAtc361WMu5SJJvX2v55fd1clnq3qx4ZtP7Ns5qjS1js6wKj9QfG5WJOc57KRu8y1OJDPF5yWmAodIt7sffT9IapkblLu5LweJi5h823t3SHA1gvNBXXD/+H/0SBx2uVph/hg0U/U9wNIB1SJJTyg720i7nw/lI7jhRovLFum6MP+Iq4gG/VnLw0L
        gFtstx2W94jCKo0oI8EIsEzoxygQw6D5b2f7vVofaZxbE9peE0djwx8tx6UxGPIOLZWDv8QrnmU9xnmwvBN7iFNcYI+zL4BgiU/HSXiVvIBYUUvfff9HPmA6S/tcZhu3Fc3J2zYdcrEU12MrHvKDfEHsxy9HA9GYTFzjGCxnbfndDS5GO5PXmCFwgtEr9/IXWKlgNYAxze88KX20vHhHJXNqRyg47EB7L+Ll5QLqrZLqDTLNRTK5WhXhitL/iobGVg0PyBVYoO
        6llSh72SQxwiOIGOFoSwSQNsdztkxDQyi3K4yVjToSfjjINp7A

        110% ... A validar assinatura ...
        Assinatura verificada com sucesso, baseada na assinatura recebida, na hash gerada e na chave pública do certificado de JOSÉ EDUARDO PINA DE MIRANDA

        +++ Test All finalizado +++



### 2. Notas genéricas:

1. Necessário instalar as seguintes packages python, por exemplo com recurso ao
pip3:

  - hashlib
  - logging
  - zeep
  - argparse           
  - base64
  - pem
  - OpenSSL
  - Crypto

2. A aplicação deve ser utilizada com Python 3.7.3 ou superior

3. Antes de utilizar, renomeie o ficheiro \_cmd_config.py para cmd_config.py
e introduza o APPLICATION_ID da sua entidade (atribuído pela AMA)

4. Licença: GNU GENERAL PUBLIC LICENSE Version 3
