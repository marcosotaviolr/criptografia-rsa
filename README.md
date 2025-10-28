## Mini-Aula Didática: Criptografia RSA
RSA (Rivest-Shamir-Adleman), um dos pilares da segurança moderna. O RSA é um algoritmo de criptografia assimétrica desenvolvido em 1977, sendo um dos sistemas de chave pública mais antigos e mais amplamente utilizados.
O RSA possui quatro Características Principais:
1. Assimetria: Usa duas chaves diferentes (pública e privada).
2. Fundamento Matemático: Sua segurança se baseia na dificuldade de fatorar números grandes.
3. Bidirecionalidade: Pode ser usado para criptografar e assinar digitalmente.
4. Adoção Ampla: É a base de protocolos como HTTPS e SSH.

--------------------------------------------------------------------------------
## 1. Princípios Matemáticos: O Alicerce da Segurança
A força do RSA não está na complexidade de seu algoritmo, mas sim em um problema matemático fundamental que é difícil de resolver rapidamente.
O Problema da Fatoração (O Segredo). A segurança do RSA é a dificuldade computacional de fatorar números grandes. Se um atacante souber o módulo público n, ele precisa encontrar seus fatores primos secretos p e q (onde n = p × q). 

Para que a fatoração permaneça impraticável, o documento recomenda que as chaves tenham um tamanho mínimo de 2048 bits (equivalente a 112 bits de segurança simétrica), com a recomendação de migrar para 3072 bits até 2025. O melhor algoritmo clássico para fatoração (GNFS) ainda requer uma complexidade exponencial para quebrar chaves deste tamanho.

Ferramentas Matemáticas Essenciais
O RSA exige conceitos de teoria dos números para a geração e o uso das chaves:
1. Aritmética Modular: É a fundação do algoritmo, permitindo que as operações sejam realizadas em um "ciclo". Ela viabiliza o cálculo eficiente de (a×b)(modn) e (a<sup>k</sup>) (modn).
2. Função Totiente de Euler (φ(n)): Este valor é crucial para o RSA. Para n sendo o produto de dois primos (p e q), φ(n)=(p−1)×(q−1). Este valor deve ser mantido em segredo.
3. Inverso Modular e Teorema de Euler: O Teorema de Euler (que dita que a<sup>φ(n)</sup> ≡1(mod n)) e seu corolário a<sup>k×φ(n)+1</sup> ≡ a(mod n) provam matematicamente que a descriptografia funcionará. O expoente privado (d) é o inverso modular do expoente público (e) módulo φ(n).

--------------------------------------------------------------------------------
## 2. Funcionamento do Algoritmo
O RSA opera em três fases principais: Geração de Chaves, Criptografia e Descriptografia.

Geração das Chaves (Fase Secreta)

A chave assimétrica é criada em cinco passos principais:

1. Gerar p e q: Dois números primos grandes e distintos (verificados por testes como o Miller-Rabin).
2. Calcular n (Módulo Público): n=p×q.
3. Calcular φ(n) (Totiente Secreto): φ(n)=(p−1)×(q−1).
4. Escolher e (Expoente Público): Um valor comum é e=65537, pois é eficiente e amplamente testado.
5. Calcular d (Expoente Privado): d é o inverso modular de e módulo φ(n), calculado usando o Algoritmo Euclidiano Estendido.

• Resultado: A Chave Pública é (n,e) e a Chave Privada é (n,d).

O Fluxo de Criptografia e Descriptografia

O Princípio Básico estabelece que se Bob usa a Chave Pública de Alice para criptografar, apenas Alice pode descriptografar com sua Chave Privada.

Criptografia: c = m<sup>e</sup>, chave pública (n, e)
Descriptografia = m = c<sup>d</sup>, chave privada (n, d)

Para que estas operações sejam viáveis com números enormes (ex: 2048 bits), a Exponenciação Modular Rápida (algoritmo Square-and-Multiply) é indispensável. Ela calcula a<sup>k</sup> (mod n) eficientemente em tempo O(log exp) e evita calcular números gigantescos.

--------------------------------------------------------------------------------
## 3. Aplicações Práticas e Segurança da Informação
O uso prático do RSA é focado e exige rigor devido às suas limitações de desempenho e complexidade.

A. Uso Prático e Limitações
1. Criptografia Híbrida: O RSA é cerca de 1000x mais lento que algoritmos simétricos como o AES. Por isso, o RSA não é usado para criptografar grandes volumes de dados. Em vez disso, seu uso recomendado é para troca de chaves simétricas, onde ele criptografa uma chave de sessão curta e rápida, que então criptografa os dados.
2. Assinatura Digital: É também amplamente usado para assinatura digital, garantindo autenticidade.

B. Implementação Segura (Padrão de Produção)

A complexidade do RSA o torna fácil de implementar incorretamente, introduzindo vulnerabilidades.

• Padding Seguro: Em sistemas de produção, é crucial usar padding (preenchimento) criptográfico seguro para evitar ataques como Bleichenbacher. Deve-se usar OAEP para criptografia e PSS para assinatura digital.

• Chaves Fortes e Aleatoriedade: É fundamental usar chaves ≥2048 bits e garantir que os primos p e q sejam gerados usando números verdadeiramente aleatórios.

C. A Ameaça Quântica

A maior limitação futura do RSA é o Algoritmo de Shor (1994), que tem a capacidade de quebrar o RSA em tempo polinomial se implementado em um computador quântico funcional. Por essa razão, o RSA é classificado como Legado no contexto pós-quântico, e sistemas como Kyber e Dilithium (algoritmos pós-quânticos) estão sendo padronizados para substituí-lo.
