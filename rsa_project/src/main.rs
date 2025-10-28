use num_bigint::{BigUint, ToBigInt, RandBigInt};
use num_integer::Integer;
use num_traits::{One, Euclid};
use rand::rngs::OsRng;
// Estruturas de Chaves
#[derive(Debug, Clone)]
struct ChavePublica {
    n: BigUint, // Módulo: n = p * q
    e: BigUint, // Expoente público
}

#[derive(Debug, Clone)]
struct ChavePrivada {
    n: BigUint, // Módulo: n = p * q
    d: BigUint, // Expoente privado
}

// Função para testar se um número é provavelmente primo usando o teste de Miller-Rabin
fn is_probably_prime(n: &BigUint, k: u32) -> bool {
    if n <= &BigUint::one() {
        return false;
    }
    if n == &BigUint::from(2u32) {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let mut rng = OsRng;
    let n_minus_one = n - BigUint::one();
    let mut d = n_minus_one.clone();
    let mut r = 0u32;

    while d.is_even() {
        d >>= 1;
        r += 1;
    }

    'next_witness: for _ in 0..k {
        let a = rng.gen_biguint_range(&BigUint::from(2u32), &(n - BigUint::from(2u32))) + BigUint::from(2u32);
        let mut x = a.modpow(&d, n);

        if x == BigUint::one() || x == n_minus_one {
            continue;
        }

        for _ in 0..r-1 {
            x = x.modpow(&BigUint::from(2u32), n);
            if x == BigUint::one() {
                return false;
            }
            if x == n_minus_one {
                continue 'next_witness;
            }
        }
        return false;
    }
    true
}

// Função para gerar um número primo do tamanho especificado
fn gerar_primo(bits: usize) -> BigUint {
    let mut rng = OsRng;
    loop {
        let n = rng.gen_biguint(bits as u64);
        if is_probably_prime(&n, 30) {  
            return n;
        }
    }
}

// Fase 1: Geração de Chaves
fn gerar_chaves(tamanho_bits: usize) -> (ChavePublica, ChavePrivada) {
    // 1. Gerar primos p e q (metade do tamanho total)
    let p = gerar_primo(tamanho_bits / 2);
    let q = gerar_primo(tamanho_bits / 2);

    // 2. Calcular o Módulo n = p * q
    let n = &p * &q;

    // 3. Calcular a Função Totiente de Euler phi(n) = (p-1) * (q-1)
    let p_minus_one = &p - BigUint::one();
    let q_minus_one = &q - BigUint::one();
    let phi_n = &p_minus_one * &q_minus_one;

    // 4. Escolher Expoente Público e (geralmente 65537)
    let e = BigUint::from(65537u32);

    // 5. Calcular Expoente Privado d (inverso modular de e mod phi(n))
    // .to_bigint() é fornecido pela trait ToBigInt
    // .extended_gcd() é fornecido pela trait Integer
    // .rem_euclid() é fornecido pela trait Euclid
    let d_bigint = e.to_bigint().unwrap()
                      .extended_gcd(&phi_n.to_bigint().unwrap())
                      .x
                      .rem_euclid(&phi_n.to_bigint().unwrap());

    // d é convertido de BigInt para BigUint
    let d = d_bigint.to_biguint().unwrap();

    let chave_publica = ChavePublica { n, e };
    let chave_privada = ChavePrivada { n: chave_publica.n.clone(), d };

    (chave_publica, chave_privada)
}

// Fase 2: Criptografia c = m^e mod n
fn criptografar(m: &BigUint, chave_publica: &ChavePublica) -> BigUint {
    // Exponenciação modular rápida (modpow)
    m.modpow(&chave_publica.e, &chave_publica.n)
}

// Fase 3: Descriptografia m = c^d mod n
fn descriptografar(c: &BigUint, chave_privada: &ChavePrivada) -> BigUint {
    // Exponenciação modular rápida (modpow)
    c.modpow(&chave_privada.d, &chave_privada.n)
}

// Auxiliar: String -> BigUint (abordagem simplificada)
fn string_para_biguint(texto: &str) -> BigUint {
    BigUint::from_bytes_be(texto.as_bytes())
}

// Auxiliar: BigUint -> String
fn biguint_para_string(numero: &BigUint) -> String {
    String::from_utf8(numero.to_bytes_be()).unwrap_or_default()
}

fn main() {
    let tamanho_chave = 512;
    println!("--- Algoritmo RSA em Rust (Exemplo Educacional, Chave {} bits) ---", tamanho_chave);

    // 1. Geração de Chaves
    let (chave_publica, chave_privada) = gerar_chaves(tamanho_chave);

    println!("\nChave Pública (n, e):");
    println!("  n: {}", chave_publica.n);
    println!("  e: {}", chave_publica.e);
    
    println!("\nChave Privada (n, d) - Mantenha em segredo:");
    println!("  d: {}", chave_privada.d);

    // 2. Criptografia e Descriptografia
    let mensagem_original_str = "A matematica é a chave para o RSA!";
    println!("\nMensagem Original: \"{}\"", mensagem_original_str);

    let m = string_para_biguint(mensagem_original_str);
    println!("Mensagem como Número (m): {}", m);

    let c = criptografar(&m, &chave_publica);
    println!("\nTexto Criptografado (c): {}", c);

    let m_descriptografado = desScriptografar(&c, &chave_privada);
    println!("\nNúmero Descriptografado (m'): {}", m_descriptografado);

    let mensagem_descriptografada_str = biguint_para_string(&m_descriptografado);
    println!("Mensagem Descriptografada: \"{}\"", mensagem_descriptografada_str);

    assert_eq!(m, m_descriptografado);
    println!("\nSucesso: A mensagem original e a descriptografada coincidem.");
}