#!/usr/bin/env python3
import os
import time
from pwn import *
from fastecdsa.curve import P256
from fastecdsa.encoding.sec1 import SEC1Encoder

import snarg
import dpp
import add 

circuit = add.build_adder(64)
BOUND1 = 2**8
n = len(circuit.inputs)
trace_len = dpp.trace_len(circuit)
b = trace_len * BOUND1 + 1

c0_idx = 128
s0_idx = -1
for gate in circuit.gates:
    if isinstance(gate, dpp.XorGate) and (gate.left.index == c0_idx or gate.right.index == c0_idx):
        s0_idx = gate.right.index if gate.left.index == c0_idx else gate.left.index
        break

pair_128_128 = dpp.pair_index(circuit, c0_idx, c0_idx)
pair_128_s0 = dpp.pair_index(circuit, c0_idx, s0_idx)

crs_points = []
with open('crs.bin', 'rb') as f:
    while chunk := f.read(33):
        crs_points.append(SEC1Encoder.decode_public_key(chunk, P256))

C_pair_128_128 = crs_points[pair_128_128 - n]
C_pair_128_s0 = crs_points[pair_128_s0 - n]
H_pair_128_128 = snarg.hash_to_point(pair_128_128 - n)
H_pair_128_s0 = snarg.hash_to_point(pair_128_s0 - n)
inv2 = (P256.q + 1) // 2

def verify_vconst(V_const):
    try: 
        r = remote('dot.chals.dicec.tf', 1337)
        r.recvuntil(b'what is ')
        question = r.recvuntil(b'?').decode().strip('?')
        a_val, b_val = map(int, question.split(' + '))
        
        c_true = (a_val + b_val) % (1 << 64)
        c_wrong = c_true ^ 1
        delta = 1 if (c_wrong & 1) else -1
        
        inputs_true = add.int_to_bits(a_val, 64) + add.int_to_bits(b_val, 64) + add.int_to_bits(c_true, 64)
        with open('crs.bin', 'rb') as f:
            h1_true, h2_true = snarg.prove(circuit, inputs_true, f)
            
        coeff1 = delta % P256.q
        coeff2 = (delta * inv2) % P256.q
        coeff3 = (-delta * V_const) % P256.q
        
        base_h2 = h2_true + (coeff1 * C_pair_128_128) + (coeff2 * C_pair_128_s0)
        base_h1 = h1_true + (coeff1 * H_pair_128_128) + (coeff2 * H_pair_128_s0)
        h2_forged = base_h2 + (coeff3 * P256.G)
        
        proof_hex = SEC1Encoder.encode_public_key(base_h1, compressed=True).hex() + \
                    SEC1Encoder.encode_public_key(h2_forged, compressed=True).hex()
                    
        r.sendlineafter(b'answer: ', str(c_wrong).encode())
        r.sendlineafter(b'proof: ', proof_hex.encode())
        
        resp = r.recvline().decode().strip()
        r.close()
        return 'huh?' in resp or 'streak' in resp
    except:
        return False

def get_v_const():
    possible_V = set()
    for x in range(-BOUND1, BOUND1 + 1):
        for y in range(-BOUND1, BOUND1 + 1):
            possible_V.add(x + b * x * (x + y))
    possible_V = list(possible_V)
    
    start_idx = 0
    BATCH_SIZE = 500 
    
    while start_idx < len(possible_V):
        try:
            r = remote('dot.chals.dicec.tf', 1337)
            r.recvuntil(b'what is ')
            question = r.recvuntil(b'?').decode().strip('?')
            a_val, b_val = map(int, question.split(' + '))
            
            c_true = (a_val + b_val) % (1 << 64)
            c_wrong = c_true ^ 1
            delta = 1 if (c_wrong & 1) else -1
            
            inputs_true = add.int_to_bits(a_val, 64) + add.int_to_bits(b_val, 64) + add.int_to_bits(c_true, 64)
            with open('crs.bin', 'rb') as f:
                h1_true, h2_true = snarg.prove(circuit, inputs_true, f)
            
            coeff1 = delta % P256.q
            coeff2 = (delta * inv2) % P256.q
            
            base_h2 = h2_true + (coeff1 * C_pair_128_128) + (coeff2 * C_pair_128_s0)
            base_h1 = h1_true + (coeff1 * H_pair_128_128) + (coeff2 * H_pair_128_s0)
            
            r.recvuntil(b'answer: ')

            while start_idx < len(possible_V):
                batch = possible_V[start_idx : start_idx + BATCH_SIZE]
                payload = b''
                for V_const in batch:
                    coeff3 = (-delta * V_const) % P256.q
                    h2_forged = base_h2 + (coeff3 * P256.G)
                    
                    proof_hex = SEC1Encoder.encode_public_key(base_h1, compressed=True).hex() + \
                                SEC1Encoder.encode_public_key(h2_forged, compressed=True).hex()
                    payload += f"{c_wrong}\n{proof_hex}\n".encode()

                r.send(payload)
                
                for j in range(len(batch)):
                    resp = r.recvline(timeout=5).decode().strip()
                    if not resp: raise EOFError()
                    if 'huh?' in resp or 'streak' in resp:
                        found_v = batch[j]
                        if verify_vconst(found_v):
                            r.close()
                            return found_v
                        else:
                            print("Fake")

                start_idx += len(batch)
                
        except (EOFError, ConnectionResetError):
            try: r.close()
            except: pass
            time.sleep(1) 
            continue 
            
    return None

def get_flag(V_const):
    r = remote('dot.chals.dicec.tf', 1337)
    
    for streak in range(1, 21):
        r.recvuntil(b'what is ')
        question = r.recvuntil(b'?').decode().strip('?')
        a_val, b_val = map(int, question.split(' + '))
        
        c_true = (a_val + b_val) % (1 << 64)
        c_wrong = c_true ^ 1
        delta = 1 if (c_wrong & 1) else -1
        
        inputs_true = add.int_to_bits(a_val, 64) + add.int_to_bits(b_val, 64) + add.int_to_bits(c_true, 64)
        with open('crs.bin', 'rb') as f:
            h1_true, h2_true = snarg.prove(circuit, inputs_true, f)
            
        coeff1 = delta % P256.q
        coeff2 = (delta * inv2) % P256.q
        coeff3 = (-delta * V_const) % P256.q
        
        base_h2 = h2_true + (coeff1 * C_pair_128_128) + (coeff2 * C_pair_128_s0)
        base_h1 = h1_true + (coeff1 * H_pair_128_128) + (coeff2 * H_pair_128_s0)
        h2_forged = base_h2 + (coeff3 * P256.G)
        
        proof_hex = SEC1Encoder.encode_public_key(base_h1, compressed=True).hex() + \
                    SEC1Encoder.encode_public_key(h2_forged, compressed=True).hex()
                    
        r.sendlineafter(b'answer: ', str(c_wrong).encode())
        r.sendlineafter(b'proof: ', proof_hex.encode())
        
        resp = r.recvline().decode().strip()
        if 'huh?' in resp or 'streak' in resp or 'dice{' in resp:
            if 'dice{' in resp:
                print("FLAG:", resp)
                break
        else:
            print(f"Lỗi: {resp}")
            break
            
    r.interactive()

if __name__ == '__main__':
    v_const = get_v_const()
    if v_const is not None:
        time.sleep(1) 
        get_flag(v_const)