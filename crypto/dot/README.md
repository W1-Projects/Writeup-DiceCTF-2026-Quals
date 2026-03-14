## Crypto / dot
Bài này yêu cầu ta khai thác 1 lỗ hổng trong hệ thống chứng minh SNARG (Succinct Non-interactive Argument of Knowledge) tự chế dành cho các mạch logic (boolean circuits).

Lỗ hổng chí mạng của bài này là verifier không kiểm tra đầy đủ proof. Nó chỉ kiểm tra 1 phần tử nhóm được xác định có nằm trong bảng tra cứu được tính toán trước hay không.
```python
def verify(inputs: list[int], st: State, proof: Proof) -> bool:
	sk, q_inputs, table = st
	...
	h1, h2 = proof
	p = h2 - sk * h1
	input_sum = sum(q_inputs[i] * inputs[i] for i in range(len(inputs)))
	p += input_sum * P256.G
	p_enc = SEC1Encoder.encode_public_key(p, compressed=True)
	return p_enc in table
```

Vì CRS được public nên ta có thể build proof ở local cho bất kỳ bổ sung chính xác nào. Ngoài ra, để flip một bit đầu ra đã chọn của `c`, có một chỗ sửa trong cách chứng minh tọa độ đã gần như hủy bỏ hoàn toàn ràng buộc ẩn của xác minh. Chỉ để lại 1 lambda vô hướng ẩn trên điểm cơ sở, vector vô hướng đó chỉ phụ thuộc vào 2 hệ số ẩn nhỏ.

Vì vậy, dù challenge yêu cầu tính toán proof local nhưng thay vì trả lời bằng `c` đúng, ta lật một bit đã chọn của `c` và thêm phần điều chỉnh tương ứng vào proof.

Sau đó trừ đi giá trị brute force lambda `*G`. Nếu giá trị đúng thì verifier sẽ thấy chính xác bảng điểm giống như đối với proof. Vậy là nó chấp nhận câu trả lời sai và trả về `huh?`. Sau khi nhận được lambda, ta lặp lại cách xây dựng proof giả đó vào 20 lần nữa và get flag ^^
```python
            valid = snarg.verify(inputs, st, proof)

			if valid and correct:
				print('correct! but that was obvious...')
				streak = 0
			elif valid and not correct:
				print('huh?')
				streak += 1
				if streak >= 20:
					print(open('flag.txt').read().strip())
					exit()
				break
```
### Bruteforce lambda
Từ đoạn source code sau, ta có công thức của $\lambda$:
```python
def sample(circuit: Circuit, bound1: int, bound2: int) -> tuple[Vector, State]:
	n = trace_len(circuit)
	b = n * bound1 + 1
	q1, q2 = tensor_queries(circuit, bound1)
	q3, val = constraint_query(circuit, bound2)
	q = [q1[i] + b * (q2[i] - q3[i]) for i in range(proof_len(circuit))]
	st = (b, val)
	return (q, st)
```
Trong `tensor_queries`, `q1` đóng vai trò bậc 1 ($u$), còn `q2` đóng vai trò tích chéo ($u \cdot w$ hoặc $u^2$):
```python
for i in range(n):
		q1[i] = v[i]
		for j in range(i + 1):
			q2[pair_index(circuit, i, j)] = v[i] * v[j] if i == j else 2 * v[i] * v[j]
```
Vì $\lambda = u * (1 + b * (u + w))$, với $u, w \in [-256,256]$ nên thay vì tìm kiếm một không gian 34 bit bất kì, ta chỉ cần sử dụng không gian này. Và nó chỉ cho ra khoảng 262 nghìn lượt thử, tức là khoảng $2^{18}$, không phải $2^{34}$.
```python
# snarg.py
BOUND1 = 2**8

# dpp.py
def tensor_queries(circuit: Circuit, bound: int) -> tuple[Vector, Vector]:
	n = trace_len(circuit)
	v = [random.randint(-bound, bound) for _ in range(n)]
    ...
```

    Flag: dice{operation_spot_by_odd_part_of_drug_city}
