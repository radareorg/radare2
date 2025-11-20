# Generic Guide: Parsing Any Floating-Point Value from Binary

To parse **any floating-point value** from binary data, you need to understand much more than just the **sign**, **exponent**, and **fraction**. The IEEE-754 standard dominates, but there are several variations (bfloat16, x87 80-bit, decimal64/128, IBM hexadecimal float, VAX, etc.). Below is a complete checklist and explanation.

---

## ✅ Essential Format Checklist

1. **Total width (N bits)** and **field layout**  
   - Sign bit (s)  
   - Exponent bits (e) and its **bias**  
   - Fraction/Mantissa bits (f), and whether there’s a **hidden leading bit** or an **explicit one** (x87).

2. **Exponent special cases**  
   - e = 0, f = 0 → **±0** (signed zero)  
   - e = 0, f ≠ 0 → **subnormal (denormal)**  
   - e = all 1s, f = 0 → **±∞**  
   - e = all 1s, f ≠ 0 → **NaN** (distinguish **qNaN** vs **sNaN** using the quiet bit)

3. **Leading bit rule**  
   - IEEE binary: implicit `1.f` for normal numbers  
   - x87 80-bit: explicit leading bit  
   - Some legacy formats differ.

4. **Endianness in memory**  
   - **Byte endianness** (little/big/mixed) affects interpretation.  
   - **x87 80-bit**: stored in 96 or 128 bits with padding.  
   - **bfloat16**: packed into 16 bits, often stored in 32-bit containers.  
   - Beware of **bit-endianness** vs **byte-endianness**.

5. **Non-binary encodings**  
   - IEEE **decimal64/128**: check if it’s **BID** (Binary Integer Decimal) or **DPD** (Densely Packed Decimal).  
   - **IBM hexadecimal float**: base-16, not base-2.  
   - Each requires unique decoding rules.

6. **Special values and metadata**  
   - **Signed zero** (−0 and +0) matters in comparisons and division.  
   - **NaN payloads** may propagate through operations (arch-dependent).  
   - **Subnormals** may be affected by FTZ/DAZ (flush-to-zero / denormals-are-zero) modes.

7. **Rounding and exceptions (when converting)**  
   - IEEE modes: ties-to-even (default), toward zero, +∞, −∞, or ties-away.  
   - Exceptions: inexact, underflow, overflow, divide-by-zero, invalid.  
   - **Parsing bits → value** involves no rounding, only when **converting** to another format or to decimal.

---

## 🧮 Generic IEEE Binary Formula

For `s` (1 bit), `e` (m bits, bias = B), `f` (n bits):

- **Normal (0 < e < 2^m−1)**:  
  `value = (−1)^s × (1.f)_2 × 2^(e − B)`

- **Subnormal (e = 0, f ≠ 0)**:  
  `value = (−1)^s × (0.f)_2 × 2^(1 − B)`

Special cases for zeros, infinities, and NaNs apply.

---

## 🧩 Pseudocode (IEEE-like Binary)

```text
read N bits respecting BYTE endianness
s = extract_bit(pattern, sign_pos)
e = extract_bits(pattern, exp_pos, m)
f = extract_bits(pattern, frac_pos, n)

if e == 0:
  if f == 0: return signed_zero(s)
  else: return (-1)^s * (f / 2^n) * 2^(1 - B)
else if e == (2^m - 1):
  if f == 0: return inf_with_sign(s)
  else: return nan_with_payload(s, f)
else:
  leading = 1  // or explicit bit if format defines it
  return (-1)^s * (leading + f/2^n) * 2^(e - B)
```

---

## 🧠 Common Format Parameters

| Format | Layout (s,e,f) | Bias | Notes |
|---------|----------------|------|-------|
| binary16 | 1-5-10 | 15 | Half precision |
| binary32 | 1-8-23 | 127 | Single precision |
| binary64 | 1-11-52 | 1023 | Double precision |
| binary128 | 1-15-112 | 16383 | Quad precision |
| bfloat16 | 1-8-7 | 127 | Same bias as float32 |
| x87 80-bit | 1-15-64 | 16383 | Explicit integer bit |
| decimal64 | varies | 398 | BID/DPD encoding |
| decimal128 | varies | 6176 | BID/DPD encoding |
| IBM hex float | varies | base-16 | Non-IEEE |

---

## ⚙️ Endianness Edge Cases

- ARM/MIPS may have **mixed word/byte endianness**.  
- x87 80-bit may include **padding** (96 or 128-bit structs).  
- Always define **endianness explicitly** when serializing (network order = big-endian).

---

## 🔁 When Rounding Applies

Rounding **does not** apply when reading raw bits.
It only applies when:
- Converting to another format (e.g., 80-bit → 64-bit)
- Converting to text (decimal printing)
- Performing arithmetic operations

Default: **ties-to-even**, but hardware can change it.

---

## 🧰 Implementation Tips

- Read bits as an **integer or bitset**, respecting endianness.  
- Avoid aliasing (no unsafe type-punning). Use `memcpy` or `bit_cast` if available.  
- For **decimal IEEE formats**, reuse or implement BID/DPD decoders.

---

## 🧾 Example (float32)

- N = 32, m = 8, n = 23, B = 127  
- 0x3F800000 → s=0, e=127, f=0 ⇒ 1.0  
- 0x7FC00001 → NaN (qNaN with payload 1)  
- 0x00000001 → smallest subnormal ≈ 2^(1−127) × 2^−23

---

If you tell me the **exact format** (width, field layout, or bit dump), I can provide a precise parser and unit tests for it.
