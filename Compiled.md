---
tags:
  - thm
  - easy
  - reverse-engineering
  - binary-exploitation
  - c
  - ghidra
Scenario: Reverse engineering a compiled C binary; bypassing `scanf` logic using whitespace behavior.
Link: https://tryhackme.com/room/compiled
---
## ⚡ Quick Reference (TL;DR)

### Key Concepts & Tricks
1.  **The `scanf` Bypass:** If a format string looks like `"%sSuffix"`, `scanf` stops reading at the first whitespace (Space/Enter). It does **not** force you to type the "Suffix".
    * *Expected:* `Prefix_Payload_Suffix`
    * *Bypass:* `Prefix_Payload` + [ENTER] -> Suffix is ignored, payload is accepted.
2.  **Ghidra Artifacts:** If you see `(-1 < iVar1) && (iVar1 < 1)`, it simply means `iVar1 == 0` (Equality Check).

### Quick Analysis Commands
```bash
# 1. Quick strings check (look for hardcoded passwords or prompts)
strings -n 8 Compiled-1688545393558.Compiled

# 2. Run binary via Docker (if on Mac/Windows)
docker run --platform linux/amd64 --rm -i -v $(pwd):/app -w /app ubuntu:latest /app/binary
```

---

## Detailed Walkthrough

### **1. Initial Reconnaissance**
First, examine the binary with `strings`:
```bash
strings -n 8 Compiled-1688545393558.Compiled
```

Key findings:
- `Password: ` - indicates password prompt
- `DoYouEven%sCTF` - suggests a scanf format string
- `__dso_handle`, `_init` - potential comparison strings
- `Correct!`, `Try again!` - success/failure messages

### **2. Static Analysis with Ghidra**
Load the binary in Ghidra and locate the `main` function.

**Decompiled Code:**
```c
undefined8 main(void)
{
  int iVar1;
  char local_28 [32];
  
  fwrite("Password: ",1,10,stdout);
  __isoc99_scanf("DoYouEven%sCTF",local_28);
  iVar1 = strcmp(local_28,"__dso_handle");
  if ((-1 < iVar1) && (iVar1 = strcmp(local_28,"__dso_handle"), iVar1 < 1)) {
    printf("Try again!");
    return 0;
  }
  iVar1 = strcmp(local_28,"_init");
  if (iVar1 == 0) {
    printf("Correct!");
  }
  else {
    printf("Try again!");
  }
  return 0;
}
```

### **3. Understanding the Logic**

#### **Input Reading:**
```c
__isoc99_scanf("DoYouEven%sCTF",local_28);
```
- Format string expects: `DoYouEven` + [any string] + `CTF`
- Only the `%s` part (between `DoYouEven` and `CTF`) gets stored in `local_28`

#### **First Check:**
```c
if ((-1 < iVar1) && (iVar1 = strcmp(local_28,"__dso_handle"), iVar1 < 1))
```
This convoluted condition is equivalent to:
```c
if (strcmp(local_28, "__dso_handle") == 0)
```
- If `local_28` equals `"__dso_handle"`, print "Try again!" and exit
- This is the **wrong password**

#### **Second Check:**
```c
iVar1 = strcmp(local_28,"_init");
if (iVar1 == 0) {
    printf("Correct!");
}
```
- If `local_28` equals `"_init"`, print "Correct!"
- This is the **correct password**

### **4. Solving the Puzzle**

**Goal:** Make `local_28 = "_init"`

**Problem:** The `scanf` format expects `DoYouEven%sCTF`
- If we type `DoYouEven_initCTF`, `%s` reads `_initCTF` (not `_init`)
- This fails the comparison

**Solution:** The `%s` stops at whitespace
- Type `DoYouEven_init` and press Enter
- `%s` reads `_init` (stops at newline)
- `scanf` fails on missing `CTF` but `local_28` already contains `_init`
- Program doesn't check if `scanf` succeeded

**Alternative:** `DoYouEven_init CTF` (with space) also works:
- `%s` reads `_init` (stops at space)
- `scanf` fails on missing `CTF` (space ≠ 'C')
- `local_28` = `"_init"` ✓

### **5. Testing the Solution**

**On Linux:**
```bash
echo "DoYouEven_init" | ./binary
```
or interactively:
```bash
./binary
Password: DoYouEven_init
Correct!
```

**On macOS (using Docker):**
```bash
docker run --platform linux/amd64 --rm -i \
  -v $(pwd):/app -w /app ubuntu:latest \
  /app/Compiled-1688545393558.Compiled
```
Then enter: `DoYouEven_init`

### **6. Key Insights**

1. **`scanf` format strings can be deceptive** - literal parts (`DoYouEven` and `CTF`) may not need to be fully matched if program doesn't check `scanf`'s return value

2. **`%s` stops at whitespace** - this allows us to control what gets stored

3. **Compiler optimizations create confusing conditions** - the first check `(-1 < iVar1) && (iVar1 = strcmp(...), iVar1 < 1)` is just a complicated way to check for equality to `0`

4. **Decompiled code may not perfectly match source** - variable names like `local_28` and `iVar1` are Ghidra's guesses

### **7. Flag**
The flag/password is: **`DoYouEven_init`**