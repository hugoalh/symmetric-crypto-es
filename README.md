# Symmetric Crypto (ES)

[**⚖️** MIT](./LICENSE.md)

[![GitHub: hugoalh/symmetric-crypto-es](https://img.shields.io/github/v/release/hugoalh/symmetric-crypto-es?label=hugoalh/symmetric-crypto-es&labelColor=181717&logo=github&logoColor=ffffff&sort=semver&style=flat "GitHub: hugoalh/symmetric-crypto-es")](https://github.com/hugoalh/symmetric-crypto-es)
[![JSR: @hugoalh/symmetric-crypto](https://img.shields.io/jsr/v/@hugoalh/symmetric-crypto?label=@hugoalh/symmetric-crypto&labelColor=F7DF1E&logo=jsr&logoColor=000000&style=flat "JSR: @hugoalh/symmetric-crypto")](https://jsr.io/@hugoalh/symmetric-crypto)
[![NPM: @hugoalh/symmetric-crypto](https://img.shields.io/npm/v/@hugoalh/symmetric-crypto?label=@hugoalh/symmetric-crypto&labelColor=CB3837&logo=npm&logoColor=ffffff&style=flat "NPM: @hugoalh/symmetric-crypto")](https://www.npmjs.com/package/@hugoalh/symmetric-crypto)

An ECMAScript (JavaScript & TypeScript) module to provide an easier symmetric crypto.

## 🔰 Begin

### 🎯 Targets

|  | **Remote** | **JSR** | **NPM** |
|:--|:--|:--|:--|
| **[Bun](https://bun.sh/)** >= v1.1.0 | ❌ | ❓ | ✔️ |
| **[Cloudflare Workers](https://workers.cloudflare.com/)** | ❌ | ❓ | ✔️ |
| **[Deno](https://deno.land/)** >= v1.42.0 | ✔️ | ✔️ | ✔️ |
| **[NodeJS](https://nodejs.org/)** >= v16.13.0 | ❌ | ❓ | ✔️ |

> [!NOTE]
> - It is possible to use this module in other methods/ways which not listed in here, however those methods/ways are not officially supported, and should beware maybe cause security issues.

### #️⃣ Resources Identifier

- **Remote - GitHub Raw:**
  ```
  https://raw.githubusercontent.com/hugoalh/symmetric-crypto-es/{Tag}/mod.ts
  ```
- **JSR:**
  ```
  [jsr:]@hugoalh/symmetric-crypto[@{Tag}]
  ```
- **NPM:**
  ```
  [npm:]@hugoalh/symmetric-crypto[@{Tag}]
  ```

> [!NOTE]
> - For usage of remote resources, it is recommended to import the entire module with the main path `mod.ts`, however it is also able to import part of the module with sub path if available, but do not import if:
>
>   - it's path has an underscore prefix (e.g.: `_foo.ts`, `_util/bar.ts`), or
>   - it is a benchmark or test file (e.g.: `foo.bench.ts`, `foo.test.ts`), or
>   - it's symbol has an underscore prefix (e.g.: `_bar`, `_foo`).
>
>   These elements are not considered part of the public API, thus no stability is guaranteed for them.
> - For usage of JSR or NPM resources, it is recommended to import the entire module with the main entrypoint, however it is also able to import part of the module with sub entrypoint if available, please visit the [file `jsr.jsonc`](./jsr.jsonc) property `exports` for available sub entrypoints.
> - It is recommended to use this module with tag for immutability.

### 🛡️ Runtime Permissions

- File System - Read \[Deno: `read`; NodeJS (>= v20.9.0) 🧪: `fs-read`\]
  - *Resources* (Optional)
- File System - Write \[Deno: `write`; NodeJS (>= v20.9.0) 🧪: `fs-write`\]
  - *Resources* (Optional)

## 🧩 APIs

- ```ts
  class SymmetricCryptor {
    decrypt(data: string): Promise<string>;
    decrypt(data: Uint8Array): Promise<Uint8Array>;
    decryptFile(...filesPath: (string | URL)[]): Promise<this>;
    encrypt(data: string): Promise<string>;
    encrypt(data: Uint8Array): Promise<Uint8Array>;
    encryptFile(...filesPath: (string | URL)[]): Promise<this>;
    readEncryptedFile(filePath: string | URL, options?: Deno.ReadFileOptions): Promise<Uint8Array>;
    readEncryptedTextFile(filePath: string | URL, options?: Deno.ReadFileOptions): Promise<string>;
    writeEncryptedFile(filePath: string | URL, data: Uint8Array, options?: Omit<Deno.WriteFileOptions, "append">): Promise<this>;
    writeEncryptedTextFile(filePath: string | URL, data: string, options?: Omit<Deno.WriteFileOptions, "append">): Promise<this>;
  }
  ```
- ```ts
  function createSymmetricCryptor(key: SymmetricCryptorKeyInput | SymmetricCryptorKeyType, options?: SymmetricCryptorOptions): Promise<SymmetricCryptor>;
  function createSymmetricCryptor(keys: (SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[], options?: Omit<SymmetricCryptorOptions, "times">): Promise<SymmetricCryptor>;
  ```
- ```ts
  interface SymmetricCryptorOptions {
    decoder?: SymmetricCryptorCipherTextDecoder;
    encoder?: SymmetricCryptorCipherTextEncoder;
    times?: number;
  }
  ```
- ```ts
  interface SymmetricCryptorKeyInput {
    algorithm?: SymmetricCryptorAlgorithm;
    key: SymmetricCryptorKeyType;
  }
  ```
- ```ts
  type SymmetricCryptorAlgorithm =
    | "AES-CBC"
    | "AES-CTR"
    | "AES-GCM";
  ```
- ```ts
  type SymmetricCryptorCipherTextDecoder = (input: string) => Uint8Array | Promise<Uint8Array>;
  ```
- ```ts
  type SymmetricCryptorCipherTextEncoder = (input: Uint8Array) => string | Promise<string>;
  ```
- ```ts
  type SymmetricCryptorKeyType = string | ArrayBuffer | DataView | Uint8Array | Uint16Array | Uint32Array | BigUint64Array;
  ```

> [!NOTE]
> - For the full or prettier documentation, can visit via:
>   - [Deno CLI `deno doc`](https://docs.deno.com/runtime/reference/cli/documentation_generator/)
>   - [JSR](https://jsr.io/@hugoalh/symmetric-crypto)

## ✍️ Examples

- ```ts
  const data = "qwertyuiop";
  const cryptor = await createSymmetricCryptor("<PassWord123456>!!");
  const encrypted = await cryptor.encrypt(data);
  console.log(encrypted);
  // "lST)L-9$J[MPqk)3Pe1qa(;,i)Wi]\"4oD9+OE(Hc"
  const decrypted = await cryptor.decrypt(encrypted);
  console.log(decrypted);
  // "qwertyuiop"
  ```
