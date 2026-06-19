# Symmetric Crypto (ES)

[**⚖️** MIT](./LICENSE.md)

🔗
[GitHub](https://github.com/hugoalh/symmetric-crypto-es)
● [JSR](https://jsr.io/@hugoalh/symmetric-crypto)
● [NPM](https://www.npmjs.com/package/@hugoalh/symmetric-crypto)

An ECMAScript module to provide an easier symmetric crypto.

## 🎯 Runtime Targets

Any runtime which support ECMAScript should able to use this; These runtimes are officially supported:

- **[Bun](https://bun.sh/)** >= v1.1.0
- **[Deno](https://deno.land/)** >= v2.1.0
- **[NodeJS](https://nodejs.org/)** >= v20.9.0

## 🛡️ Runtime Permissions

- File System - Read (Deno: `read`; NodeJS: `fs-read`) (Optional)
- File System - Write (Deno: `write`; NodeJS: `fs-write`) (Optional)

## #️⃣ Sources & Entrypoints

- GitHub Raw
  ```
  https://raw.githubusercontent.com/hugoalh/symmetric-crypto-es/{Tag}/mod.ts
  ```
- JSR
  ```
  jsr:@hugoalh/symmetric-crypto[@{Tag}]
  ```
- NPM
  ```
  npm:@hugoalh/symmetric-crypto[@{Tag}]
  ```

| **Name** | **Path** | **Description** |
|:--|:--|:--|
| `.` | `./mod.ts` | Default. |

> [!NOTE]
> - Different runtimes have vary support for the sources and entrypoints, visit the runtime documentation for more information.
> - It is recommended to include tag for immutability.
> - These are not part of the public APIs hence should not be used:
>   - Benchmark/Test file (e.g.: `example.bench.ts`, `example.test.ts`).
>   - Entrypoint name or path include any underscore prefix (e.g.: `_example.ts`, `foo/_example.ts`).
>   - Identifier/Namespace/Symbol include any underscore prefix (e.g.: `_example`, `Foo._example`).

## 🧩 APIs

- ```ts
  class SymmetricCryptorBasic {
    constructor(key: SymmetricCryptorKeyInput | SymmetricCryptorKeyType, options?: SymmetricCryptorOptions);
    constructor(keys: readonly (SymmetricCryptorKeyInput | SymmetricCryptorKeyType)[], options?: Omit<SymmetricCryptorOptions, "times">);
    decrypt(data: string): Promise<string>;
    decrypt(data: Uint8Array): Promise<Uint8Array>;
    encrypt(data: string): Promise<string>;
    encrypt(data: Uint8Array): Promise<Uint8Array>;
  }
  ```
- ```ts
  class SymmetricCryptor extends SymmetricCryptorBasic {
    decryptFileInPlace(filePath: string | URL): Promise<void>;
    encryptFileInPlace(filePath: string | URL): Promise<void>;
    readEncryptedFile(filePath: string | URL, options?: Deno.ReadFileOptions): Promise<Uint8Array>;
    readEncryptedTextFile(filePath: string | URL, options?: Deno.ReadFileOptions): Promise<string>;
    writeEncryptedFile(filePath: string | URL, data: Uint8Array, options?: Omit<Deno.WriteFileOptions, "append">): Promise<void>;
    writeEncryptedTextFile(filePath: string | URL, data: string, options?: Omit<Deno.WriteFileOptions, "append">): Promise<void>;
  }
  ```
- ```ts
  interface SymmetricCryptorOptions {
    cipherTextCoder?: SymmetricCryptorCipherTextCoderDefault | SymmetricCryptorCipherTextCoderOptions;
    times?: number;
  }
  ```
- ```ts
  interface SymmetricCryptorCipherTextCoderOptions {
    decoder: SymmetricCryptorCipherTextDecoder;
    encoder: SymmetricCryptorCipherTextEncoder;
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
  type SymmetricCryptorCipherTextDecoder = (data: string) => Uint8Array | Promise<Uint8Array>;
  ```
- ```ts
  type SymmetricCryptorCipherTextEncoder = (data: Uint8Array) => string | Promise<string>;
  ```
- ```ts
  type SymmetricCryptorCipherTextCoderDefault =
    | "base64"
    | "base64url";
  ```
- ```ts
  type SymmetricCryptorKeyType =
    | string
    | ArrayBuffer
    | BigUint64Array
    | DataView
    | Uint8Array
    | Uint16Array
    | Uint32Array;
  ```

> [!NOTE]
> - For the full or prettier documentation, can visit via:
>   - [Deno CLI `deno doc`](https://docs.deno.com/runtime/reference/cli/doc/)
>   - [JSR](https://jsr.io/@hugoalh/symmetric-crypto)

## ✍️ Examples

- ```ts
  const data = "qwertyuiop";
  const cryptor = new SymmetricCryptor("<PassWord123456>!!");
  const encrypted = await cryptor.encrypt(data);
  console.log(encrypted);
  // "6zUMUyY3gQaKqCZZOcFGucdlpnQa5i97PfypJpByA+Y="
  const decrypted = await cryptor.decrypt(encrypted);
  console.log(decrypted);
  // "qwertyuiop"
  ```
