# Symmetric Crypto (ES)

[**⚖️** MIT](./LICENSE.md)

🔗
[DistBoard @hugoalh](https://hugoalh.github.io/distboard/symmetric_crypto_ecmascript)
● [GitHub](https://github.com/hugoalh/symmetric-crypto-es)
● [JSR](https://jsr.io/@hugoalh/symmetric-crypto)
● [NPM](https://www.npmjs.com/package/@hugoalh/symmetric-crypto)

An ECMAScript module to provide an easier symmetric crypto.

## 🎯 Runtime Targets

Any runtime which support ECMAScript should able to use this; These runtimes are officially supported:

- **[Bun](https://bun.sh/)** >= v1.1.0
- **[Deno](https://deno.land/)** >= v2.1.0
- **[NodeJS](https://nodejs.org/)** >= v20.9.0

## 🛡️ Runtime Permissions

This does not request any runtime permission.

## #️⃣ Entrypoints

| **Name** | **Path** | **Description** |
|:--|:--|:--|
| `.` | `./mod.ts` | Default. |

> [!NOTE]
> - Different runtimes have vary support for the entrypoints, visit the runtime documentation for more information.
> - These are not part of the public APIs hence should not be used:
>   - Benchmark/Test file (e.g.: `example.bench.ts`, `example.test.ts`).
>   - Entrypoint name or path include any underscore prefix (e.g.: `_example.ts`, `foo/_example.ts`).
>   - Identifier/Namespace/Symbol include any underscore prefix (e.g.: `_example`, `Foo._example`).

## 🧩 APIs

- ```ts
  class SymmetricCryptor {
    decrypt(data: Uint8Array): Uint8Array;
    decryptStream(): SymmetricCryptorDecryptStream | SymmetricCryptorDecryptStreamAuthTag | SymmetricCryptorDecryptStreamCCM;
    encrypt(data: Uint8Array): Uint8Array;
    encryptStream(): SymmetricCryptorEncryptStream | SymmetricCryptorEncryptStreamCCM;
  }
  ```
- ```ts
  class SymmetricCryptorDecryptStream extends TransformStream<Uint8Array, Uint8Array>;
  ```
- ```ts
  class SymmetricCryptorDecryptStreamAuthTag extends TransformStream<Uint8Array, Uint8Array>;
  ```
- ```ts
  class SymmetricCryptorDecryptStreamCCM extends TransformStream<Uint8Array, Uint8Array>;
  ```
- ```ts
  class SymmetricCryptorEncryptStream extends TransformStream<Uint8Array, Uint8Array>;
  ```
- ```ts
  class SymmetricCryptorEncryptStreamCCM extends TransformStream<Uint8Array, Uint8Array>;
  ```
- ```ts
  function createSymmetricCryptor(key: BinaryLike, options?: SymmetricCryptorOptions): Promise<SymmetricCryptor>;
  ```
- ```ts
  interface SymmetricCryptorOptions {
    algorithm?: SymmetricCryptoAlgorithm;
    scrypt?: ScryptOptions;
  }
  ```

> [!NOTE]
> - For the full or prettier documentation, can visit via:
>   - [Deno CLI `deno doc`](https://docs.deno.com/runtime/reference/cli/doc)
>   - [JSR](https://jsr.io/@hugoalh/symmetric-crypto)

## ✍️ Examples

- ```ts
  const data = "qwertyuiop";
  const cryptor = await createSymmetricCryptor("QwErTyUiOp");
  const encrypted = cryptor.encrypt(new TextEncoder().encode(data));
  const decrypted = cryptor.decrypt(encrypted);
  ```
- ```ts
  const cryptor = await createSymmetricCryptor("QwErTyUiOp");
  await using file = await Deno.open(filePath);
  const encrypted = file.readable.pipeThrough(cryptor.encryptStream());
  ```
