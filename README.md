# Metal_Mnemonic_Recovery

<p align="center">
  <a href="#english"><strong>English</strong></a> |
  <a href="#russian"><strong>Русский</strong></a>
</p>

<a id="english"></a>
<p align="center">
  <img src="./docs/media/hero.svg" alt="Metal_Mnemonic_Recovery hero" width="820">
</p>

<p align="center">
  <img alt="Platform" src="https://img.shields.io/badge/platform-macOS%20%7C%20Metal-0f172a?style=for-the-badge">
  <img alt="GPU API" src="https://img.shields.io/badge/GPU%20API-Metal%203-0ea5e9?style=for-the-badge">
  <img alt="Focus" src="https://img.shields.io/badge/focus-BIP39%20Recovery-22c55e?style=for-the-badge">
  <img alt="Targets" src="https://img.shields.io/badge/targets-BTC%20%7C%20ETH%20%7C%20SOL%20%7C%20TON-f59e0b?style=for-the-badge">
</p>

Author: Mikhail Khoroshavin aka "XopMC"

`Metal_Mnemonic_Recovery` is a macOS tool for recovering incomplete BIP39 phrases. It follows the workflow of the original CUDA project, but runs the heavy calculations on the GPU through Metal.

This repository is a full Metal adaptation of [XopMC/CUDA_Mnemonic_Recovery](https://github.com/XopMC/CUDA_Mnemonic_Recovery). The CUDA repository is the original project; this repository contains the macOS and Metal version.

## Why This Project Exists

- Recover real BIP39 phrases with missing words marked as `*`.
- Check candidate phrases against exact hashes, Bloom filters, and XOR filters.
- Provide one recovery CLI for Bitcoin-like targets, Ethereum, Solana, and TON.
- Keep the familiar recovery CLI and `Found:` output while moving the heavy work to the GPU through Metal.

## Scope

- Platform: macOS with Metal support
- GPU API: Metal 3
- Command-line mode: recovery
- Supported targets: BTC compressed/uncompressed/segwit/taproot/xpoint, ETH, Solana, TON short/all
- Supported derivation modes: `-d_type 1`, `2`, `3`, `4`
- Best tested on: Apple Silicon Macs

This repository covers the macOS and Metal version only. It does not include CUDA setup steps or cross-platform release packages.

## Quick Start

`-device` still accepts the old list and range syntax, but the current Metal build uses the first valid Metal device.

Try a one-missing-word recovery using the included compressed-address example:

```bash
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -device 0 \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst *" \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
```

Recover templates from a file:

```bash
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -device 0 \
  -recovery -i examples/templates.txt \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
```

Run Solana exact recovery:

```bash
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -device 0 \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -hash 89dfcdfe8986448bf0ca1f5bc1720de5ad66104c
```

## Build

Requirements:

- macOS with Metal support
- Xcode or Xcode Command Line Tools with Metal compiler support
- CMake 3.22+

Configure and build:

```bash
cmake --preset macos-metal-release
cmake --build out/build/macos-metal-release -j4
```

Default executable path:

```text
out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery
```

The build also places the files required at runtime next to the executable:

- `ChecksumKernels.metallib`
- `secp-precompute-v1.bin`

## Live Recovery Status

During longer runs the program prints status lines with candidates per second, hashes per second, tested count, how many candidates passed the checksum, and found results.

<p>
  <img src="./docs/media/recovery-speed-3missing.png" alt="Local Metal speed screenshot for a 3-missing recovery run" width="920">
</p>

Caption: screenshot from a local macOS Metal run on the bundled `1x3missing` example. It shows one real run on one machine, not a universal performance claim.

## Supported Target Families

`-c` selects which target families are derived and checked.

| Letter | Family | Typical output |
| --- | --- | --- |
| `c` | BTC compressed | compressed hash160 / address match |
| `u` | BTC uncompressed | uncompressed hash160 / address match |
| `s` | BTC segwit | wrapped segwit hash160 |
| `r` | Taproot | 32-byte xonly output |
| `x` | XPoint | 32-byte xonly/public point style match |
| `e` | Ethereum | last 20 bytes of Keccak-256 |
| `S` | Solana | 32-byte ed25519 public key |
| `t` | TON short set | 32-byte wallet hash |
| `T` | TON all variants | 32-byte wallet hash |

## Validation

Main local checks:

```bash
ctest --test-dir out/build/macos-metal-release --output-on-failure
bash ./scripts/validate_release_macos.sh
bash ./tests/no_fallback_macos.sh
bash ./tests/build_purity_macos.sh
bash ./tests/build_purity_unified_macos.sh
```

These checks cover:

- command help and CLI behavior
- recovery from a single template and from files
- typo correction mode
- passphrase passed directly and from files
- exact secp, Solana, TON, mixed `-d_type 3`, and `-d_type 4`
- checks that the program does not fall back
- checks that the public build stays Metal-only and does not silently fall back

## Notes

- This release focuses on recovery commands. Older non-recovery modes from the CUDA codebase are not part of the supported Metal release.
- The `Found:` output format stays the same, so existing parsing scripts keep working.
- This repository is intentionally macOS and Metal only. It does not include CUDA setup steps, cross-platform binary promises, or CPU fallback as the main execution path.
- The `-device` flag still accepts the old list and range syntax, but the current Metal build uses the first valid Metal device.

## Support And Policy

- [Validation](./VALIDATION.md)
- [Benchmarks](./BENCHMARKS.md)
- [Release Checklist](./RELEASE_CHECKLIST.md)
- [Security Policy](./SECURITY.md)
- [Responsible Use](./RESPONSIBLE_USE.md)
- [Support](./SUPPORT.md)
- [Third-Party Notices](./THIRD_PARTY_NOTICES.md)
- [Changelog](./CHANGELOG.md)

---

<a id="russian"></a>

# Metal_Mnemonic_Recovery

Автор: Михаил Хорошавин aka "XopMC"

`Metal_Mnemonic_Recovery` это инструмент для восстановления неполных BIP39-фраз на macOS. Он повторяет рабочий сценарий исходного CUDA-проекта, но выполняет тяжёлые вычисления на GPU через Metal.

Этот репозиторий является полной Metal-адаптацией [XopMC/CUDA_Mnemonic_Recovery](https://github.com/XopMC/CUDA_Mnemonic_Recovery). Исходный CUDA-репозиторий остаётся оригинальным проектом, а здесь находится версия для macOS и Metal.

## Зачем нужен проект

- Восстанавливать реальные BIP39-фразы, где пропущенные слова отмечены как `*`.
- Проверять кандидаты по точным хешам, Bloom-фильтрам и XOR-фильтрам.
- Использовать один понятный recovery CLI для Bitcoin-подобных целей, Ethereum, Solana и TON.
- Сохранить знакомый интерфейс recovery и формат `Found:`, но перенести тяжёлые вычисления на GPU через Metal.

## Область поддержки

- Платформа: macOS с поддержкой Metal
- GPU API: Metal 3
- Режим командной строки: recovery
- Поддерживаемые цели: BTC compressed/uncompressed/segwit/taproot/xpoint, ETH, Solana, TON short/all
- Поддерживаемые режимы деривации: `-d_type 1`, `2`, `3`, `4`
- Лучше всего протестировано на: Apple Silicon Mac

Этот репозиторий посвящён только версии для macOS и Metal. Здесь нет инструкций по CUDA и нет кроссплатформенных release-пакетов.

## Быстрый старт

`-device` по-прежнему понимает старый синтаксис со списками и диапазонами, но текущая Metal-версия использует первое подходящее устройство Metal.

Восстановить одну пропущенную позицию по встроенному примеру с точным хешем:

```bash
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -device 0 \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst *" \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
```

Восстановление из файла с шаблонами:

```bash
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -device 0 \
  -recovery -i examples/templates.txt \
  -d examples/derivations/default.txt \
  -c c \
  -hash 1a4603d1ff9121515d02a6fee37c20829ca522b0
```

Точный запуск восстановления для Solana:

```bash
./out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery \
  -device 0 \
  -recovery "adapt access alert human kiwi rough pottery level soon funny burst divorce" \
  -d examples/validation/derivations-solana.txt \
  -c S \
  -d_type 2 \
  -hash 89dfcdfe8986448bf0ca1f5bc1720de5ad66104c
```

## Сборка

Требования:

- macOS с поддержкой Metal
- Xcode или Xcode Command Line Tools с поддержкой компилятора Metal
- CMake 3.22+

Конфигурация и сборка:

```bash
cmake --preset macos-metal-release
cmake --build --preset macos-metal-release
```

Исполняемый файл по умолчанию:

```text
out/build/macos-metal-release/bin/Metal_Mnemonic_Recovery
```

Сборка также кладёт рядом файлы, нужные для запуска:

- `ChecksumKernels.metallib`
- `secp-precompute-v1.bin`

## Живой статус во время recovery

Во время длинных прогонов программа печатает живой статус: текущую скорость по кандидатам, скорость по хешам, счётчик `tested`, число checksum-valid кандидатов и число найденных совпадений.

<p>
  <img src="./docs/media/recovery-speed-3missing.png" alt="Локальный скриншот скорости Metal на запуске с тремя пропущенными словами" width="920">
</p>

Подпись: локальный скриншот запуска на macOS Metal для встроенного примера `1x3missing`. Это снимок одного реального запуска, а не обещание одинаковой скорости на любой машине.

## Поддерживаемые семейства целей

`-c` задаёт набор семейств, которые будут деривироваться и проверяться.

| Буква | Семейство | Типичный результат |
| --- | --- | --- |
| `c` | BTC compressed | compressed hash160 / address match |
| `u` | BTC uncompressed | uncompressed hash160 / address match |
| `s` | BTC segwit | wrapped segwit hash160 |
| `r` | Taproot | 32-byte xonly output |
| `x` | XPoint | 32-byte xonly/public point style match |
| `e` | Ethereum | последние 20 байт Keccak-256 |
| `S` | Solana | 32-byte ed25519 public key |
| `t` | TON short set | 32-byte wallet hash |
| `T` | TON all variants | 32-byte wallet hash |

## Валидация

Основные локальные проверки:

```bash
ctest --test-dir out/build/macos-metal-release --output-on-failure
bash ./scripts/validate_release_macos.sh
bash ./tests/no_fallback_macos.sh
bash ./tests/build_purity_macos.sh
bash ./tests/build_purity_unified_macos.sh
```

Эти проверки покрывают:

- справку по командам и поведение CLI
- восстановление из одной строки и из файлов
- исправление опечаток
- передачу passphrase напрямую и через файл
- точные проверки для secp, Solana, TON, mixed `-d_type 3` и `-d_type 4`
- проверки, что программа не уходит в fallback
- проверки, что публичная сборка остаётся Metal-only без скрытого отката

## Заметки

- Этот релиз ориентирован на recovery-команды. Старые нерелевантные режимы из CUDA-версии в поддерживаемый Metal-релиз не входят.
- Формат вывода `Found:` сохранён, чтобы старые скрипты разбора продолжали работать.
- Репозиторий специально ограничен macOS и Metal. Здесь нет инструкций по CUDA, обещаний по другим платформам и CPU fallback как основного пути выполнения.
- Параметр `-device` оставлен совместимым со старым синтаксисом, но текущая Metal-версия использует первое подходящее устройство.

## Поддержка и документы

- [Validation](./VALIDATION.md)
- [Benchmarks](./BENCHMARKS.md)
- [Release Checklist](./RELEASE_CHECKLIST.md)
- [Security Policy](./SECURITY.md)
- [Responsible Use](./RESPONSIBLE_USE.md)
- [Support](./SUPPORT.md)
- [Third-Party Notices](./THIRD_PARTY_NOTICES.md)
- [Changelog](./CHANGELOG.md)
