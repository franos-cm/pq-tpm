# Overview

This project is an adaptation of the [official TPM 2.0 reference implementation](https://github.com/microsoft/ms-tpm-20-ref) (version 183), aimed at adding support for the CRYSTALS-Dilithium signature scheme.

Differently from the original repository, this one is not supposed to be a stand-alone project that can be run as a software simulation. Instead, this repository should be understood as part of [this larger project](https://github.com/franos-cm/project-petalite), and it is meant to be a library for firmware running on a baremetal RISC-V host. As such, the build process described in the original repository will not work here as originally intended.

We recommend reading the original repository to better understand the TPM architecture and its code structure.

# Changes

Two main types of changes were made to the codebase. The first type of change was so the TPM library would work using wolfSSL instead of OpenSSL. In theory, the original code already had *some* support for wolfSSL (as per the original documentation); in practice, compilation would fail when using the wolfSSL bindings.

The remaining, more laborious, changes were to either add new (vendor-specific) commands, or modify existing ones, so that all three Dilithium operations — `KEYGEN`, `SIGN`, `VERIFY` — are supported by the TPM.

The Dilithium operations themselves are not part of this codebase; instead, `__plat` HAL function calls to a Dilithium hardware accelerator are performed. The implementation of these functions, and the accelerator itself, are part of the scope of the other (aforementioned) project.