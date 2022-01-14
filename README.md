# Trusted Booting Protocol

A remote trusted booting protocol based on TPM chip, which can verify the credibility of the remote host through the master host and prevent the remote one from being hijacked. At the same time, the protocol can be self insured.

## Dependencies

You need to install the following dependencies:

- [IBM TPM Software Simulator](https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm974.tar.gz/download?use_mirror=iweb)
- [cJSON](https://github.com/DaveGamble/cJSON)
- [OpenSSL](https://www.openssl.org/)
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

## Build && Run

To Build:
```bash
make
```

To Run. Running the TPM Simulator, then open two terminals:

```bash
./proxy-v <port>
```

and

```bash
./sdw-tpm <server_ip> <server_port>
```

You will get some log files in the `log` directory, check them out.

## Reference
1. [Part 1:Architecture](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf)
2. [Part 2:Structures](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf)
3. [Part 3:Commands](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf)
4. [Part 3:Commands - Code](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_code_pub.pdf)
5. [TCG TSS 2.0 System Level API (SAPI) Specification](https://trustedcomputinggroup.org/resource/tcg-tss-2-0-system-level-api-sapi-specification/)
6. [TCG TSS 2.0 Enhanced System API (ESAPI) Specification](https://trustedcomputinggroup.org/resource/tcg-tss-2-0-enhanced-system-api-esapi-specification/)

## Credit

All copyright belongs to the author of [this paper](https://ieeexplore.ieee.org/document/9186690/).
