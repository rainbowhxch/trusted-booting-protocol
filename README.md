# Trusted Booting Protocol

This protocol comes from [this paper](https://ieeexplore.ieee.org/document/9186690/), and this implement is used for learning purposes.

## Dependencies

You need to install the following dependencies:

- [IBM TPM Software Simulator](https://sourceforge.net/projects/ibmswtpm2/files/ibmtpm974.tar.gz/download?use_mirror=iweb) or [swtpm](https://github.com/stefanberger/swtpm)
- [cJSON](https://github.com/DaveGamble/cJSON)
- [OpenSSL](https://www.openssl.org/)
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss)

## Build && Run

To Build:
```bash
make
```

To Run. Running the TPM Simulator, then:
```bash
./proxy-v
./sdw-tpm
```

## Credit

All copyright belongs to the author of [this paper](https://ieeexplore.ieee.org/document/9186690/).
