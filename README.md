# libgtrfc3161 #

Guardtime's KSI Blockchain is an industrial scale blockchain platform that cryptographically ensures data integrity and proves time of existence. The KSI signatures, based on hash chains, link data to this global calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical example is signing of any type of logs - system logs, financial transactions, call records, etc. For more, see [https://guardtime.com](https://guardtime.com).

`libgtrfc3161` is a software development kit for developers who want to convert Guardtime's legacy signatures to
Guardtime's KSI signatures in their C/C++ based applications .

## Installation

### Latest Release from Guardtime Repository

In order to install the `libgtrfc3161` on CentOS/RHEL:

```
cd /etc/yum.repos.d

# In case of RHEL/CentOS 7
sudo curl -O https://download.guardtime.com/ksi/configuration/guardtime.el7.repo

# In case of RHEL/CentOS 8
sudo curl -O https://download.guardtime.com/ksi/configuration/guardtime.el8.repo

# In case of RHEL/CentOS 9
sudo curl -O https://download.guardtime.com/ksi/configuration/guardtime.el9.repo

yum install libgtrfc3161
```

In order to install the `libgtrfc3161` on Debian/Ubuntu:

```
# Add Guardtime pgp key.
sudo curl https://download.guardtime.com/ksi/GUARDTIME-GPG-KEY-2 | sudo apt-key add -

# In case of Debian 12 (Bookworm)
sudo curl -o /etc/apt/sources.list.d/guardtime.list https://download.guardtime.com/ksi/configuration/guardtime.bookworm.list

sudo apt update
apt-get install libgtrfc3161
```

In order to install the `libgtrfc3161` on macOS:

```
brew tap guardtime/ksi
brew install libgtrfc3161
```

### From Source Code

To use `libgtrfc3161`, check out the source code from Github and build it with the `rebuild.sh` script. To build the legacy signature converter SDK, `libksi` and `libksi-devel` (KSI C SDK) packages are needed. `libksi` is available in Guardtime repository or as source code, see more at: [https://github.com/GuardTime/libksi](https://github.com/GuardTime/libksi).

To use `libgtrfc3161` in your C/C++ project, link it against the `libksi` and `libgtrfc3161` libraries.

## Usage

A simple example how to convert a legacy signature:

```C
  #include <ksi/ksi.h>
  #include <gtrfc3161/tsconvert.h>

  /* Read the legacy signature from file. */
  FILE *in_file = NULL;
  size_t in_size = 0;
  unsigned char *in_buf = NULL;
  in_file = fopen("signature.gtts", "rb");
  fseek(in_file, 0, SEEK_END);
  in_size = ftell(in_file);
  in_buf = malloc(in_size);
  fread(in_buf, 1, in_size, in_file);

  /* Convert signature. */
  KSI_CTX *ctx = NULL;
  KSI_CTX_new(&ctx);
  KSI_Signature *ksi_signature = NULL;
  convert_signature(ctx, in_buf, in_size, &ksi_signature);

  /* Serialize the KSI signature and write into file. */
  unsigned char *out_buf = NULL;
  size_t out_size = 0;
  FILE *out_file = NULL;
  KSI_Signature_serialize(ksi_signature, &out_buf, &out_size);
  out_file = fopen("signature.ksi", "wb");
  fwrite(out_buf, 1, out_size, out_file);

  /* Cleanup. */
  fclose(in_file);
  fclose(out_file);
  free(in_buf);
  free(out_buf);
  KSI_Signature_free(ksi_signature);
  KSI_CTX_free(ctx);
```

## Contributing

See CONTRIBUTING.md file.

## License

See LICENSE file.

## Dependencies

| Dependency | Version | License type | Source                              | Notes |
| :----------| :-------| :------------| :-----------------------------------|:------|
| libksi     | >= 3.10 | Apache 2.0   | https://github.com/GuardTime/libksi |       |
| CuTest     | 1.5     | Zlib         |                                     | Required only for testing. |

## Compatibility

| OS/Platform                                | Compatibility                                 |
| :------------------------------------------| :---------------------------------------------|
| CentOS/RHEL 7,8,9, x86_64 architecture     | Fully compatible and tested.                 |
| Debian 12+                                 | Fully compatible and tested.                 |
| Ubuntu                                     | Compatible but not tested on regular basis.  |
| OS X                                       | Compatible but not tested on regular basis.  |
| Windows 7, 8, 10, 11                       | Compatible but not tested on a regular basis. Build combination of `DLL=dll` and `RTL=MT(d)` not supported. |
