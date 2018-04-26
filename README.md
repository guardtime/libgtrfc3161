# libgtrfc3161 #
Guardtime Keyless Signature Infrastructure (KSI) is an industrial scale blockchain platform that cryptographically
ensures data integrity and proves time of existence. Its keyless signatures, based on hash chains, link data to global
calendar blockchain. The checkpoints of the blockchain, published in newspapers and electronic media, enable long term
integrity of any digital asset without the need to trust any system. There are many applications for KSI, a classical
example is signing of any type of logs - system logs, financial transactions, call records, etc. For more,
see [https://guardtime.com](https://guardtime.com).

`libgtrfc3161` is a software development kit for developers who want to convert Guardtime's legacy signatures to
Guardtime's KSI signatures in their C/C++ based applications .

## Installation ##

### Latest Release from Guardtime Repository

In order to install the `liblegacy` CentOS/RHEL packages directly from the Guardtime public repository, download and save the repository configuration to the `/etc/yum.repos.d/` folder:

```
cd /etc/yum.repos.d

# In case of RHEL/CentOS 6
sudo curl -O http://download.guardtime.com/ksi/configuration/guardtime.el6.repo

# In case of RHEL/CentOS 7
sudo curl -O http://download.guardtime.com/ksi/configuration/guardtime.el7.repo

yum install libgtrfc3161
```

### From Source Code

If the latest version is needed or the package is not available for the platform you are using, check out the source code from Github and build it with the `rebuild.sh` script. To build the legacy signature converter SDK, `libksi` and `libksi-devel` (KSI C SDK) packages are needed. `libksi` is available in Guardtime repository or as source code in GitHub: [https://github.com/GuardTime/libksi](https://github.com/GuardTime/libksi).

To use libgtrfc3161 in your C/C++ project, link it against the `libksi` and `libgtrfc3161` libraries.

## Usage ##

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

The API full reference is available here [http://guardtime.github.io/libgtrfc3161/](http://guardtime.github.io/libgtrfc3161/).

## Contributing ##

See CONTRIBUTING.md file.

## License ##

See LICENSE file.

## Dependencies ##
| Dependency        | Version                           | License type | Source                         | Notes |
| :---              | :---                              | :---         | :---                           |:---   |
| libksi            | >= 3.10 | Apache 2.0   | https://github.com/GuardTime/libksi       |  |
| CuTest            | 1.5                               | Zlib         |                                | Required only for testing. |

## Compatibility ##
| OS / Platform                              | Compatibility                                |
| :---                                       | :---                                         |
| CentOS / RHEL 6 and 7, x86_64 architecture | Fully compatible and tested.                  |
| Debian, ...                                | Compatible but not tested on a regular basis. |
